package content

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/keithlinneman/linnemanlabs-web/internal/cryptoutil"
	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// stubInliner is a test double for ProvenanceInliner returning fixed payloads.
type stubInliner struct {
	contentJSON []byte
	appJSON     []byte
	contentErr  error
	appErr      error
	gotSnap     *Snapshot
}

func (s *stubInliner) AppDataIsland(_ context.Context) ([]byte, error) {
	return s.appJSON, s.appErr
}

func (s *stubInliner) ContentDataIsland(_ context.Context, snap *Snapshot) ([]byte, error) {
	s.gotSnap = snap
	return s.contentJSON, s.contentErr
}

// notMapFS is an fs.FS that is not a fstest.MapFS, to exercise the
// non-mutable-FS branch of inlineProvenance.
type notMapFS struct{}

func (notMapFS) Open(string) (fs.File, error) { return nil, fs.ErrNotExist }

func TestInjectIsland(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		id      string
		payload string
		wantOut string
		wantOK  bool
	}{
		{
			name:    "fills empty content island",
			in:      `<script type="application/json" id="provenance-content-data"></script>`,
			id:      contentDataIslandID,
			payload: `{"x":1}`,
			wantOut: `<script type="application/json" id="provenance-content-data">{"x":1}</script>`,
			wantOK:  true,
		},
		{
			name:    "tolerates swapped attribute order",
			in:      `<script id="provenance-app-data" type="application/json"></script>`,
			id:      appDataIslandID,
			payload: `{"a":1}`,
			wantOut: `<script id="provenance-app-data" type="application/json">{"a":1}</script>`,
			wantOK:  true,
		},
		{
			name:    "replaces whitespace-only inner content",
			in:      "<script type=\"application/json\" id=\"provenance-content-data\">\n   \n</script>",
			id:      contentDataIslandID,
			payload: `1`,
			wantOut: `<script type="application/json" id="provenance-content-data">1</script>`,
			wantOK:  true,
		},
		{
			name:    "preserves surrounding markup",
			in:      `<p>before</p><script type="application/json" id="provenance-content-data"></script><p>after</p>`,
			id:      contentDataIslandID,
			payload: `[1,2,3]`,
			wantOut: `<p>before</p><script type="application/json" id="provenance-content-data">[1,2,3]</script><p>after</p>`,
			wantOK:  true,
		},
		{
			name:    "idempotent: skips already-filled island",
			in:      `<script type="application/json" id="provenance-content-data">{"old":1}</script>`,
			id:      contentDataIslandID,
			payload: `{"new":2}`,
			wantOut: `<script type="application/json" id="provenance-content-data">{"old":1}</script>`,
			wantOK:  false,
		},
		{
			name:    "no marker present",
			in:      `<html><body>no island here</body></html>`,
			id:      contentDataIslandID,
			payload: `{"x":1}`,
			wantOut: `<html><body>no island here</body></html>`,
			wantOK:  false,
		},
		{
			name:    "id on non-script element is not matched",
			in:      `<script>var a=1;</script><div id="provenance-app-data"></div>`,
			id:      appDataIslandID,
			payload: `{"a":1}`,
			wantOut: `<script>var a=1;</script><div id="provenance-app-data"></div>`,
			wantOK:  false,
		},
		{
			name:    "id prefix collision is not matched",
			in:      `<script type="application/json" id="provenance-app-data-extra"></script>`,
			id:      appDataIslandID,
			payload: `{"a":1}`,
			wantOut: `<script type="application/json" id="provenance-app-data-extra"></script>`,
			wantOK:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, ok := injectIsland([]byte(tt.in), tt.id, []byte(tt.payload))
			if ok != tt.wantOK {
				t.Fatalf("injectIsland ok = %v, want %v", ok, tt.wantOK)
			}
			if string(out) != tt.wantOut {
				t.Fatalf("injectIsland out =\n  %q\nwant\n  %q", out, tt.wantOut)
			}
		})
	}
}

func TestInjectIsland_Idempotent(t *testing.T) {
	in := []byte(`<script type="application/json" id="provenance-content-data"></script>`)
	payload := []byte(`{"v":1}`)

	first, ok := injectIsland(in, contentDataIslandID, payload)
	if !ok {
		t.Fatal("first injection should succeed")
	}
	second, ok := injectIsland(first, contentDataIslandID, payload)
	if ok {
		t.Fatal("second injection should be a no-op")
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("second injection changed bytes: %q vs %q", first, second)
	}
}

func TestInjectDataIslands(t *testing.T) {
	contentIsland := `<script type="application/json" id="provenance-content-data"></script>`
	appIsland := `<script type="application/json" id="provenance-app-data"></script>`

	// .json file whose bytes contain the marker but must be left untouched.
	notHTML := []byte(contentIsland)

	mfs := fstest.MapFS{
		"page.html":   &fstest.MapFile{Data: []byte(contentIsland + appIsland)},
		"footer.html": &fstest.MapFile{Data: []byte("<footer>" + appIsland + "</footer>")},
		"feed.json":   &fstest.MapFile{Data: append([]byte(nil), notHTML...)},
		"notes.txt":   &fstest.MapFile{Data: []byte(`id="provenance-app-data"`)},
	}

	contentJSON := []byte(`{"c":true}`)
	appJSON := []byte(`{"a":true}`)

	counts, modified := injectDataIslands(mfs, contentJSON, appJSON)

	if counts.content != 1 {
		t.Fatalf("content injections = %d, want 1", counts.content)
	}
	if counts.app != 2 {
		t.Fatalf("app injections = %d, want 2", counts.app)
	}
	if len(modified) != 2 || modified[0] != "footer.html" || modified[1] != "page.html" {
		t.Fatalf("modified = %v, want [footer.html page.html] (sorted)", modified)
	}

	page := mfs["page.html"].Data
	if !bytes.Contains(page, contentJSON) || !bytes.Contains(page, appJSON) {
		t.Fatalf("page.html missing an injected island: %q", page)
	}
	if !bytes.Contains(mfs["footer.html"].Data, appJSON) {
		t.Fatalf("footer.html missing app island: %q", mfs["footer.html"].Data)
	}

	// non-HTML file with the marker substring must be byte-identical.
	if !bytes.Equal(mfs["feed.json"].Data, notHTML) {
		t.Fatalf("feed.json was modified: %q", mfs["feed.json"].Data)
	}
}

func TestInjectDataIslands_NilPayloadSkipsIsland(t *testing.T) {
	both := `<script type="application/json" id="provenance-content-data"></script>` +
		`<script type="application/json" id="provenance-app-data"></script>`
	mfs := fstest.MapFS{"page.html": &fstest.MapFile{Data: []byte(both)}}

	appJSON := []byte(`{"a":1}`)
	counts, _ := injectDataIslands(mfs, nil, appJSON)

	if counts.content != 0 {
		t.Fatalf("content injections = %d, want 0 (nil payload)", counts.content)
	}
	if counts.app != 1 {
		t.Fatalf("app injections = %d, want 1", counts.app)
	}
	if bytes.Contains(mfs["page.html"].Data, []byte(`>{`)) && !bytes.Contains(mfs["page.html"].Data, appJSON) {
		t.Fatal("content island should remain empty when payload is nil")
	}
}

func TestInlineProvenance_FillsAndWarnsOnMissingIsland(t *testing.T) {
	// page has only the content island; the app island is absent, exercising the
	// zero-match warn path without failing.
	page := `<script type="application/json" id="provenance-content-data"></script>`
	mfs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(page)}}

	l := &Loader{
		logger: log.Nop(),
		inliner: &stubInliner{
			contentJSON: []byte(`{"island":"content"}`),
			appJSON:     []byte(`{"island":"app"}`),
		},
	}
	snap := &Snapshot{FS: mfs}

	l.inlineProvenance(context.Background(), snap)

	if !bytes.Contains(mfs["index.html"].Data, []byte(`{"island":"content"}`)) {
		t.Fatalf("content island not filled: %q", mfs["index.html"].Data)
	}
}

func TestInlineProvenance_InlinerErrorSkipsThatIsland(t *testing.T) {
	page := `<script type="application/json" id="provenance-content-data"></script>` +
		`<script type="application/json" id="provenance-app-data"></script>`
	mfs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(page)}}

	l := &Loader{
		logger: log.Nop(),
		inliner: &stubInliner{
			contentErr: context.DeadlineExceeded, // content build fails
			appJSON:    []byte(`{"island":"app"}`),
		},
	}
	l.inlineProvenance(context.Background(), &Snapshot{FS: mfs})

	got := mfs["index.html"].Data
	if bytes.Contains(got, []byte(`provenance-content-data">{`)) {
		t.Fatalf("content island should be left empty when its build errors: %q", got)
	}
	if !bytes.Contains(got, []byte(`{"island":"app"}`)) {
		t.Fatalf("app island should still be filled: %q", got)
	}
}

func TestInlineProvenance_NoInlinerIsNoop(t *testing.T) {
	page := `<script type="application/json" id="provenance-content-data"></script>`
	mfs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(page)}}

	l := &Loader{logger: log.Nop()} // inliner nil
	l.inlineProvenance(context.Background(), &Snapshot{FS: mfs})

	if string(mfs["index.html"].Data) != page {
		t.Fatalf("page changed with no inliner: %q", mfs["index.html"].Data)
	}
}

// TestInjectedIslandServedWithCorrectLength confirms that after injection the
// real serving primitive (http.ServeFileFS, as used by sitehandler) returns the
// injected bytes with a Content-Length matching the grown file size.
func TestInjectedIslandServedWithCorrectLength(t *testing.T) {
	// not named index.html: http.ServeFileFS redirects "/index.html" requests to
	// "./", which would mask the body. sitehandler serves the resolved file path.
	const name = "provenance/index.html"
	page := `<!doctype html><script type="application/json" id="provenance-content-data"></script>`
	mfs := fstest.MapFS{name: &fstest.MapFile{Data: []byte(page)}}
	payload := []byte(`{"served":true}`)

	counts, _ := injectDataIslands(mfs, payload, nil)
	if counts.content != 1 {
		t.Fatalf("content injections = %d, want 1", counts.content)
	}

	rr := httptest.NewRecorder()
	http.ServeFileFS(rr, httptest.NewRequest(http.MethodGet, "/provenance/", http.NoBody), mfs, name)

	res := rr.Result()
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Contains(body, payload) {
		t.Fatalf("served body missing injected payload: %q", body)
	}
	if want := int64(len(mfs[name].Data)); res.ContentLength != want {
		t.Fatalf("Content-Length = %d, want %d", res.ContentLength, want)
	}
}

func TestInlineProvenance_NonMapFSIsSkipped(t *testing.T) {
	l := &Loader{
		logger:  log.Nop(),
		inliner: &stubInliner{contentJSON: []byte(`{}`), appJSON: []byte(`{}`)},
	}
	// must not panic and must tolerate a non-mutable FS.
	l.inlineProvenance(context.Background(), &Snapshot{FS: notMapFS{}})
}

// TestLoadHash_InlinesProvenanceIslands exercises the full load path: a bundle
// whose page carries both empty placeholders is served from the snapshot FS with
// both islands populated.
func TestLoadHash_InlinesProvenanceIslands(t *testing.T) {
	page := `<!doctype html><html><body>` +
		`<script type="application/json" id="provenance-content-data"></script>` +
		`<script type="application/json" id="provenance-app-data"></script>` +
		`</body></html>`

	data := makeTarGz(t, map[string]string{
		"index.html":   page,
		"release.json": `{"version":"1.0.0"}`,
	})
	hash := cryptoutil.SHA384Hex(data)

	fake := newFakeS3()
	putBundle(fake, hash, data)
	putSigBundle(fake, hash, []byte(`{"mock":"sig"}`))

	l := newTestLoader(t, fake, ssmWithValue(ssmValue(hash)))
	stub := &stubInliner{
		contentJSON: []byte(`{"island":"content"}`),
		appJSON:     []byte(`{"island":"app"}`),
	}
	l.inliner = stub

	snap, err := l.LoadHash(t.Context(), "sha384", hash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}

	out, err := fs.ReadFile(snap.FS, "index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if !bytes.Contains(out, []byte(`id="provenance-content-data">{"island":"content"}</script>`)) {
		t.Fatalf("content island not injected: %q", out)
	}
	if !bytes.Contains(out, []byte(`id="provenance-app-data">{"island":"app"}</script>`)) {
		t.Fatalf("app island not injected: %q", out)
	}

	// the inliner must be handed the snapshot under construction (with provenance).
	if stub.gotSnap == nil || stub.gotSnap.Provenance == nil || stub.gotSnap.Provenance.Version != "1.0.0" {
		t.Fatalf("inliner did not receive the loaded snapshot: %+v", stub.gotSnap)
	}
}

func TestLoadHash_NoInlinerLeavesPlaceholders(t *testing.T) {
	page := `<html><body>` +
		`<script type="application/json" id="provenance-content-data"></script>` +
		`</body></html>`

	data := makeTarGz(t, map[string]string{
		"index.html":   page,
		"release.json": `{"version":"1.0.0"}`,
	})
	hash := cryptoutil.SHA384Hex(data)

	fake := newFakeS3()
	putBundle(fake, hash, data)
	putSigBundle(fake, hash, []byte(`{"mock":"sig"}`))

	// default helper leaves inliner nil
	l := newTestLoader(t, fake, ssmWithValue(ssmValue(hash)))

	snap, err := l.LoadHash(t.Context(), "sha384", hash)
	if err != nil {
		t.Fatalf("LoadHash: %v", err)
	}

	out, err := fs.ReadFile(snap.FS, "index.html")
	if err != nil {
		t.Fatalf("read index.html: %v", err)
	}
	if !bytes.Contains(out, []byte(`id="provenance-content-data"></script>`)) {
		t.Fatalf("placeholder should remain empty with no inliner: %q", out)
	}
}
