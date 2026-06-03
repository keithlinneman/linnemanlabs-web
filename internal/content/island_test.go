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

// contentIsland / appIsland build a data-island <script> carrying its sentinel.
func contentIsland() string {
	return `<script type="application/json" id="provenance-content-data">` + contentDataSentinel + `</script>`
}

func appIsland() string {
	return `<script type="application/json" id="provenance-app-data">` + appDataSentinel + `</script>`
}

func TestInjectDataIslands(t *testing.T) {
	page := `<!doctype html><html><body>` + contentIsland() + appIsland() + `</body></html>`
	footer := `<footer><script type=application/json id=provenance-app-data>` + appDataSentinel + `</script></footer>`
	// a .json asset that contains the sentinel must be left untouched.
	notHTML := []byte(contentDataSentinel)

	mfs := fstest.MapFS{
		"page.html":   &fstest.MapFile{Data: []byte(page)},
		"footer.html": &fstest.MapFile{Data: []byte(footer)},
		"feed.json":   &fstest.MapFile{Data: append([]byte(nil), notHTML...)},
	}

	contentJSON := []byte(`{"c":true}`)
	appJSON := []byte(`{"a":true}`)

	counts, modified := injectDataIslands(mfs, contentJSON, appJSON)

	if counts.content != 1 {
		t.Fatalf("content replacements = %d, want 1", counts.content)
	}
	if counts.app != 2 {
		t.Fatalf("app replacements = %d, want 2", counts.app)
	}
	if len(modified) != 2 || modified[0] != "footer.html" || modified[1] != "page.html" {
		t.Fatalf("modified = %v, want [footer.html page.html] (sorted)", modified)
	}

	gotPage := mfs["page.html"].Data
	if !bytes.Contains(gotPage, contentJSON) || !bytes.Contains(gotPage, appJSON) {
		t.Fatalf("page.html missing a payload: %q", gotPage)
	}
	if bytes.Contains(gotPage, []byte(contentDataSentinel)) || bytes.Contains(gotPage, []byte(appDataSentinel)) {
		t.Fatalf("page.html still contains a sentinel: %q", gotPage)
	}
	if !bytes.Contains(mfs["footer.html"].Data, appJSON) {
		t.Fatalf("footer.html missing app payload: %q", mfs["footer.html"].Data)
	}
	if !bytes.Equal(mfs["feed.json"].Data, notHTML) {
		t.Fatalf("feed.json (non-HTML) was modified: %q", mfs["feed.json"].Data)
	}
}

func TestInjectDataIslands_Idempotent(t *testing.T) {
	mfs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(contentIsland())}}
	contentJSON := []byte(`{"v":1}`)

	c1, m1 := injectDataIslands(mfs, contentJSON, nil)
	if c1.content != 1 || len(m1) != 1 {
		t.Fatalf("first run: counts=%+v modified=%v", c1, m1)
	}
	first := append([]byte(nil), mfs["index.html"].Data...)

	c2, m2 := injectDataIslands(mfs, contentJSON, nil)
	if c2.content != 0 || len(m2) != 0 {
		t.Fatalf("second run should be a no-op: counts=%+v modified=%v", c2, m2)
	}
	if !bytes.Equal(first, mfs["index.html"].Data) {
		t.Fatalf("second run changed the file: %q", mfs["index.html"].Data)
	}
}

func TestInjectDataIslands_NilPayloadSkipsIsland(t *testing.T) {
	mfs := fstest.MapFS{"page.html": &fstest.MapFile{Data: []byte(contentIsland() + appIsland())}}

	appJSON := []byte(`{"a":1}`)
	counts, _ := injectDataIslands(mfs, nil, appJSON)

	if counts.content != 0 {
		t.Fatalf("content replacements = %d, want 0 (nil payload)", counts.content)
	}
	if counts.app != 1 {
		t.Fatalf("app replacements = %d, want 1", counts.app)
	}
	got := mfs["page.html"].Data
	if !bytes.Contains(got, []byte(contentDataSentinel)) {
		t.Fatal("content sentinel should remain when its payload is nil")
	}
	if !bytes.Contains(got, appJSON) {
		t.Fatal("app sentinel should have been replaced")
	}
}

func TestInlineProvenance_FillsAndWarnsOnMissingIsland(t *testing.T) {
	// page has only the content sentinel; the app sentinel is absent, exercising
	// the zero-match warn path without failing.
	mfs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(contentIsland())}}

	l := &Loader{
		logger: log.Nop(),
		inliner: &stubInliner{
			contentJSON: []byte(`{"island":"content"}`),
			appJSON:     []byte(`{"island":"app"}`),
		},
	}
	l.inlineProvenance(context.Background(), &Snapshot{FS: mfs})

	if !bytes.Contains(mfs["index.html"].Data, []byte(`{"island":"content"}`)) {
		t.Fatalf("content island not filled: %q", mfs["index.html"].Data)
	}
}

func TestInlineProvenance_InlinerErrorSkipsThatIsland(t *testing.T) {
	mfs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(contentIsland() + appIsland())}}

	l := &Loader{
		logger: log.Nop(),
		inliner: &stubInliner{
			contentErr: context.DeadlineExceeded, // content build fails
			appJSON:    []byte(`{"island":"app"}`),
		},
	}
	l.inlineProvenance(context.Background(), &Snapshot{FS: mfs})

	got := mfs["index.html"].Data
	if !bytes.Contains(got, []byte(contentDataSentinel)) {
		t.Fatalf("content sentinel should remain when its build errors: %q", got)
	}
	if !bytes.Contains(got, []byte(`{"island":"app"}`)) {
		t.Fatalf("app island should still be filled: %q", got)
	}
}

func TestInlineProvenance_NoInlinerIsNoop(t *testing.T) {
	page := contentIsland()
	mfs := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte(page)}}

	l := &Loader{logger: log.Nop()} // inliner nil
	l.inlineProvenance(context.Background(), &Snapshot{FS: mfs})

	if string(mfs["index.html"].Data) != page {
		t.Fatalf("page changed with no inliner: %q", mfs["index.html"].Data)
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

// TestInjectedIslandServedWithCorrectLength confirms that after injection the
// real serving primitive (http.ServeFileFS, as used by sitehandler) returns the
// injected bytes with a Content-Length matching the grown file size.
func TestInjectedIslandServedWithCorrectLength(t *testing.T) {
	// not named index.html: http.ServeFileFS redirects "/index.html" requests to
	// "./", which would mask the body. sitehandler serves the resolved file path.
	const name = "provenance/index.html"
	mfs := fstest.MapFS{name: &fstest.MapFile{Data: []byte(`<!doctype html>` + contentIsland())}}
	payload := []byte(`{"served":true}`)

	counts, _ := injectDataIslands(mfs, payload, nil)
	if counts.content != 1 {
		t.Fatalf("content replacements = %d, want 1", counts.content)
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

// TestLoadHash_InlinesProvenanceIslands exercises the full load path: a bundle
// whose page carries both sentinels is served from the snapshot FS with both
// replaced by the provenance JSON.
func TestLoadHash_InlinesProvenanceIslands(t *testing.T) {
	page := `<!doctype html><html><body>` + contentIsland() + appIsland() + `</body></html>`

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
	if !bytes.Contains(out, []byte(`>{"island":"content"}</script>`)) {
		t.Fatalf("content island not injected: %q", out)
	}
	if !bytes.Contains(out, []byte(`>{"island":"app"}</script>`)) {
		t.Fatalf("app island not injected: %q", out)
	}
	if bytes.Contains(out, []byte(contentDataSentinel)) || bytes.Contains(out, []byte(appDataSentinel)) {
		t.Fatalf("a sentinel survived injection: %q", out)
	}

	// the inliner must be handed the snapshot under construction (with provenance).
	if stub.gotSnap == nil || stub.gotSnap.Provenance == nil || stub.gotSnap.Provenance.Version != "1.0.0" {
		t.Fatalf("inliner did not receive the loaded snapshot: %+v", stub.gotSnap)
	}
}

func TestLoadHash_NoInlinerLeavesSentinels(t *testing.T) {
	page := `<html><body>` + contentIsland() + `</body></html>`

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
	if !bytes.Contains(out, []byte(contentDataSentinel)) {
		t.Fatalf("sentinel should remain with no inliner: %q", out)
	}
}
