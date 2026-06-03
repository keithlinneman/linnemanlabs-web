package provenancehttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/keithlinneman/linnemanlabs-web/internal/log"
)

// TestMarshalIsland_EscapesScriptClose proves a field value containing a literal
// </script> is HTML-escaped, so it cannot terminate the <script> data island.
func TestMarshalIsland_EscapesScriptClose(t *testing.T) {
	const breakout = "feature/</script><script>alert(1)</script>"
	v := map[string]string{"branch": breakout}

	out, err := marshalIsland(v)
	if err != nil {
		t.Fatalf("marshalIsland: %v", err)
	}
	// the raw breakout sequence must not survive into the embedded JSON
	if strings.Contains(string(out), "</script>") {
		t.Fatalf("output contains an unescaped </script>: %s", out)
	}
	// '<' must be escaped to the < form
	if !strings.Contains(string(out), "\\u003c") {
		t.Fatalf("output should escape '<' to \\u003c: %s", out)
	}
	// escaping is lossless: the value round-trips unchanged
	var back map[string]string
	if err := json.Unmarshal(out, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back["branch"] != breakout {
		t.Fatalf("round-trip mismatch: %q", back["branch"])
	}
}

// TestInliner_AppDataIsland_MatchesEndpoint asserts the inlined app island is
// the same JSON the /api/provenance/app endpoint serves.
func TestInliner_AppDataIsland_MatchesEndpoint(t *testing.T) {
	api := NewAPI(contentProvider(), evidenceStore(), log.Nop())

	rr := httptest.NewRecorder()
	api.HandleAppProvenance(rr, httptest.NewRequest(http.MethodGet, "/api/provenance/app", http.NoBody))
	endpoint := decodeJSON(t, rr.Body.Bytes())

	islandJSON, err := api.Inliner().AppDataIsland(context.Background())
	if err != nil {
		t.Fatalf("AppDataIsland: %v", err)
	}
	island := decodeJSON(t, islandJSON)

	// evidence.files / attestations.files come from map iteration, so their
	// order is nondeterministic in the endpoint itself; compare order-insensitively.
	normalizeFileOrder(endpoint)
	normalizeFileOrder(island)

	if !reflect.DeepEqual(endpoint, island) {
		t.Fatalf("app island differs from endpoint:\n endpoint=%v\n island=%v", endpoint, island)
	}
}

// TestInliner_ContentDataIsland_MatchesEndpoint asserts the inlined content
// island is the same JSON the /api/provenance/content endpoint serves (modulo
// runtime.server_time, which is request-time and inherently varies).
func TestInliner_ContentDataIsland_MatchesEndpoint(t *testing.T) {
	cp := contentProvider()
	api := NewAPI(cp, evidenceStore(), log.Nop())

	rr := httptest.NewRecorder()
	api.HandleContentProvenance(rr, httptest.NewRequest(http.MethodGet, "/api/provenance/content", http.NoBody))
	endpoint := decodeJSON(t, rr.Body.Bytes())

	islandJSON, err := api.Inliner().ContentDataIsland(context.Background(), cp.snap)
	if err != nil {
		t.Fatalf("ContentDataIsland: %v", err)
	}
	island := decodeJSON(t, islandJSON)

	dropServerTime(endpoint)
	dropServerTime(island)

	if !reflect.DeepEqual(endpoint, island) {
		t.Fatalf("content island differs from endpoint:\n endpoint=%v\n island=%v", endpoint, island)
	}
}

func decodeJSON(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return m
}

// dropServerTime removes runtime.server_time from a decoded content response.
func dropServerTime(m map[string]any) {
	if rt, ok := m["runtime"].(map[string]any); ok {
		delete(rt, "server_time")
	}
}

// normalizeFileOrder sorts the map-iteration-ordered file arrays of an app
// provenance response by path so two responses can be compared deterministically.
func normalizeFileOrder(m map[string]any) {
	for _, key := range []string{"evidence", "attestations"} {
		sub, ok := m[key].(map[string]any)
		if !ok {
			continue
		}
		files, ok := sub["files"].([]any)
		if !ok {
			continue
		}
		sort.Slice(files, func(i, j int) bool {
			return filePath(files[i]) < filePath(files[j])
		})
	}
}

func filePath(v any) string {
	if m, ok := v.(map[string]any); ok {
		if p, ok := m["path"].(string); ok {
			return p
		}
	}
	return ""
}
