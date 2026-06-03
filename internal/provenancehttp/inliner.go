package provenancehttp

import (
	"context"
	"encoding/json"
	"time"

	"github.com/keithlinneman/linnemanlabs-web/internal/content"
)

// Inliner returns an adapter that fills a content bundle's provenance data
// islands with the exact JSON served by /api/provenance/app and
// /api/provenance/content. Wire it into content.LoaderOptions.Inliner so each
// freshly loaded bundle is augmented in-memory before it is published.
func (api *API) Inliner() content.ProvenanceInliner {
	return &provenanceInliner{api: api}
}

type provenanceInliner struct{ api *API }

func (in *provenanceInliner) AppDataIsland(ctx context.Context) ([]byte, error) {
	return marshalIsland(in.api.buildAppProvenance(ctx))
}

func (in *provenanceInliner) ContentDataIsland(ctx context.Context, snap *content.Snapshot) ([]byte, error) {
	return marshalIsland(buildContentResponse(snap, time.Now().UTC()))
}

// marshalIsland encodes v for embedding inside an HTML <script> data island.
func marshalIsland(v any) ([]byte, error) {
	return json.Marshal(v)
}
