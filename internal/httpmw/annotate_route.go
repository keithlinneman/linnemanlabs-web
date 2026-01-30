package httpmw

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// AnnotateHTTPRoute sets OTel http.route + span name using RoutePattern from chi
func AnnotateHTTPRoute(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)

		ctx := r.Context()
		// Get route pattern
		routePat := ""
		if rc := chi.RouteContext(ctx); rc != nil {
			routePat = rc.RoutePattern()
		}
		if routePat == "" {
			routePat = r.URL.Path
		}

		// Annotate prometheus metrics

		// Annotate span if recording
		span := trace.SpanFromContext(ctx)
		if span == nil || !span.IsRecording() {
			return
		}
		span.SetAttributes(attribute.String("http.route", routePat))
		span.SetName(r.Method + " " + routePat)
	})
}
