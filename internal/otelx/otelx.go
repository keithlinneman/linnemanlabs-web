package otelx

import (
	"context"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

type Options struct {
	Enabled   bool
	Endpoint  string
	Insecure  bool
	Sample    float64
	Service   string
	Component string
	Version   string
}

func Init(ctx context.Context, o Options) (func(context.Context) error, error) {
	if !o.Enabled {
		otel.SetTracerProvider(sdktrace.NewTracerProvider())
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{}, propagation.Baggage{},
		))
		return func(context.Context) error { return nil }, nil
	}

	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(o.Endpoint),
	}
	if o.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}

	// by default this is a blocking call with no timeout
	// we are using a local collector that forwards to otlp
	// backends so setting this to 3 seconds is safe
	dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
	defer dialCancel()
	exp, err := otlptracegrpc.New(dialCtx, opts...)
	if err != nil {
		return nil, err
	}

	res, _ := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithOS(),
		resource.WithHost(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(o.Service+"."+o.Component),
			semconv.ServiceVersionKey.String(o.Version),
		),
	)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(
			sdktrace.TraceIDRatioBased(o.Sample),
		)),
		sdktrace.WithBatcher(exp,
			sdktrace.WithMaxQueueSize(2048),
			sdktrace.WithBatchTimeout(5*time.Second),
		),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	return tp.Shutdown, nil
}
