package prof

import (
	"context"
	"runtime"

	"github.com/grafana/pyroscope-go"

	"github.com/keithlinneman/linnemanlabs-web/internal/log"
	"github.com/keithlinneman/linnemanlabs-web/internal/xerrors"
)

type Options struct {
	Enabled              bool
	AppName              string
	ServerAddress        string
	AuthToken            string
	TenantID             string
	Tags                 map[string]string
	ProfileMutexFraction int
	BlockProfileRate     int
}

func Start(ctx context.Context, opts Options) (func(), error) {
	L := log.FromContext(ctx)

	if !opts.Enabled {
		L.Info(ctx, "pyroscope disabled")
		return func() {}, nil
	}

	if opts.ServerAddress == "" {
		err := xerrors.Newf("invalid server address (%q)", opts.ServerAddress)
		L.Error(ctx, err, "pyroscope options")
		return func() {}, err
	}

	if opts.ProfileMutexFraction > 0 {
		runtime.SetMutexProfileFraction(opts.ProfileMutexFraction)
	}
	if opts.BlockProfileRate > 0 {
		runtime.SetBlockProfileRate(opts.BlockProfileRate)
	}
	cfg := pyroscope.Config{
		ApplicationName: opts.AppName,
		ServerAddress:   opts.ServerAddress,
		Tags:            opts.Tags,
	}
	if tid := opts.TenantID; tid != "" {
		cfg.TenantID = tid
	}
	cfg.ProfileTypes = []pyroscope.ProfileType{
		pyroscope.ProfileCPU,
		pyroscope.ProfileAllocObjects,
		pyroscope.ProfileAllocSpace,
		pyroscope.ProfileInuseObjects,
		pyroscope.ProfileInuseSpace,
		pyroscope.ProfileGoroutines,
		pyroscope.ProfileMutexCount,
		pyroscope.ProfileMutexDuration,
		pyroscope.ProfileBlockCount,
		pyroscope.ProfileBlockDuration,
	}

	profiler, err := pyroscope.Start(cfg)
	if err != nil {
		L.Error(ctx, err, "pyroscope start failed",
			"server_address", opts.ServerAddress,
			"app_name", opts.AppName,
		)
		return func() {}, err
	}

	L.Info(ctx, "pyroscope started",
		"server_address", opts.ServerAddress,
		"app_name", opts.AppName,
	)

	return func() {
		profiler.Stop()
		L.Info(context.Background(), "pyroscope stopped",
			"server_address", opts.ServerAddress,
			"app_name", opts.AppName,
		)
	}, nil
}
