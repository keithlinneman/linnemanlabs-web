package version

import "runtime/debug"

var (
	Version    = "dev"
	Commit     = "none"
	CommitDate string
	BuildDate  string
	BuildId    string
	GoVersion  string
	VCSDirty   *bool
)

type Info struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	CommitDate string `json:"commit_date"`
	BuildDate  string `json:"build_date"`
	BuildId    string `json:"build_id"`
	GoVersion  string `json:"go_version"`
	VCSDirty   *bool  `json:"vcs_dirty,omitempty"`
}

func Get() Info {
	out := Info{
		Version:    Version,
		Commit:     Commit,
		CommitDate: CommitDate,
		BuildDate:  BuildDate,
		BuildId:    BuildId,
		GoVersion:  GoVersion,
		VCSDirty:   VCSDirty,
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		out.GoVersion = bi.GoVersion
		var dirty *bool
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if out.Commit == "none" && s.Value != "" {
					out.Commit = s.Value
				}
			case "vcs.time":
				if out.BuildDate == "" && s.Value != "" {
					out.BuildDate = s.Value
				}
				out.CommitDate = s.Value
			case "vcs.modified":
				switch s.Value {
				case "true":
					t := true
					dirty = &t
				case "false":
					f := false
					dirty = &f
				}
			}
		}
		if dirty != nil {
			out.VCSDirty = dirty
		}
	}

	return out
}
