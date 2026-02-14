package version

import "runtime/debug"

const AppName = "linnemanlabs-web"

// set via -ldflags at build time
var (
	Version    = "dev"
	Commit     = "none"
	CommitDate string
	BuildDate  string
	BuildId    string
	GoVersion  string
	VCSDirty   *bool

	// github user that initiated the build by triggering the workflow
	BuildActor string

	// source repo
	Repository string

	// "github-actions", "local", etc
	BuildSystem string

	// iam role or github oidc subject depending if local or ci build
	BuilderIdentity string

	// github runner metadata, empty for local builds
	BuildRunID  string
	BuildRunURL string

	// key that attestations are tied to
	ReleaseId string

	// where we fetch attestations at runtime
	EvidenceBucket string
	EvidencePrefix string

	// reference to cosign key used to sign artifacts
	CosignKeyRef string
)

type Info struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	CommitDate string `json:"commit_date"`
	BuildDate  string `json:"build_date"`
	BuildId    string `json:"build_id"`
	GoVersion  string `json:"go_version"`
	VCSDirty   *bool  `json:"vcs_dirty,omitempty"`

	Repository      string `json:"repository,omitempty"`
	BuildActor      string `json:"build_actor,omitempty"`
	BuildSystem     string `json:"build_system,omitempty"`
	BuilderIdentity string `json:"builder_identity,omitempty"`
	BuildRunID      string `json:"build_run_id,omitempty"`
	BuildRunURL     string `json:"build_run_url,omitempty"`
	ReleaseId       string `json:"release_id,omitempty"`
	EvidenceBucket  string `json:"evidence_bucket,omitempty"`
	EvidencePrefix  string `json:"evidence_prefix,omitempty"`
	CosignKeyRef    string `json:"cosign_key_ref,omitempty"`
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

		Repository:      Repository,
		BuildActor:      BuildActor,
		BuildSystem:     BuildSystem,
		BuilderIdentity: BuilderIdentity,
		BuildRunID:      BuildRunID,
		BuildRunURL:     BuildRunURL,
		ReleaseId:       ReleaseId,
		EvidenceBucket:  EvidenceBucket,
		EvidencePrefix:  EvidencePrefix,
		CosignKeyRef:    CosignKeyRef,
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

	// if not set by ldflags in ci then assume local build
	if out.BuildSystem == "" {
		if out.Version == "dev" {
			out.BuildSystem = "local"
		}
	}

	return out
}

// HasProvenance returns whether this binary has ci injected provenance
// used for conditional attestation fetching at startup
func (i Info) HasProvenance() bool {
	return i.ReleaseId != "" && i.EvidenceBucket != ""
}
