package content

import (
	"io/fs"
	"time"
)

type Snapshot struct {
	FS         fs.FS
	Meta       Meta
	Provenance *Provenance
	LoadedAt   time.Time
}
