package content

import "io/fs"

type Snapshot struct {
	FS   fs.FS
	Meta Meta
}
