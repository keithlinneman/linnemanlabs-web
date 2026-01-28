package version_test

import (
	"testing"

	v "github.com/keithlinneman/linnemanlabs-web/internal/version"
)

func TestVCSDirtyTriState(t *testing.T) {
	v.VCSDirty = nil
	info := v.Get()
	if info.VCSDirty != nil {
		t.Fatalf("VCSDirty = %v, want nil", info.VCSDirty)
	}

	trueVal := true
	v.VCSDirty = &trueVal
	info = v.Get()
	if info.VCSDirty == nil || *info.VCSDirty != true {
		t.Fatalf("VCSDirty = %v, want true", info.VCSDirty)
	}

	falseVal := false
	v.VCSDirty = &falseVal
	info = v.Get()
	if info.VCSDirty == nil || *info.VCSDirty != false {
		t.Fatalf("VCSDirty = %v, want false", info.VCSDirty)
	}
}
