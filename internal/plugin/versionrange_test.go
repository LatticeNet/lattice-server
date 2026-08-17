package plugin

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.8.0-alpha.5", "0.8.0-alpha.7", -1},
		{"0.8.0-alpha.7", "0.8.0-alpha.5", 1},
		{"0.8.0-alpha.7", "0.8.0-alpha.7", 0},
		{"0.8.0-alpha.7", "0.8.0", -1}, // release outranks prerelease
		{"0.8.0", "0.8.0-alpha.7", 1},
		{"0.8.0", "0.8.1", -1},
		{"0.2.9", "0.3.0", -1},
		{"0.3.3", "0.3.3", 0},
		{"v0.3.3", "0.3.3", 0},                    // v-prefix tolerated
		{"0.8.0-alpha.2", "0.8.0-beta.1", -1},     // alpha < beta lexically
		{"0.12.1-alpha.8", "0.12.1-alpha.10", -1}, // numeric tail, not lexical
		{"1.0", "1.0.0", 0},                       // missing segments read as zero
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	cases := []struct {
		version, expr string
		want          bool
	}{
		{"0.8.0-alpha.7", "", true},
		{"0.8.0-alpha.7", "*", true},
		{"0.8.0-alpha.7", ">=0.8.0-alpha.5", true},
		{"0.8.0-alpha.5", ">=0.8.0-alpha.5", true},
		{"0.8.0-alpha.4", ">=0.8.0-alpha.5", false},
		{"0.8.0", ">=0.8.0-alpha.5", true},
		{"0.8.0-alpha.7", ">=0.8.0-alpha.5, <0.9", true},
		{"0.9.0", ">=0.8.0-alpha.5, <0.9", false},
		{"0.8.0-alpha.7", "0.8.0-alpha.7", true},
		{"0.8.0-alpha.7", "==0.8.0-alpha.8", false},
		{"0.8.0-alpha.7", "!=0.8.0-alpha.6", true},
		{"0.8.0-alpha.7", ">0.8.0-alpha.7", false},
		{"0.8.0-alpha.7", "<=0.8.0-alpha.7", true},
		{"0.8.0-alpha.7", "garbage!!", false},
	}
	for _, c := range cases {
		if got := versionInRange(c.version, c.expr); got != c.want {
			t.Errorf("versionInRange(%q, %q) = %v, want %v", c.version, c.expr, got, c.want)
		}
	}
}

func TestValidVersionRange(t *testing.T) {
	for _, ok := range []string{"", "*", ">=0.8.0-alpha.5", ">=1.0, <2.0", "==0.3.3"} {
		if err := validVersionRange(ok); err != nil {
			t.Errorf("validVersionRange(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{">=", "abc", ">= 1.0 ", "=>1.0"} {
		if err := validVersionRange(bad); err == nil {
			t.Errorf("validVersionRange(%q) = nil, want error", bad)
		}
	}
}
