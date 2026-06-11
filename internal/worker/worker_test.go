package worker

import (
	"testing"

	"github.com/LatticeNet/lattice-sdk/model"
)

type fakeKV []model.KVEntry

func (f fakeKV) KV(bucket string) []model.KVEntry {
	out := []model.KVEntry{}
	for _, e := range f {
		if e.Bucket == bucket {
			out = append(out, e)
		}
	}
	return out
}

func TestWorkerRuntimeUsesExplicitCapabilities(t *testing.T) {
	_, err := Runtime{}.Run(model.WorkerScript{Source: "hello"}, Request{Path: "/"})
	if err == nil {
		t.Fatal("expected missing capability error")
	}
}

func TestWorkerRuntimeRendersTemplateWithKVRead(t *testing.T) {
	rt := Runtime{KV: fakeKV{{Bucket: "default", Key: "message", Value: "world"}}}
	resp, err := rt.Run(model.WorkerScript{
		Source:       "hello {{kv:default/message}} at {{path}}",
		Capabilities: []string{"worker:route", "kv:read"},
	}, Request{Path: "/edge"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != "hello world at /edge" {
		t.Fatalf("unexpected body %q", resp.Body)
	}
}

// A worker without kv:read must not be able to read KV values, even though it
// can route. The reference resolves to empty instead of leaking the value.
func TestWorkerRuntimeDeniesKVWithoutCapability(t *testing.T) {
	rt := Runtime{KV: fakeKV{{Bucket: "default", Key: "message", Value: "world"}}}
	resp, err := rt.Run(model.WorkerScript{
		Source:       "hello {{kv:default/message}} at {{path}}",
		Capabilities: []string{"worker:route"},
	}, Request{Path: "/edge"})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != "hello  at /edge" {
		t.Fatalf("expected KV value withheld, got %q", resp.Body)
	}
}

func TestValidateSourceBlocksDangerousPrimitives(t *testing.T) {
	if err := ValidateSource("fetch('http://169.254.169.254')"); err == nil {
		t.Fatal("expected fetch primitive to be blocked")
	}
}
