package worker

import (
	"errors"
	"fmt"
	"strings"

	"github.com/LatticeNet/lattice-sdk/model"
)

type KVReader interface {
	KV(bucket string) []model.KVEntry
}

type Runtime struct {
	KV KVReader
}

type Request struct {
	Path string `json:"path"`
}

type Response struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

func (r Runtime) Run(script model.WorkerScript, req Request) (Response, error) {
	if !hasCapability(script.Capabilities, "worker:route") {
		return Response{}, errors.New("worker lacks worker:route capability")
	}
	body := script.Source
	body = strings.ReplaceAll(body, "{{path}}", req.Path)
	// KV interpolation is a privileged capability: a worker may only read the
	// KV store when it explicitly declares kv:read. Otherwise references resolve
	// to empty so a route worker cannot exfiltrate KV it was not granted.
	if hasCapability(script.Capabilities, "kv:read") {
		body = replaceKV(body, r.KV)
	} else {
		body = replaceKV(body, nil)
	}
	return Response{Status: 200, Body: body}, nil
}

// replaceKV resolves {{kv:bucket/key}} references. A nil reader resolves every
// reference to empty, which is how an unauthorized worker is denied KV access
// without leaking the reference text.
func replaceKV(body string, kv KVReader) string {
	for {
		start := strings.Index(body, "{{kv:")
		if start < 0 {
			return body
		}
		end := strings.Index(body[start:], "}}")
		if end < 0 {
			return body
		}
		end += start
		ref := strings.TrimPrefix(body[start:end], "{{kv:")
		parts := strings.SplitN(ref, "/", 2)
		value := ""
		if kv != nil && len(parts) == 2 {
			for _, entry := range kv.KV(parts[0]) {
				if entry.Key == parts[1] {
					value = entry.Value
					break
				}
			}
		}
		body = body[:start] + value + body[end+2:]
	}
}

func hasCapability(caps []string, cap string) bool {
	for _, c := range caps {
		if c == cap {
			return true
		}
	}
	return false
}

func ValidateSource(source string) error {
	blocked := []string{"os.", "exec(", "process.env", "require(", "fetch("}
	for _, item := range blocked {
		if strings.Contains(source, item) {
			return fmt.Errorf("worker source references blocked primitive %q", item)
		}
	}
	return nil
}
