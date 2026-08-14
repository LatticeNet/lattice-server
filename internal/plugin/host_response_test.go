package plugin

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	sdkplugin "github.com/LatticeNet/lattice-sdk/plugin"
)

func exactHostPayload(size int) json.RawMessage {
	return json.RawMessage(`"` + strings.Repeat("x", size-2) + `"`)
}

func decodeHostResponseFrame(t *testing.T, frame []byte, v2 bool) systemHostResponse {
	t.Helper()
	var raw json.RawMessage
	if v2 {
		decoded, err := decodeStdioJSONV2Frame(frame, sdkplugin.DefaultMaxHostResponseFrameBytes)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateStdioJSONV2Frame(decoded, 1, "1", "h1"); err != nil {
			t.Fatal(err)
		}
		raw = decoded.HostResponse
	} else {
		var envelope struct {
			HostResponse json.RawMessage `json:"host_response"`
		}
		if err := json.Unmarshal(frame, &envelope); err != nil {
			t.Fatal(err)
		}
		raw = envelope.HostResponse
	}
	var response systemHostResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestBoundedHostResponsePayloadAndFrameEdges(t *testing.T) {
	builders := []struct {
		name string
		v2   bool
		fn   hostResponseFrameBuilder
	}{{name: "fresh", fn: buildLegacyHostResponseFrame}, {name: "pooled", v2: true, fn: buildV2HostResponseFrame(1, "1", "h1")}}
	for _, builder := range builders {
		t.Run(builder.name, func(t *testing.T) {
			atPayload := systemHostResponse{ID: "h1", OK: true, Result: exactHostPayload(sdkplugin.DefaultMaxHostResponsePayloadBytes)}
			frame, err := encodeBoundedHostResponse(atPayload, builder.fn)
			if err != nil {
				t.Fatal(err)
			}
			if got := decodeHostResponseFrame(t, frame, builder.v2); !got.OK || len(got.Result) != sdkplugin.DefaultMaxHostResponsePayloadBytes {
				t.Fatalf("N response mismatch: %+v payload=%d", got, len(got.Result))
			}

			overPayload := atPayload
			overPayload.Result = exactHostPayload(sdkplugin.DefaultMaxHostResponsePayloadBytes + 1)
			frame, err = encodeBoundedHostResponse(overPayload, builder.fn)
			if err != nil {
				t.Fatal(err)
			}
			if got := decodeHostResponseFrame(t, frame, builder.v2); got.OK || got.ID != "h1" || got.Error != boundedHostResponseError || len(got.Result) != 0 {
				t.Fatalf("N+1 did not produce correlated bounded failure: %+v", got)
			}

			atFrameBuilder := padFirstHostResponseFrame(builder.fn, sdkplugin.DefaultMaxHostResponseFrameBytes)
			frame, err = encodeBoundedHostResponse(systemHostResponse{ID: "h1", OK: false, Error: "bounded"}, atFrameBuilder)
			if err != nil || len(frame) != sdkplugin.DefaultMaxHostResponseFrameBytes {
				t.Fatalf("F frame len=%d err=%v", len(frame), err)
			}
			if got := decodeHostResponseFrame(t, frame, builder.v2); got.Error != "bounded" {
				t.Fatal("F response was unexpectedly replaced")
			}

			overFrameBuilder := padFirstHostResponseFrame(builder.fn, sdkplugin.DefaultMaxHostResponseFrameBytes+1)
			frame, err = encodeBoundedHostResponse(systemHostResponse{ID: "h1", OK: false, Error: "bounded"}, overFrameBuilder)
			if err != nil {
				t.Fatal(err)
			}
			if got := decodeHostResponseFrame(t, frame, builder.v2); got.OK || got.Error != boundedHostResponseError {
				t.Fatalf("F+1 did not produce bounded failure: %+v", got)
			}

			canary := "vless://credential-canary private-key-canary"
			frame, err = encodeBoundedHostResponse(systemHostResponse{ID: "h1", OK: false, Error: strings.Repeat("e", maxHostResponseErrorBytes) + canary}, builder.fn)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(frame, []byte(canary)) {
				t.Fatalf("bounded broker error leaked diagnostic: %q", frame)
			}
			if got := decodeHostResponseFrame(t, frame, builder.v2); got.OK || got.Error != boundedHostResponseError {
				t.Fatalf("over-bound error did not produce canonical failure: %+v", got)
			}
		})
	}
}

func padFirstHostResponseFrame(base hostResponseFrameBuilder, target int) hostResponseFrameBuilder {
	first := true
	return func(response json.RawMessage) ([]byte, error) {
		frame, err := base(response)
		if err != nil || !first {
			return frame, err
		}
		first = false
		if len(frame) < target {
			frame = append(frame, bytes.Repeat([]byte(" "), target-len(frame))...)
		}
		return frame, nil
	}
}

func TestBoundedHostResponseOversizeThenSmallKeepsJSONLSynchronized(t *testing.T) {
	for _, builder := range []hostResponseFrameBuilder{buildLegacyHostResponseFrame, buildV2HostResponseFrame(1, "1", "h1")} {
		var stream bytes.Buffer
		if err := emitBoundedHostResponse(&stream, systemHostResponse{ID: "h1", OK: true, Result: exactHostPayload(sdkplugin.DefaultMaxHostResponsePayloadBytes + 1)}, builder); err != nil {
			t.Fatal(err)
		}
		if err := emitBoundedHostResponse(&stream, systemHostResponse{ID: "h1", OK: true, Result: json.RawMessage(`{"small":true}`)}, builder); err != nil {
			t.Fatal(err)
		}
		scanner := bufio.NewScanner(&stream)
		scanner.Buffer(make([]byte, 64*1024), sdkplugin.DefaultMaxHostResponseFrameBytes+1)
		lines := 0
		for scanner.Scan() {
			lines++
		}
		if err := scanner.Err(); err != nil || lines != 2 {
			t.Fatalf("JSONL stream desynchronized: lines=%d err=%v", lines, err)
		}
	}
}
