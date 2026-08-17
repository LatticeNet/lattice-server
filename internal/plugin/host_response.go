package plugin

import (
	"encoding/json"
	"errors"
	"io"

	sdkplugin "github.com/LatticeNet/lattice-sdk/plugin"
)

const (
	boundedHostResponseError  = "host response exceeds protocol limits"
	maxHostResponseErrorBytes = 512
)

type hostResponseFrameBuilder func(json.RawMessage) ([]byte, error)

func encodeBoundedHostResponse(resp systemHostResponse, build hostResponseFrameBuilder) ([]byte, error) {
	if len(resp.Result) > sdkplugin.DefaultMaxHostResponsePayloadBytes || len(resp.Error) > maxHostResponseErrorBytes {
		resp = boundedHostResponseFailure(resp.ID)
	}
	response, err := json.Marshal(resp)
	if err != nil {
		resp = boundedHostResponseFailure(resp.ID)
		response, err = json.Marshal(resp)
		if err != nil {
			return nil, err
		}
	}
	frame, err := build(response)
	if err != nil || len(frame) > sdkplugin.DefaultMaxHostResponseFrameBytes {
		resp = boundedHostResponseFailure(resp.ID)
		response, marshalErr := json.Marshal(resp)
		if marshalErr != nil {
			return nil, marshalErr
		}
		frame, err = build(response)
	}
	if err != nil {
		return nil, err
	}
	if len(frame) > sdkplugin.DefaultMaxHostResponseFrameBytes {
		return nil, errors.New("bounded host response frame exceeds protocol limit")
	}
	return frame, nil
}

func emitBoundedHostResponse(w io.Writer, resp systemHostResponse, build hostResponseFrameBuilder) error {
	frame, err := encodeBoundedHostResponse(resp, build)
	if err != nil {
		return err
	}
	frame = append(frame, '\n')
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

func boundedHostResponseFailure(id string) systemHostResponse {
	return systemHostResponse{ID: id, OK: false, Error: boundedHostResponseError}
}

func buildLegacyHostResponseFrame(response json.RawMessage) ([]byte, error) {
	return json.Marshal(struct {
		HostResponse json.RawMessage `json:"host_response"`
	}{HostResponse: response})
}

func buildV2HostResponseFrame(generation uint64, invocation, hostCallID string) hostResponseFrameBuilder {
	return func(response json.RawMessage) ([]byte, error) {
		return json.Marshal(stdioJSONV2Frame{
			Protocol: 2, Kind: "host_response", Generation: generation, InvocationID: invocation,
			HostCallID: hostCallID, HostResponse: response,
		})
	}
}
