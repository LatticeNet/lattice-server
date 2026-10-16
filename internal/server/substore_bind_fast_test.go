package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"testing"
)

// legacyParseSubstoreNodeObject is parseSubstoreNodeObject before its
// strictjson fast path: the token walk alone.
func legacyParseSubstoreNodeObject(raw json.RawMessage) (substoreNodeObject, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return substoreNodeObject{}, errors.New("node is not a JSON object")
	}
	obj := substoreNodeObject{values: map[string]json.RawMessage{}}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return substoreNodeObject{}, errors.New("node key is not a string")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return substoreNodeObject{}, err
		}
		if _, dup := obj.values[key]; dup {
			return substoreNodeObject{}, errors.New("node repeats a key")
		}
		obj.keys = append(obj.keys, key)
		obj.values[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return substoreNodeObject{}, errors.New("node object is not closed")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return substoreNodeObject{}, errors.New("node has trailing data")
	}
	return obj, nil
}

func sameNodeObject(t *testing.T, raw []byte) {
	t.Helper()
	got, gotErr := parseSubstoreNodeObject(raw)
	want, wantErr := legacyParseSubstoreNodeObject(raw)
	if (gotErr == nil) != (wantErr == nil) || (gotErr != nil && gotErr.Error() != wantErr.Error()) {
		t.Fatalf("node %q: error %v, the token walk %v", raw, gotErr, wantErr)
	}
	if gotErr == nil && (!reflect.DeepEqual(got.keys, want.keys) || !reflect.DeepEqual(got.values, want.values)) {
		t.Fatalf("node %q: %v %v, the token walk %v %v", raw, got.keys, got.values, want.keys, want.values)
	}
}

var nodeObjectCorpus = []string{
	`{"name":"a","type":"vless","port":443,"reality-opts":{"public-key":"k","short-id":"0a"},"tags":["x"]}`,
	` {"a" : 1 , "b":[1, 2]} `, `{"a":{"b":1,"b":2}}`, `{"a":1,"a":2}`, `{"a":1e999}`, `{"a":1,"a":2}`,
	`{}`, `[]`, `"x"`, `{"a":1}{}`, `{"a":1} x`, `{"a":}`, `{"a":1,}`, ``, "{\"\xff\":1}", `{"a":"<b>"}`,
}

func TestParseSubstoreNodeObjectMatchesTheTokenWalk(t *testing.T) {
	for _, raw := range nodeObjectCorpus {
		sameNodeObject(t, []byte(raw))
	}
}

func FuzzParseSubstoreNodeObjectMatchesTheTokenWalk(f *testing.F) {
	for _, raw := range nodeObjectCorpus {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		sameNodeObject(t, raw)
	})
}
