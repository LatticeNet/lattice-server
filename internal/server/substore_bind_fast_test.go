package server

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"reflect"
	"slices"
	"strings"
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

func sameRenderReply(t *testing.T, raw []byte) {
	t.Helper()
	got, gotErr := decodePluginRenderReply(raw)
	var want pluginRenderReply
	wantErr := json.Unmarshal(raw, &want)
	if (gotErr == nil) != (wantErr == nil) || gotErr != nil && gotErr.Error() != wantErr.Error() {
		t.Fatalf("reply %q: error %v, json.Unmarshal %v", raw, gotErr, wantErr)
	}
	if gotErr == nil && !reflect.DeepEqual(got, want) {
		t.Fatalf("reply %q: %+v, json.Unmarshal %+v", raw, got, want)
	}
}

var renderReplyCorpus = []string{
	`{"content":"","content_type":"application/json","target":"sing-box","plan":{"kind":"nodes","nodes":[]},"live_revision":"r","node_count":3}`,
	`{"content":"x","headers":{"a":"b"}}`, `{"Content":"x"}`, `{"content":"x","CONTENT":"y"}`, `{"content":1}`, `{"plan":null}`,
	`{"content":"a","content":"b"}`, `{"ſontent":"x"}`, `{"headers":{"a":1}}`, `[]`, `null`, `{"plan":{"a":1,"a":2}}`, `{"content":"x"} y`,
}

func TestDecodePluginRenderReplyIsJSONUnmarshal(t *testing.T) {
	for _, raw := range renderReplyCorpus {
		sameRenderReply(t, []byte(raw))
	}
}

func FuzzDecodePluginRenderReplyIsJSONUnmarshal(f *testing.F) {
	for _, raw := range renderReplyCorpus {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		sameRenderReply(t, raw)
	})
}

// legacyLineCatalogueSecretForms is lineCatalogueSecretForms before it
// skipped the JSON-escaped copy of a form that escaping leaves unchanged.
func legacyLineCatalogueSecretForms(secret string) []string {
	raws := [][]byte{[]byte(secret)}
	forms := []string{secret, url.QueryEscape(secret), url.PathEscape(secret)}
	if dashless := strings.ReplaceAll(secret, "-", ""); dashless != secret {
		if id, err := hex.DecodeString(dashless); err == nil && len(id) == 16 {
			forms = append(forms, dashless)
			raws = append(raws, id)
		}
	}
	for _, raw := range raws {
		forms = append(forms, base64.RawStdEncoding.EncodeToString(raw), base64.RawURLEncoding.EncodeToString(raw))
	}
	for _, form := range slices.Clone(forms) {
		if escaped, err := json.Marshal(form); err == nil {
			forms = append(forms, string(escaped[1:len(escaped)-1]))
		}
	}
	return forms
}

// The owner and identity checks look for the same needles as before.
func TestLineCatalogueSecretsFindTheSameNeedles(t *testing.T) {
	for _, secret := range []string{"8f0c2a9e-41d7-4b3c-8a5e-1f2d3c4b5a69", "s3cr3t/Pa55+w0rd=Id&x", `quote"back\slash`, "tab\there", "<html>&", "é-ü", " line", "\xff\xfe\xfd\xfc", "a\ufffdbc", "plain"} {
		got := newLineCatalogueSecrets([]string{secret}).needles
		var legacy lineCatalogueSecrets
		seen := map[string]bool{}
		for _, form := range legacyLineCatalogueSecretForms(secret) {
			if needle := strings.ToLower(form); !seen[needle] {
				seen[needle] = true
				legacy.needles = append(legacy.needles, []byte(needle))
			}
		}
		if !reflect.DeepEqual(got, legacy.needles) {
			t.Fatalf("secret %q: needles %q, before %q", secret, got, legacy.needles)
		}
	}
}
