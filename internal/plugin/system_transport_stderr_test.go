package plugin

import (
	"context"
	"io"
	"os"
	"testing"
	"time"
)

func newStderrMatcherTestTransport(t *testing.T) (*systemWorkerTransport, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	tr := &systemWorkerTransport{stderr: r, stderrDone: make(chan struct{})}
	go tr.drainStderr()
	t.Cleanup(func() {
		_ = w.Close()
		_ = r.Close()
		<-tr.stderrDone
	})
	return tr, w
}

func TestV2StderrMarkerExactStreamingBoundaries(t *testing.T) {
	tests := []struct {
		name      string
		payload   string
		limit     int
		want      string
		truncated bool
	}{
		{name: "empty", limit: 8},
		{name: "no newline", payload: "abc", limit: 8, want: "abc"},
		{name: "ends newline", payload: "abc\n", limit: 8, want: "abc\n"},
		{name: "cap exact", payload: "1234", limit: 4, want: "1234"},
		{name: "cap plus one", payload: "12345", limit: 4, want: "1234", truncated: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tr, w := newStderrMatcherTestTransport(t)
			tr.beginStderr(tc.limit, 7, "inv")
			marker := []byte(v2StderrCompleteMarkerPrefix + "7 inv\n")
			wire := append([]byte(tc.payload), marker...)
			for _, b := range wire { // force every possible marker boundary to split
				if _, err := w.Write([]byte{b}); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tr.waitStderrMarker(ctx); err != nil {
				t.Fatal(err)
			}
			got, truncated := tr.endStderr()
			if string(got) != tc.want || truncated != tc.truncated {
				t.Fatalf("stderr=(%q,%v), want (%q,%v)", got, truncated, tc.want, tc.truncated)
			}
		})
	}
}

func TestV2StderrMarkerExitWithoutMarkerReturnsPromptly(t *testing.T) {
	tr, w := newStderrMatcherTestTransport(t)
	tr.beginStderr(64, 8, "missing")
	if _, err := io.WriteString(w, "diagnostic"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tr.waitStderrMarker(ctx); err == nil {
		t.Fatal("missing marker unexpectedly accepted")
	}
}

func TestV2StderrMarkerSameWriteSuffixIsViolation(t *testing.T) {
	tr, w := newStderrMatcherTestTransport(t)
	tr.beginStderr(64, 9, "suffix")
	if _, err := io.WriteString(w, v2StderrCompleteMarkerPrefix+"9 suffix\nlate"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tr.waitStderrMarker(ctx); err != nil {
		t.Fatal(err)
	}
	if !tr.stderrProtocolViolation() {
		t.Fatal("raw bytes after marker were silently accepted")
	}
	tr.beginStderr(64, 9, "next")
	if !tr.stderrProtocolViolation() {
		t.Fatal("next invocation reset the prior terminal violation")
	}
}
