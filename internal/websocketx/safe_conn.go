// Package websocketx adapts a gorilla *websocket.Conn into an
// io.ReadWriteCloser so two terminal WebSocket legs can be spliced with a plain
// io.Copy pair.
//
// gorilla forbids concurrent callers of its data-write methods (NextWriter /
// WriteMessage); calling them from two goroutines panics the connection. Every
// data and control/text write is therefore serialized through a single mutex.
// This is the load-bearing correctness property of the adapter: a byte pump and
// a future keepalive writer can safely share one connection.
package websocketx

import (
	"io"
	"sync"

	"github.com/gorilla/websocket"
)

var _ io.ReadWriteCloser = (*Conn)(nil)

// Conn wraps a gorilla WebSocket connection and exposes it as an
// io.ReadWriteCloser. Reads return message payloads and transparently skip
// zero-length keepalive frames; writes emit binary frames and are serialized so
// data and control writers never race.
type Conn struct {
	*websocket.Conn
	writeMu sync.Mutex
	readBuf []byte
}

// NewConn wraps conn. The returned Conn owns all writes to conn; callers must
// not write to the underlying connection directly (doing so reintroduces the
// concurrent-writer panic this type exists to prevent).
func NewConn(conn *websocket.Conn) *Conn {
	return &Conn{Conn: conn}
}

// Write sends data as a single binary WebSocket frame. Safe to call
// concurrently with WriteMessage; both serialize on the same mutex.
func (c *Conn) Write(data []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.Conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		return 0, err
	}
	return len(data), nil
}

// WriteMessage sends a single WebSocket frame of the given type, serialized
// against all other writers. Resize control frames are sent with
// websocket.TextMessage; this overrides the embedded method so the write mutex
// is always held.
func (c *Conn) WriteMessage(messageType int, data []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.Conn.WriteMessage(messageType, data)
}

// Read returns the payload of the next data frame. Zero-length frames (used as
// cheap keepalives) are skipped so they never surface to io.Copy as a spurious
// empty read. A payload larger than the caller's buffer is retained and drained
// across subsequent reads.
func (c *Conn) Read(data []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(data, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}
	for {
		_, payload, err := c.Conn.ReadMessage()
		if err != nil {
			return 0, err
		}
		if len(payload) == 0 {
			// Zero-length keepalive frame; keep waiting for real data.
			continue
		}
		n := copy(data, payload)
		if n < len(payload) {
			c.readBuf = payload[n:]
		}
		return n, nil
	}
}

// SetReadLimit caps the size of a single inbound message. An oversized frame
// makes the next Read return an error, which tears the bridge down. Passthrough
// to the underlying connection.
func (c *Conn) SetReadLimit(limit int64) {
	c.Conn.SetReadLimit(limit)
}
