package v2rayhttp

import (
	"crypto/tls"
	"net"
	"net/http"
	"reflect"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
	"golang.org/x/net/http2"
)

// Track owned connections instead of inspecting http2's private pool layout.
// Go 1.27 delegates http2.Transport to net/http and removes that private pool.
type forceCloseTransport struct {
	*http2.Transport
	access      sync.Mutex
	connections map[*trackedHTTP2Conn]struct{}
}

func (t *forceCloseTransport) track(conn net.Conn) net.Conn {
	c := &trackedHTTP2Conn{Conn: conn, owner: t}
	t.access.Lock()
	if t.connections == nil {
		t.connections = make(map[*trackedHTTP2Conn]struct{})
	}
	t.connections[c] = struct{}{}
	t.access.Unlock()
	return c
}

func (t *forceCloseTransport) reset() {
	t.access.Lock()
	connections := t.connections
	t.connections = nil
	t.access.Unlock()
	for conn := range connections {
		_ = conn.Close()
	}
}

type trackedHTTP2Conn struct {
	net.Conn
	owner *forceCloseTransport
}

func (c *trackedHTTP2Conn) ConnectionState() tls.ConnectionState {
	if conn, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return conn.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (c *trackedHTTP2Conn) Close() error {
	c.owner.access.Lock()
	delete(c.owner.connections, c)
	c.owner.access.Unlock()
	return c.Conn.Close()
}

func ResetTransport(rawTransport http.RoundTripper) http.RoundTripper {
	switch transport := rawTransport.(type) {
	case *http.Transport:
		transport.CloseIdleConnections()
		return transport.Clone()
	case *forceCloseTransport:
		transport.reset()
		return transport
	default:
		panic(E.New("unknown transport type: ", reflect.TypeOf(transport)))
	}
}
