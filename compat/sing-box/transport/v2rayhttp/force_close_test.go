package v2rayhttp

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

func TestResetTransportClosesActiveHTTP2AndAllowsRedial(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("want HTTP/2, got %s", r.Proto)
		}
		if r.URL.Path == "/stream" {
			_, _ = io.WriteString(w, "ready")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = io.WriteString(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	transport := &forceCloseTransport{Transport: &http2.Transport{}}
	transport.DialTLSContext = func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
		dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}} // local test server
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return transport.track(conn), nil
	}
	defer transport.reset()
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
	response, err := client.Get(server.URL + "/stream")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.TLS == nil || response.TLS.NegotiatedProtocol != "h2" {
		t.Fatal("lost TLS connection state")
	}
	ready := make([]byte, 5)
	if _, err = io.ReadFull(response.Body, ready); err != nil {
		t.Fatal(err)
	}
	if string(ready) != "ready" {
		t.Fatalf("unexpected payload %q", ready)
	}
	if ResetTransport(transport) != transport {
		t.Fatal("reset replaced transport")
	}
	if _, err = io.ReadAll(response.Body); err == nil {
		t.Fatal("active stream survived reset")
	}
	response2, err := client.Get(server.URL + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	defer response2.Body.Close()
	payload, err := io.ReadAll(response2.Body)
	if err != nil || strings.TrimSpace(string(payload)) != "ok" {
		t.Fatalf("redial: %q, %v", payload, err)
	}
}
