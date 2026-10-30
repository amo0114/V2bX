//go:build with_utls

package tls

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	"github.com/xtls/reality"
)

func TestCompatibilityTimeoutClone(t *testing.T) {
	configs := []Config{
		&STDClientConfig{config: &tls.Config{}},
		&STDServerConfig{config: &tls.Config{}},
		&UTLSClientConfig{config: &utls.Config{}},
		&RealityServerConfig{config: &reality.Config{}},
		&RealityClientConfig{uClient: &UTLSClientConfig{config: &utls.Config{}}},
	}
	for _, config := range configs {
		if config.HandshakeTimeout() != 0 {
			t.Fatalf("%T changed default timeout", config)
		}
		config.SetHandshakeTimeout(time.Second)
		clone := config.Clone()
		if clone.HandshakeTimeout() != time.Second {
			t.Fatalf("%T lost timeout during clone", config)
		}
		clone.SetHandshakeTimeout(2 * time.Second)
		if config.HandshakeTimeout() != time.Second {
			t.Fatalf("%T clone mutated original", config)
		}
	}
}

func TestCompatibilityHandshakeDeadline(t *testing.T) {
	client, peer := net.Pipe()
	defer client.Close()
	defer peer.Close()
	config := &STDClientConfig{config: &tls.Config{InsecureSkipVerify: true}}
	config.SetHandshakeTimeout(30 * time.Millisecond)
	_, err := ClientHandshake(context.Background(), client, config)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}
