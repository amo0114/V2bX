package dispatcher

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/geodata"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

type overrideSniffResult struct {
	domain, protocol string
}

func (r overrideSniffResult) Domain() string   { return r.domain }
func (r overrideSniffResult) Protocol() string { return r.protocol }

func TestShouldOverrideHonorsCoreExclusions(t *testing.T) {
	domains, err := (&geodata.MphDomainMatcherFactory{}).BuildMatcher([]*geodata.DomainRule{
		{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Full, Value: "excluded.example"}}},
		{Value: &geodata.DomainRule_Custom{Custom: &geodata.Domain{Type: geodata.Domain_Regex, Value: `^private\.`}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	privateIPs := geodata.GetPrivateIPMatcher()
	for _, tc := range []struct {
		name, domain, target string
		excludeDomains       geodata.DomainMatcher
		excludeIPs           geodata.IPMatcher
		protocols            []string
		want                 bool
	}{
		{name: "ordinary TLS", domain: "public.example", target: "8.8.8.8", protocols: []string{"tls"}, want: true},
		{name: "excluded domain ignores case", domain: "EXCLUDED.EXAMPLE", target: "8.8.8.8", excludeDomains: domains, protocols: []string{"tls"}},
		{name: "excluded regex", domain: "private.example", target: "8.8.8.8", excludeDomains: domains, protocols: []string{"tls"}},
		{name: "unmatched domain", domain: "public.example", target: "8.8.8.8", excludeDomains: domains, protocols: []string{"tls"}, want: true},
		{name: "excluded destination IP", domain: "public.example", target: "10.0.0.1", excludeIPs: privateIPs, protocols: []string{"tls"}},
		{name: "unmatched destination IP", domain: "public.example", target: "8.8.8.8", excludeIPs: privateIPs, protocols: []string{"tls"}, want: true},
		{name: "domain destination skips IP matcher", domain: "public.example", target: "original.example", excludeIPs: privateIPs, protocols: []string{"tls"}, want: true},
		{name: "protocol not requested", domain: "public.example", target: "8.8.8.8", protocols: []string{"http"}},
		{name: "empty sniffed domain", target: "8.8.8.8", protocols: []string{"tls"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := session.SniffingRequest{
				ExcludeForDomain:               tc.excludeDomains,
				ExcludeForIP:                   tc.excludeIPs,
				OverrideDestinationForProtocol: tc.protocols,
			}
			d := &DefaultDispatcher{}
			got := d.shouldOverride(context.Background(), overrideSniffResult{tc.domain, "tls"}, request,
				net.TCPDestination(net.ParseAddress(tc.target), 443))
			if got != tc.want {
				t.Fatalf("shouldOverride() = %v, want %v", got, tc.want)
			}
		})
	}
}
