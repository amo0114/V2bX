package dns

import (
	"github.com/miekg/dns"
	"testing"
)

func TestCompatibilityDNSCacheLifetimeAndCopy(t *testing.T) {
	for _, disableExpire := range []bool{false, true} {
		client := NewClient(ClientOptions{DisableExpire: disableExpire})
		question := dns.Question{Name: "example.invalid.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
		message := &dns.Msg{Question: []dns.Question{question}}
		rr, err := dns.NewRR("example.invalid. 60 IN A 192.0.2.1")
		if err != nil {
			t.Fatal(err)
		}
		message.Answer = []dns.RR{rr}
		client.storeCache(nil, question, message, 60)
		response, ttl := client.loadResponse(question, nil)
		if response == nil || (!disableExpire && (ttl <= 0 || ttl > 60)) {
			t.Fatalf("cache miss or invalid TTL: %d", ttl)
		}
		response.Answer[0].Header().Name = "mutated.invalid."
		original, _ := client.loadResponse(question, nil)
		if original.Answer[0].Header().Name != question.Name {
			t.Fatal("cached response was mutated")
		}
		client.ClearCache()
		if response, _ := client.loadResponse(question, nil); response != nil {
			t.Fatal("cache survived clear")
		}
	}
	client := NewClient(ClientOptions{IndependentCache: true})
	if client.transportCache == nil || client.cache != nil {
		t.Fatal("independent cache initialization changed")
	}
}
