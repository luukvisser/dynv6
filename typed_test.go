package dynv6

import (
	"net/netip"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// Typed records (libdns.Address, libdns.TXT, ...) must be accepted, not only
// libdns.RR: callers such as caddy-dynamicdns pass libdns.Address. Offline;
// no API token needed.
func TestTypedRecords(t *testing.T) {
	var a libdns.Record = libdns.Address{Name: "www", IP: netip.MustParseAddr("192.0.2.1"), TTL: time.Minute}
	r, err := fromLibdnsRecord("example.dynv6.net", &a)
	if err != nil {
		t.Fatalf("fromLibdnsRecord(Address): %v", err)
	}
	if r.Name != "www" || r.Type != "A" || r.Data != "192.0.2.1" || r.TTL != time.Minute {
		t.Fatalf("unexpected record %+v", r)
	}

	var aaaa libdns.Record = libdns.Address{Name: "@", IP: netip.MustParseAddr("2001:db8::1")}
	if r, err := fromLibdnsRecord("example.dynv6.net", &aaaa); err != nil || r.Type != "AAAA" {
		t.Fatalf("fromLibdnsRecord(AAAA): %+v, %v", r, err)
	}

	var txt libdns.Record = libdns.TXT{Name: "_acme-challenge", Text: "token"}
	if got := getDataFromRecord(txt); got != "token" {
		t.Fatalf("getDataFromRecord(TXT) = %q", got)
	}

	recs := []record{{ID: 1, Name: "www", Type: "A", Data: "192.0.2.1"}}
	if f := findRecord(recs, &a); f == nil || f.ID != 1 {
		t.Fatalf("findRecord(Address) = %+v", f)
	}
	if f := findRecordWithValue(recs, &a); f == nil || f.ID != 1 {
		t.Fatalf("findRecordWithValue(Address) = %+v", f)
	}

	var nilRec libdns.Record
	if _, err := fromLibdnsRecord("example.dynv6.net", &nilRec); err == nil {
		t.Fatal("fromLibdnsRecord(nil) gave no error")
	}
	if findRecord(recs, &nilRec) != nil {
		t.Fatal("findRecord(nil) found something")
	}
}
