// Fuzz tests for the two functions that read untrusted text: the -groups list and names printed from peers.
// go test runs the seeds; go test -fuzz=FuzzParseGroups (or FuzzOneWord) searches further.
package main

import (
	"strings"
	"testing"
)

func FuzzParseGroups(f *testing.F) {
	for _, s := range []string{"X25519MLKEM768", "X25519MLKEM768,X25519", "SecP384r1MLKEM1024,P-256", "", ",", "x25519", "X25519,,X25519"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ids, err := parseGroups(s)
		if err != nil {
			if ids != nil {
				t.Fatalf("%q: error %v with ids %v", s, err, ids)
			}
			return
		}
		names := strings.Split(s, ",")
		if len(ids) != len(names) {
			t.Fatalf("%q: %d ids for %d names", s, len(ids), len(names))
		}
		for i, id := range ids {
			if groupNames[names[i]] != id {
				t.Fatalf("%q: name %q gave %v", s, names[i], id)
			}
		}
	})
}

func FuzzOneWord(f *testing.F) {
	for _, s := range []string{"nginx", "a b\tc\n", "ü\x00\x7f", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := oneWord(s)
		if len([]rune(out)) != len([]rune(s)) {
			t.Fatalf("%q -> %q: rune count changed", s, out)
		}
		for _, r := range out {
			if r <= ' ' || r >= 0x7f {
				t.Fatalf("%q -> %q: kept %q", s, out, r)
			}
		}
	})
}
