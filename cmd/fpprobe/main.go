// Command fpprobe checks what netlog's fingerprint profiles look like on the
// wire, using a TLS-fingerprint reflection service (tls.peet.ws).
//
//	go run ./cmd/fpprobe                          # every profile, summary
//	go run ./cmd/fpprobe -profile chrome_155 -raw # one profile, full JSON
//	go run ./cmd/fpprobe -check                   # verified profiles vs their captures; exits 1 on mismatch
//	go run ./cmd/fpprobe -proxy http://127.0.0.1:12345
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/mosphox/netlog/internal/fp"
)

func main() {
	proxy := flag.String("proxy", "", "upstream proxy URL, e.g. http://127.0.0.1:12345")
	only := flag.String("profile", "", "probe only this profile id")
	raw := flag.Bool("raw", false, "print the full JSON response")
	check := flag.Bool("check", false, "probe verified profiles only and fail on any mismatch")
	flag.Parse()

	failed := false
	for _, p := range fp.All() {
		if (*only != "" && p.ID != *only) || (*check && !p.Verified) {
			continue
		}
		r, err := fp.Probe(p, *proxy)
		if err != nil {
			fmt.Printf("%-12s ERROR %v\n", p.ID, err)
			failed = true
			continue
		}
		if *raw {
			fmt.Println(string(r.Raw))
			continue
		}
		fmt.Printf("%-12s ja4 %s  akamai %s  ja3 %s  peetprint %s\n", p.ID, r.JA4, r.AkamaiHash, r.JA3Hash, r.Peetprint)
		for _, c := range r.Checks {
			if !c.OK {
				failed = true
				fmt.Printf("             MISMATCH %s\n               want %s\n               got  %s\n", c.Name, c.Want, c.Got)
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}
