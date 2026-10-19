package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

func main() {
	var (
		webAddr = flag.String("web", "127.0.0.1:9494", "web UI listen address")
		dataDir = flag.String("data", "", "data directory (default: <project>/data)")
		caOut   = flag.String("ca-out", "", "where to export the CA cert (default: ~/Desktop/netlogger-ca.pem)")
	)
	flag.Parse()

	// Resolve data dir: flag, else next to the working directory.
	dir := *dataDir
	if dir == "" {
		wd, _ := os.Getwd()
		dir = filepath.Join(wd, "data")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatalf("data dir: %v", err)
	}

	cfgStore, err := newConfigStore(filepath.Join(dir, "config.json"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	ca, err := loadOrCreateCA(dir)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	logs, err := newLogStore(filepath.Join(dir, "logs"))
	if err != nil {
		log.Fatalf("logs: %v", err)
	}

	// Export CA cert for Firefox import.
	caPath := *caOut
	if caPath == "" {
		home, _ := os.UserHomeDir()
		caPath = filepath.Join(home, "Desktop", "netlogger-ca.pem")
	}
	if err := ca.exportCACert(caPath); err != nil {
		log.Printf("warning: could not export CA cert to %s: %v", caPath, err)
		caPath = filepath.Join(dir, "ca-cert.pem")
	}

	srv, err := NewServer(cfgStore, ca, logs)
	if err != nil {
		log.Fatalf("server: %v", err)
	}
	if err := srv.StartProxy(); err != nil {
		log.Fatalf("proxy listen: %v", err)
	}

	cfg := cfgStore.get()
	fmt.Println("netlogger")
	fmt.Printf("  proxy       : http://127.0.0.1:%d   (set Firefox HTTP+HTTPS proxy here)\n", cfg.ListenPort)
	fmt.Printf("  upstream    : %s\n", nonEmpty(cfg.UpstreamURL, "direct"))
	fmt.Printf("  web UI      : http://%s\n", *webAddr)
	fmt.Printf("  data dir    : %s\n", dir)
	fmt.Printf("  CA cert     : %s   (import into Firefox → Authorities)\n", caPath)
	fmt.Printf("  fingerprint : JA4 %s | Akamai %s\n", targetJA4, targetAkamai)
	fmt.Println()

	ws := &webServer{srv: srv, caPath: caPath, dataDir: dir}
	if err := ws.start(*webAddr); err != nil {
		log.Fatalf("web server: %v", err)
	}
}

func nonEmpty(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}
