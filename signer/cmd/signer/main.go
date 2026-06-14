package main

import (
	"context"
	"log"
	"os"

	"kryard/signer/internal/api"
	"kryard/signer/internal/httpx"
	"kryard/signer/internal/kms"
)

func main() {
	addr := os.Getenv("SIGNER_ADDR")
	if addr == "" {
		addr = ":8081"
	}

	provider, err := kms.FromEnv(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	allowImport := os.Getenv("ALLOW_KEY_IMPORT") == "true"
	if allowImport {
		log.Print("WARNING: key import is ENABLED (ALLOW_KEY_IMPORT=true) — use only for controlled migrations")
	}

	deps := api.Deps{
		KMSProvider: provider,
		AllowImport: allowImport,
	}

	srv := api.NewServer(deps)
	httpSrv := httpx.NewHTTPServer(addr, srv)
	log.Printf("signer listening on %s (private internal API, KMS provider: %s)", addr, provider.Name())
	if err := httpSrv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
