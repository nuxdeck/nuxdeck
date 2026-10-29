// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"strings"
	"testing"

	"github.com/nuxdeck/nuxdeck/internal/server/config"
)

func TestPublicURLDerivation(t *testing.T) {
	host, _ := os.Hostname()
	if host == "" {
		host = "localhost"
	}
	for _, tc := range []struct {
		name, public, addr, want string
	}{
		{"configured", "https://nux.example.com/", ":8443", "https://nux.example.com"},
		{"derived with port", "", ":8443", "https://" + host + ":8443"},
		{"derived default port", "", "0.0.0.0:443", "https://" + host},
		{"derived bind address ignored", "", "127.0.0.1:9443", "https://" + host + ":9443"},
	} {
		cfg := config.Defaults()
		cfg.Server.PublicURL, cfg.HTTP.HTTPSAddr = tc.public, tc.addr
		if got := publicURL(cfg); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if strings.HasSuffix(publicURL(config.Defaults()), "/") {
		t.Error("trailing slash")
	}
}
