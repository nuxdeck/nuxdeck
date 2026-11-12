// SPDX-License-Identifier: AGPL-3.0-only

package telemetry

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// The default telemetry client refuses TLS below 1.2 whatever Go release is built.
func TestTEL_DefaultClientRequiresTLS12(t *testing.T) {
	s := New(Options{})
	tr, ok := s.o.Client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport = %T, want *http.Transport", s.o.Client.Transport)
	}
	if tr.TLSClientConfig == nil || tr.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("TLS MinVersion = %+v, want TLS 1.2", tr.TLSClientConfig)
	}
	if s.o.Client.CheckRedirect == nil {
		t.Fatal("redirects must not be followed")
	}
}
