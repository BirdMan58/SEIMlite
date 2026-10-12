package discovery

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPServiceMatchesNextcloud(t *testing.T) {
	body := `<html><head><title>Nextcloud</title></head><body><div id="login">Sign in</div></body></html>`
	if !httpServiceMatches("nextcloud", body, http.Header{}) {
		t.Fatal("nextcloud fingerprint should match a Nextcloud page")
	}
}

func TestHTTPServiceMatchesRejectsUnrelatedPage(t *testing.T) {
	body := `<html><head><title>Welcome to nginx</title></head><body>It works!</body></html>`
	if httpServiceMatches("nextcloud", body, http.Header{}) {
		t.Fatal("non-Nextcloud page should not match the Nextcloud fingerprint")
	}
}

func TestProbeHTTPServiceURLMatchesHTTPSNextcloud(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><head><title>Nextcloud</title></head><body>Sign in</body></html>`))
	}))
	defer srv.Close()

	if !probeHTTPServiceURL(srv.URL, "nextcloud") {
		t.Fatal("HTTPS Nextcloud page should match the Nextcloud fingerprint")
	}
}
