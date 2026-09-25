package discovery

import (
	"net/http"
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
