package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newDiscoveryServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	var s *httptest.Server
	s = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		time.Sleep(delay)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, fmt.Sprintf(`{"issuer":%q,"authorization_endpoint":"/auth","token_endpoint":"/token","jwks_uri":"/keys","id_token_signing_alg_values_supported":["RS256"]}`, s.URL))
	}))
	t.Cleanup(s.Close)
	return s
}

func deadIssuerURL(t *testing.T) string {
	t.Helper()
	s := httptest.NewServer(http.NotFoundHandler())
	url := s.URL
	s.Close()
	return url
}

func setOidcFlags(t *testing.T, configs ...string) {
	t.Helper()
	flagAuthOidcIssuer, flagAuthOidcClientId, flagAuthOktaIssuer = "", "", ""
	flagAuthOidc = configs
	t.Cleanup(func() { flagAuthOidc = nil })
}

func TestAuthMiddlewareUnreachableAdditionalIssuer(t *testing.T) {
	healthy := newDiscoveryServer(t, 0)
	setOidcFlags(t,
		fmt.Sprintf("client_id=primary;issuer=%s", healthy.URL),
		fmt.Sprintf("client_id=secondary;issuer=%s", deadIssuerURL(t)),
	)

	mw, logins, err := authMiddleware(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, mw)
	require.Len(t, logins, 1)
	assert.Equal(t, "primary", logins[0].Client)
}

func TestAuthMiddlewareUnreachablePrimaryIssuer(t *testing.T) {
	healthy := newDiscoveryServer(t, 0)
	setOidcFlags(t,
		fmt.Sprintf("client_id=primary;issuer=%s", deadIssuerURL(t)),
		fmt.Sprintf("client_id=secondary;issuer=%s", healthy.URL),
	)

	_, _, err := authMiddleware(context.Background())
	assert.ErrorContains(t, err, "failed to set up oidc provider")
}

func TestAuthMiddlewareSlowIssuersDoNotShareTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("slow")
	}
	a := newDiscoveryServer(t, 9*time.Second)
	b := newDiscoveryServer(t, 9*time.Second)
	c := newDiscoveryServer(t, 0)
	setOidcFlags(t,
		fmt.Sprintf("client_id=a;issuer=%s", a.URL),
		fmt.Sprintf("client_id=b;issuer=%s", b.URL),
		fmt.Sprintf("client_id=c;issuer=%s", c.URL),
	)

	_, _, err := authMiddleware(context.Background())
	assert.NoError(t, err)
}
