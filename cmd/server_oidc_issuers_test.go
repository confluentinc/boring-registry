package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boring-registry/boring-registry/pkg/core"
	"github.com/boring-registry/boring-registry/pkg/discovery"
	"github.com/go-kit/kit/auth/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type flappingIssuer struct {
	*httptest.Server
	up atomic.Bool
}

func newFlappingIssuer(t *testing.T, up bool) *flappingIssuer {
	t.Helper()
	f := &flappingIssuer{}
	f.up.Store(up)
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" || !f.up.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.URL,
			"authorization_endpoint":                f.URL + "/auth",
			"token_endpoint":                        f.URL + "/token",
			"jwks_uri":                              f.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	t.Cleanup(f.Close)
	return f
}

func setOidcFlags(t *testing.T, configs ...string) {
	t.Helper()
	flagAuthOidcIssuer, flagAuthOidcClientId, flagAuthOktaIssuer = "", "", ""
	flagAuthOidc = configs
	t.Cleanup(func() { flagAuthOidc = nil })
}

func fetchDiscovery(t *testing.T, login loginSource) discovery.Discovery {
	t.Helper()
	mux := http.NewServeMux()
	registerDiscovery(mux, login)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/terraform.json", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var d discovery.Discovery
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &d))
	return d
}

func TestAuthMiddlewareStartsWithAllIssuersDown(t *testing.T) {
	first := newFlappingIssuer(t, false)
	second := newFlappingIssuer(t, false)
	setOidcFlags(t,
		fmt.Sprintf("client_id=first;issuer=%s", first.URL),
		fmt.Sprintf("client_id=second;issuer=%s", second.URL),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	mw, login, err := authMiddleware(ctx)
	require.NoError(t, err)
	require.NotNil(t, mw)
	assert.Less(t, time.Since(start), time.Second)

	d := fetchDiscovery(t, login)
	assert.Nil(t, d.LoginV1)
	assert.NotEmpty(t, d.ModulesV1)

	ctx = context.WithValue(ctx, jwt.JWTContextKey, "aaa.bbb.ccc")
	_, err = mw(func(context.Context, any) (any, error) { return nil, nil })(ctx, nil)
	assert.ErrorIs(t, err, core.ErrInvalidToken)
}

func TestAuthMiddlewareIssuersRecoverWhileRunning(t *testing.T) {
	first := newFlappingIssuer(t, false)
	second := newFlappingIssuer(t, false)
	setOidcFlags(t,
		fmt.Sprintf("client_id=first;issuer=%s", first.URL),
		fmt.Sprintf("client_id=second;issuer=%s", second.URL),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, login, err := authMiddleware(ctx)
	require.NoError(t, err)
	assert.Nil(t, fetchDiscovery(t, login).LoginV1)

	first.up.Store(true)
	require.Eventually(t, func() bool {
		d := fetchDiscovery(t, login)
		return d.LoginV1 != nil && d.LoginV1.Client == "first" && d.LoginV1.Authz == first.URL+"/auth"
	}, 10*time.Second, 50*time.Millisecond)
}
