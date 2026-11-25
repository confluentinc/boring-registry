package cmd

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthMiddleware(t *testing.T) {
	data := `{
				"issuer": "ISSUER",
				"authorization_endpoint": "/auth",
				"token_endpoint": "/token",
				"jwks_uri": "/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`

	hf := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, strings.ReplaceAll(data, "ISSUER", flagAuthOidcIssuer))
	}
	s := httptest.NewServer(http.HandlerFunc(hf))
	defer s.Close()

	tests := []struct {
		name                string
		authOidc            []string
		authOidcIssuer      string
		authOidcClientId    string
		authOktaIssuer      string
		authOktaClientId    string
		authOktaAuthz       string
		authOktaToken       string
		wantErr             bool
		errMessage          string
		authIssuer          string
		expectedOidcClients []string
	}{
		{
			name:             "only OIDC is configured",
			authOidcIssuer:   s.URL,
			authOidcClientId: "boring-registry",
		},
		{
			name:             "OIDC and Okta are both configured",
			authOidcIssuer:   s.URL,
			authOidcClientId: "boring-registry",
			authOktaIssuer:   "something",
			wantErr:          true,
			errMessage:       "both OIDC and Okta are configured, only one is allowed at a time",
		},
		{
			name:             "Okta is configured",
			authOktaIssuer:   "something",
			authOktaClientId: "boring-registry",
			authOktaAuthz:    "/authz",
			authOktaToken:    "/token",
		},
		{
			name: "Multiple OIDC set",
			authOidc: []string{
				fmt.Sprintf("client_id=boring-registry-test1;issuer=%s;scopes=openid;login_grants=grants1,grants2;login_ports=123,456", s.URL),
				fmt.Sprintf("client_id=boring-registry-test2;issuer=%s;scopes=openid", s.URL),
			},
			authIssuer:          s.URL,
			expectedOidcClients: []string{"boring-registry-test1", "boring-registry-test2"},
		},
	}

	for _, test := range tests {
		// Initializing global variables, this is potentially problematic!
		flagAuthOidcIssuer = test.authOidcIssuer
		if flagAuthOidcIssuer == "" {
			flagAuthOidcIssuer = test.authIssuer
		}
		flagAuthOidcClientId = test.authOidcClientId
		flagAuthOktaIssuer = test.authOktaIssuer
		flagAuthOktaClientId = test.authOktaClientId
		flagAuthOktaAuthz = test.authOktaAuthz
		flagAuthOktaToken = test.authOktaToken
		flagAuthOidc = test.authOidc

		ctx, cancel := context.WithCancel(context.Background())
		mw, login, err := authMiddleware(ctx)
		if test.wantErr {
			assert.Error(t, err)
			assert.ErrorContains(t, err, test.errMessage)
		} else {
			assert.NoError(t, err)
			assert.NotNil(t, mw)
			if assert.NotNil(t, login) {
				wantClient := test.authOktaClientId
				if len(test.authOidc) > 0 {
					wantClient = test.expectedOidcClients[0]
				} else if test.authOidcIssuer != "" {
					wantClient = test.authOidcClientId
				}

				assert.Eventually(t, func() bool { return login() != nil }, 5*time.Second, 10*time.Millisecond)
				l := login()
				assert.Equal(t, wantClient, l.Client)
				assert.NotEmpty(t, l.Authz)
				assert.NotEmpty(t, l.Token)
				assert.NotEmpty(t, l.GrantTypes)
				assert.NotEmpty(t, l.Ports)
			}
		}
		cancel()
	}
}
