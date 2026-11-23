package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/boring-registry/boring-registry/pkg/core"
	"github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOidcProviderDiscovery(t *testing.T) {
	data := `{
				"issuer": "ISSUER",
				"authorization_endpoint": "/auth",
				"token_endpoint": "/token",
				"jwks_uri": "/keys",
				"id_token_signing_alg_values_supported": ["RS256"]
			}`

	var issuer string
	hf := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, err := io.WriteString(w, strings.ReplaceAll(data, "ISSUER", issuer)); err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}
	s := httptest.NewServer(http.HandlerFunc(hf))
	defer s.Close()
	issuer = s.URL

	provider := newReadyProvider(t, issuer, "boring-registry", false)
	authURL, tokenURL, ok := provider.Endpoints()
	assert.True(t, ok)
	assert.NotEmpty(t, authURL)
	assert.NotEmpty(t, tokenURL)
}

func TestOidcProviderGetIssuer(t *testing.T) {
	issuer := "https://example.com"
	provider := &OidcProvider{
		issuer: issuer,
	}

	assert.Equal(t, issuer, provider.GetIssuer())
}

func TestOidcProviderNonJWTTokenHandling(t *testing.T) {
	tests := []struct {
		name               string
		acceptNonJWTTokens bool
		token              string
		expectError        bool
	}{
		{
			name:               "Non-JWT token accepted when configured",
			acceptNonJWTTokens: true,
			token:              "non-jwt-token-from-ci-system",
			expectError:        false,
		},
		{
			name:               "Non-JWT token rejected when not configured",
			acceptNonJWTTokens: false,
			token:              "non-jwt-token-from-ci-system",
			expectError:        true,
		},
		{
			name:               "Empty token always rejected",
			acceptNonJWTTokens: true,
			token:              "",
			expectError:        true,
		},
		{
			name:               "Short token rejected",
			acceptNonJWTTokens: true,
			token:              "short",
			expectError:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := &OidcProvider{
				logger:             slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})),
				issuer:             "https://example.com",
				acceptNonJWTTokens: tt.acceptNonJWTTokens,
			}

			err := provider.Verify(context.Background(), tt.token)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOidcProviderValidateNonJWTToken(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))

	provider := &OidcProvider{
		logger: logger,
		issuer: "https://example.com",
	}

	tests := []struct {
		name        string
		token       string
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid token",
			token:       "valid-ci-token-1234567890",
			expectError: false,
		},
		{
			name:        "empty token",
			token:       "",
			expectError: true,
			errorMsg:    "empty token",
		},
		{
			name:        "token too short",
			token:       "short",
			expectError: true,
			errorMsg:    "token too short",
		},
		{
			name:        "minimum length token",
			token:       "1234567890",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := provider.validateNonJWTToken(tt.token)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestOidcProviderVerify(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))

	t.Run("Non-JWT token validation", func(t *testing.T) {
		provider := &OidcProvider{
			logger:             logger,
			issuer:             "https://example.com",
			acceptNonJWTTokens: true,
		}

		err := provider.Verify(context.Background(), "valid-ci-token")
		assert.NoError(t, err)

		err = provider.Verify(context.Background(), "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "empty token")
	})

	t.Run("Regular OIDC token validation", func(t *testing.T) {
		data := `{
			"issuer": "ISSUER",
			"authorization_endpoint": "/auth",
			"token_endpoint": "/token",
			"jwks_uri": "/keys",
			"id_token_signing_alg_values_supported": ["RS256"]
		}`

		jwksData := `{
			"keys": [
				{
					"kty": "RSA",
					"use": "sig",
					"kid": "test-key",
					"n": "example-n",
					"e": "AQAB"
				}
			]
		}`

		var issuer string
		mux := http.NewServeMux()
		mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, strings.ReplaceAll(data, "ISSUER", issuer))
		})
		mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, jwksData)
		})

		s := httptest.NewServer(mux)
		defer s.Close()
		issuer = s.URL

		provider := newReadyProvider(t, issuer, "boring-registry", false)

		err := provider.Verify(context.Background(), "invalid.jwt.token")
		assert.Error(t, err)
		assert.True(t, errors.Is(err, core.ErrInvalidToken),
			"OIDC verification failure should wrap core.ErrInvalidToken for 401 status code mapping")
	})
}

func TestOidcProviderVerify_NonJWTRejection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError}))

	provider := &OidcProvider{
		logger:             logger,
		issuer:             "https://example.com",
		acceptNonJWTTokens: false,
	}

	err := provider.Verify(context.Background(), "not-a-jwt-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token is not in JWT format")
	// Non-JWT rejection is a format error, not an OIDC verification failure,
	// so it should NOT wrap ErrInvalidToken.
	assert.False(t, errors.Is(err, core.ErrInvalidToken))
}

func TestNewOidcProvider(t *testing.T) {
	t.Run("successful provider creation", func(t *testing.T) {
		data := `{
			"issuer": "ISSUER",
			"authorization_endpoint": "/auth",
			"token_endpoint": "/token",
			"jwks_uri": "/keys",
			"id_token_signing_alg_values_supported": ["RS256"]
		}`

		var issuer string
		hf := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, strings.ReplaceAll(data, "ISSUER", issuer))
		}
		s := httptest.NewServer(http.HandlerFunc(hf))
		defer s.Close()
		issuer = s.URL

		provider := newReadyProvider(t, issuer, "test-client-id", false)
		assert.NotNil(t, provider)
		assert.Equal(t, issuer, provider.GetIssuer())
		assert.Equal(t, "test-client-id", provider.clientIdentifier)
		assert.NotNil(t, provider.logger)
		assert.NotNil(t, provider.provider.Load())
		assert.False(t, provider.acceptNonJWTTokens)
	})

	t.Run("unreachable issuer does not fail creation", func(t *testing.T) {
		provider := NewOidcProvider(t.Context(), "http://invalid-url-12345", "test-client-id", false)
		assert.NotNil(t, provider)
		_, _, ok := provider.Endpoints()
		assert.False(t, ok)
		assert.ErrorIs(t, provider.Verify(t.Context(), "a.b.c"), core.ErrInvalidToken)
	})

	t.Run("erroring issuer does not fail creation", func(t *testing.T) {
		hf := func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		s := httptest.NewServer(http.HandlerFunc(hf))
		defer s.Close()

		provider := NewOidcProvider(t.Context(), s.URL, "test-client-id", false)
		assert.NotNil(t, provider)
		_, _, ok := provider.Endpoints()
		assert.False(t, ok)
	})

	t.Run("provider with non-JWT token support", func(t *testing.T) {
		data := `{
			"issuer": "ISSUER",
			"authorization_endpoint": "/auth",
			"token_endpoint": "/token",
			"jwks_uri": "/keys",
			"id_token_signing_alg_values_supported": ["RS256"]
		}`

		var issuer string
		hf := func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/.well-known/openid-configuration" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, strings.ReplaceAll(data, "ISSUER", issuer))
		}
		s := httptest.NewServer(http.HandlerFunc(hf))
		defer s.Close()
		issuer = s.URL

		provider := newReadyProvider(t, issuer, "test-client-id", true)
		assert.NotNil(t, provider)
		assert.True(t, provider.acceptNonJWTTokens)
	})
}

func TestOidcProviderURLs(t *testing.T) {
	data := `{
		"issuer": "ISSUER",
		"authorization_endpoint": "ISSUER/auth",
		"token_endpoint": "ISSUER/token", 
		"jwks_uri": "ISSUER/keys",
		"id_token_signing_alg_values_supported": ["RS256"]
	}`

	var issuer string
	hf := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, strings.ReplaceAll(data, "ISSUER", issuer))
	}
	s := httptest.NewServer(http.HandlerFunc(hf))
	defer s.Close()
	issuer = s.URL

	provider := newReadyProvider(t, issuer, "test-client", false)

	authURL, tokenURL, ok := provider.Endpoints()
	assert.True(t, ok)
	assert.Equal(t, fmt.Sprintf("%s/auth", issuer), authURL)
	assert.Equal(t, fmt.Sprintf("%s/token", issuer), tokenURL)
}

func TestOidcConfig(t *testing.T) {
	config := OidcConfig{
		ClientID:           "test-client-id",
		Issuer:             "https://example.com",
		Scopes:             []string{"openid", "profile"},
		LoginGrants:        []string{"authorization_code"},
		LoginPorts:         []int{10000, 10010},
		AcceptNonJWTTokens: true,
	}

	assert.Equal(t, "test-client-id", config.ClientID)
	assert.Equal(t, "https://example.com", config.Issuer)
	assert.Equal(t, []string{"openid", "profile"}, config.Scopes)
	assert.Equal(t, []string{"authorization_code"}, config.LoginGrants)
	assert.Equal(t, []int{10000, 10010}, config.LoginPorts)
	assert.True(t, config.AcceptNonJWTTokens)
}

func newReadyProvider(t *testing.T, issuer, clientID string, acceptNonJWT bool) *OidcProvider {
	t.Helper()
	provider := NewOidcProvider(t.Context(), issuer, clientID, acceptNonJWT)
	require.Eventually(t, func() bool {
		_, _, ok := provider.Endpoints()
		return ok
	}, 5*time.Second, 10*time.Millisecond)
	return provider
}

func TestOidcProviderRecoversAfterIssuerComesUp(t *testing.T) {
	oldMin, oldMax := oidcMinBackoff, oidcMaxBackoff
	oidcMinBackoff, oidcMaxBackoff = 10*time.Millisecond, 20*time.Millisecond
	t.Cleanup(func() { oidcMinBackoff, oidcMaxBackoff = oldMin, oldMax })

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwk := jose.JSONWebKey{Key: key.Public(), KeyID: "k1", Algorithm: "ES256", Use: "sig"}

	var up atomic.Bool
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if !up.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              issuer + "/keys",
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	s := httptest.NewServer(mux)
	defer s.Close()
	issuer = s.URL

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}}, nil)
	require.NoError(t, err)
	payload, err := json.Marshal(map[string]any{
		"iss": issuer,
		"sub": "argo",
		"aud": "registry",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	jws, err := signer.Sign(payload)
	require.NoError(t, err)
	token, err := jws.CompactSerialize()
	require.NoError(t, err)

	provider := NewOidcProvider(t.Context(), issuer, "registry", false)
	assert.ErrorIs(t, provider.Verify(t.Context(), token), core.ErrInvalidToken)

	time.Sleep(100 * time.Millisecond)
	assert.ErrorIs(t, provider.Verify(t.Context(), token), core.ErrInvalidToken)

	up.Store(true)
	require.Eventually(t, func() bool {
		return provider.Verify(t.Context(), token) == nil
	}, 5*time.Second, 10*time.Millisecond)
}
