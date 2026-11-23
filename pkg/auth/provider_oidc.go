package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/boring-registry/boring-registry/pkg/audit"
	"github.com/boring-registry/boring-registry/pkg/core"
	"github.com/coreos/go-oidc/v3/oidc"
)

type OidcProvider struct {
	logger             *slog.Logger
	issuer             string
	clientIdentifier   string
	acceptNonJWTTokens bool
	provider           atomic.Pointer[oidc.Provider]
}

var (
	oidcDiscoveryTimeout = 15 * time.Second
	oidcVerifyTimeout    = 10 * time.Second
	oidcHTTPTimeout      = 10 * time.Second
	oidcMinBackoff       = time.Second
	oidcMaxBackoff       = 30 * time.Second
)

type OidcConfig struct {
	ClientID           string
	Issuer             string
	Scopes             []string
	LoginGrants        []string
	LoginPorts         []int
	AcceptNonJWTTokens bool
}

func (o *OidcProvider) GetIssuer() string {
	return o.issuer
}

func (o *OidcProvider) String() string { return "oidc" }

func (o *OidcProvider) validateNonJWTToken(token string) error {
	if token == "" {
		return fmt.Errorf("empty token")
	}

	if len(token) < 10 {
		return fmt.Errorf("token too short")
	}

	o.logger.Debug("accepting non-JWT token", slog.String("issuer", o.issuer))
	return nil
}

func (o *OidcProvider) Verify(ctx context.Context, token string) error {
	parts := strings.Split(token, ".")
	isJWT := len(parts) == 3

	if !isJWT && o.acceptNonJWTTokens {
		return o.validateNonJWTToken(token)
	}

	if !isJWT {
		return fmt.Errorf("token is not in JWT format and provider does not accept non-JWT tokens")
	}

	oidcConfig := &oidc.Config{
		ClientID: o.clientIdentifier,
	}
	provider := o.provider.Load()
	if provider == nil {
		return fmt.Errorf("%w: discovery for issuer %s has not completed", core.ErrInvalidToken, o.issuer)
	}
	verifier := provider.Verifier(oidcConfig)

	verifyCtx, cancel := context.WithTimeout(ctx, oidcVerifyTimeout)
	defer cancel()
	idToken, err := verifier.Verify(verifyCtx, token)
	if err != nil {
		return fmt.Errorf("%w: %w", core.ErrInvalidToken, err)
	}

	userCtx, err := o.extractUserContext(idToken)
	if err != nil {
		o.logger.Debug("failed to extract user context", slog.String("err", err.Error()))

	} else {

		o.logger.Debug("extracted user context for audit",
			slog.String("email", userCtx.UserEmail),
			slog.String("subject", userCtx.Subject))
	}

	return nil
}

// extractUserContext extracts user information from OIDC token claims
func (o *OidcProvider) extractUserContext(idToken *oidc.IDToken) (*audit.UserContext, error) {
	var claims struct {
		Email      string   `json:"email"`
		Name       string   `json:"name"`
		GivenName  string   `json:"given_name"`
		FamilyName string   `json:"family_name"`
		Subject    string   `json:"sub"`
		ClientID   audience `json:"aud"`
		Username   string   `json:"preferred_username"`
	}

	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to extract claims: %w", err)
	}

	return buildUserContext(
		claims.Email,
		claims.Name,
		claims.GivenName,
		claims.FamilyName,
		claims.Subject,
		o.issuer,
		string(claims.ClientID),
		claims.Username,
	), nil
}

// Endpoints returns the authorization and token URLs once discovery has succeeded.
func (o *OidcProvider) Endpoints() (authURL, tokenURL string, ok bool) {
	provider := o.provider.Load()
	if provider == nil {
		return "", "", false
	}
	endpoint := provider.Endpoint()
	return endpoint.AuthURL, endpoint.TokenURL, true
}

// NewOidcProvider never blocks or fails; discovery retries in the background until ctx ends.
func NewOidcProvider(ctx context.Context, issuer, clientIdentifier string, acceptNonJWTTokens bool) *OidcProvider {
	o := &OidcProvider{
		logger:             slog.Default(),
		issuer:             issuer,
		clientIdentifier:   clientIdentifier,
		acceptNonJWTTokens: acceptNonJWTTokens,
	}
	go o.discoverUntilReady(ctx)
	return o
}

func (o *OidcProvider) discoverUntilReady(ctx context.Context) {
	backoff := oidcMinBackoff
	for {
		start := time.Now()
		// The client also bounds later key refreshes, which go-oidc runs without a deadline
		httpCtx := oidc.ClientContext(ctx, &http.Client{Timeout: oidcHTTPTimeout})
		discoveryCtx, cancel := context.WithTimeout(httpCtx, oidcDiscoveryTimeout)
		provider, err := oidc.NewProvider(discoveryCtx, o.issuer)
		cancel()
		if err == nil {
			o.provider.Store(provider)
			o.logger.Info("finished initializing OIDC provider",
				slog.String("issuer", o.issuer), slog.String("took", time.Since(start).String()))
			return
		}

		o.logger.Warn("OIDC discovery failed, retrying",
			slog.String("issuer", o.issuer), slog.String("err", err.Error()), slog.String("retry_in", backoff.String()))
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, oidcMaxBackoff)
	}
}
