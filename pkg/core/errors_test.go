package core

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProviderError_Error(t *testing.T) {
	type fields struct {
		Reason     string
		Provider   *Provider
		StatusCode int
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "with hostname, namespace, name",
			fields: fields{
				Reason: "this is the prefix",
				Provider: &Provider{
					Hostname:  "example.com",
					Namespace: "example",
					Name:      "test",
				},
			},
			want: "this is the prefix: hostname=example.com, namespace=example, name=test",
		},
		{
			name: "with hostname, namespace, name, os, and arch",
			fields: fields{
				Reason: "this is the prefix",
				Provider: &Provider{
					Hostname:  "example.com",
					Namespace: "example",
					Name:      "test",
					Version:   "0.1.2",
					OS:        "linux",
					Arch:      "amd64",
				},
			},
			want: "this is the prefix: hostname=example.com, namespace=example, name=test, version=0.1.2, os=linux, arch=amd64",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := ProviderError{
				Reason:     tt.fields.Reason,
				Provider:   tt.fields.Provider,
				StatusCode: tt.fields.StatusCode,
			}
			assert.Equalf(t, tt.want, p.Error(), "Error()")
		})
	}
}

func TestGenericError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "ErrVarMissing returns 400",
			err:        ErrVarMissing,
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "ErrInvalidToken returns 401",
			err:        ErrInvalidToken,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "ErrUnauthorized returns 401",
			err:        ErrUnauthorized,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrapped ErrInvalidToken returns 401",
			err:        fmt.Errorf("%w: audience mismatch", ErrInvalidToken),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "double wrapped ErrInvalidToken returns 401",
			err:        fmt.Errorf("%w: %w", ErrInvalidToken, errors.New("oidc: token expired")),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "ErrObjectAlreadyExists returns 409",
			err:        ErrObjectAlreadyExists,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "unknown error returns 500",
			err:        errors.New("unknown error"),
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantStatus, GenericError(tt.err))
		})
	}
}
