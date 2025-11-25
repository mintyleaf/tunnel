package api

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"strings"
)

type AuthService struct {
	DB *sql.DB

	MasterToken         string
	MasterLocalhostOnly bool
	TokenAuthDisabled   bool
}

const masterAuthKey = "master_auth_success"

func (s AuthService) TokenAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if val := r.Context().Value(masterAuthKey); val != nil {
			if masterSuccess, ok := val.(bool); ok && masterSuccess {
				next.ServeHTTP(w, r)
				return
			}
		}

		if s.TokenAuthDisabled {
			http.Error(w, "unathorized", http.StatusUnauthorized)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "unathorized", http.StatusUnauthorized)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		token = strings.TrimSpace(token)

		if token == "" {
			http.Error(w, "unathorized", http.StatusUnauthorized)
			return
		}

		err := s.ValidateAndBurnToken(token)

		if err == nil {
			next.ServeHTTP(w, r)
			return
		} else {
			switch {
			case errors.Is(err, ErrTokenNotFound):
				http.Error(w, "unathorized", http.StatusUnauthorized)
			case errors.Is(err, ErrTokenExpired):
				http.Error(w, "token expired", http.StatusUnauthorized)
			default:
				http.Error(w, "unathorized", http.StatusUnauthorized)
			}
		}
	})
}

func (s AuthService) MasterAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// disabled
		if s.MasterToken == "" {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			next.ServeHTTP(w, r)
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		token = strings.TrimSpace(token)

		if token == s.MasterToken {
			if s.MasterLocalhostOnly {
				ip, _, err := net.SplitHostPort(r.RemoteAddr)
				if err != nil {
					next.ServeHTTP(w, r)
					return
				}

				if ip != "127.0.0.1" && ip != "::1" {
					http.Error(w, "unauthorized", http.StatusForbidden)
					return
				}
			}

			ctx := context.WithValue(r.Context(), masterAuthKey, true)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s AuthService) RequireAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if val := r.Context().Value(masterAuthKey); val != nil {
			if masterSuccess, ok := val.(bool); ok && masterSuccess {
				next.ServeHTTP(w, r)
				return
			}
		}

		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}
