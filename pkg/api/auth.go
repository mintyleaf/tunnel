package api

import (
	"database/sql"
	"net/http"
)

type AuthService struct {
	DB *sql.DB

	MasterToken         string
	MasterLocalhostOnly bool
	TokenAuthDisabled   bool
}

// TODO: write theeese
func (s AuthService) TokenAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func (s AuthService) MasterAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
