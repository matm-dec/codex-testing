package auth

import (
	"net/http"
)

// Simple session check. In real implementation, this would validate Google OAuth.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// allow callback endpoint without session
		if r.URL.Path == "/callback" || r.URL.Path == "/login" {
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie("session")
		if err != nil || cookie.Value != "ok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
