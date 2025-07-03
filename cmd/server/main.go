package main

import (
	"log"
	"net/http"

	"example.com/network-inventory/internal/api"
	"example.com/network-inventory/internal/auth"
)

func login(w http.ResponseWriter, r *http.Request) {
	// In real implementation, redirect to Google SSO
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func callback(w http.ResponseWriter, r *http.Request) {
	// Placeholder for OAuth callback
	http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", login)
	mux.HandleFunc("/callback", callback)
	mux.Handle("/api/v1/live-macs", auth.Middleware(http.HandlerFunc(api.LiveMacs)))
	mux.Handle("/api/v1/audit-report", auth.Middleware(http.HandlerFunc(api.AuditReport)))
	fs := http.FileServer(http.Dir("static"))
	mux.Handle("/static/", auth.Middleware(http.StripPrefix("/static/", fs)))
	mux.Handle("/", auth.Middleware(http.FileServer(http.Dir("static"))))

	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", mux))
}
