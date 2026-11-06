package auth

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed admin/*
var adminAssets embed.FS

func adminPage() http.Handler {
	root, err := fs.Sub(adminAssets, "admin")
	if err != nil {
		panic(err)
	}
	files := http.StripPrefix("/admin/", http.FileServerFS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src blob:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		switch r.URL.Path {
		case "/admin/", "/admin/style.css", "/admin/app.mjs", "/admin/api.mjs":
			if r.URL.Path == "/admin/app.mjs" || r.URL.Path == "/admin/api.mjs" {
				w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
			}
			files.ServeHTTP(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}
