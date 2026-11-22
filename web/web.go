// Package web embeds the built React + ghostty-web browser UI (web/dist).
package web

import (
	"embed"
	"io/fs"
	"mime"
	"net/http"
)

//go:embed dist
var distFS embed.FS

func init() {
	_ = mime.AddExtensionType(".wasm", "application/wasm")
}

// ContentSecurityPolicy allows local scripts/styles and Ghostty's embedded
// WebAssembly module (loaded via data: URL + WebAssembly.compile) with no
// third-party CDN origins.
const ContentSecurityPolicy = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self' data:; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// Handler serves the embedded UI bundle.
func Handler() http.Handler {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic(err)
	}
	files := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", ContentSecurityPolicy)
		files.ServeHTTP(w, r)
	})
}
