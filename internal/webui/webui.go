// Package webui embeds the built React dashboard and serves it as a
// single-page app. The frontend source lives in the repo's web/ directory and
// builds into dist/, which is embedded at compile time.
package webui

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var distFS embed.FS

// Handler returns an http.Handler that serves the embedded SPA. Requests for
// paths that don't map to an embedded asset fall back to index.html so the
// client-side router can handle them.
func Handler() (http.Handler, error) {
	sub, err := fs.Sub(distFS, "dist")
	if err != nil {
		return nil, err
	}
	fileServer := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !assetExists(sub, r.URL.Path) {
			r = r.Clone(r.Context())
			r.URL.Path = "/"
		}
		fileServer.ServeHTTP(w, r)
	}), nil
}

// assetExists reports whether urlPath maps to a real embedded file.
func assetExists(fsys fs.FS, urlPath string) bool {
	name := urlPath
	if name != "" && name[0] == '/' {
		name = name[1:]
	}
	if name == "" {
		name = "index.html"
	}
	f, err := fsys.Open(name)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}
