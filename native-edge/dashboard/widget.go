package dashboard

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed widget.html
var widgetHTML []byte

//go:embed widget_settings.js
var widgetSettings []byte

//go:embed widget_scanner.js
var widgetScanner []byte

//go:embed widget_topology.js
var widgetTopology []byte

//go:embed widget_theme.js
var widgetTheme []byte

//go:embed widget_journal.js
var widgetJournal []byte

//go:embed widget_protect.js
var widgetProtect []byte

//go:embed widget_errors.js
var widgetErrors []byte

func (s *Server) widgetPage(w http.ResponseWriter, r *http.Request) {
	if !s.authorised(r) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	page := bytes.ReplaceAll(widgetHTML, []byte("__SETTINGS_SCRIPT__"), widgetSettings)
	page = bytes.ReplaceAll(page, []byte("__SCANNER_SCRIPT__"), widgetScanner)
	page = bytes.ReplaceAll(page, []byte("__TOPOLOGY_SCRIPT__"), widgetTopology)
	page = bytes.ReplaceAll(page, []byte("__THEME_SCRIPT__"), widgetTheme)
	page = bytes.ReplaceAll(page, []byte("__JOURNAL_SCRIPT__"), widgetJournal)
	page = bytes.ReplaceAll(page, []byte("__PROTECT_SCRIPT__"), widgetProtect)
	page = bytes.ReplaceAll(page, []byte("__ERRORS_SCRIPT__"), widgetErrors)
	w.Write(bytes.ReplaceAll(page, []byte("__TOKEN__"), []byte(s.token)))
}

var svgVariable = regexp.MustCompile(`\$\(([^)]+)\)`)

func (s *Server) widgetAsset(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if !fs.ValidPath(name) || !(strings.HasPrefix(name, "Fonts/") || strings.HasPrefix(name, "MainTopPanel/") || strings.HasPrefix(name, "TrafficPage/")) {
		http.NotFound(w, r)
		return
	}
	ext := filepath.Ext(name)
	contentType := map[string]string{".svg": "image/svg+xml", ".ttf": "font/ttf", ".otf": "font/otf"}[ext]
	if contentType == "" {
		http.NotFound(w, r)
		return
	}
	data, err := fs.ReadFile(os.DirFS(s.o.AssetsPath), name)
	if err != nil || len(data) > 2<<20 {
		http.NotFound(w, r)
		return
	}
	if ext == ".svg" {
		var theme struct {
			Colors map[string]string `json:"colors"`
		}
		raw, err := os.ReadFile(filepath.Join(s.o.AssetsPath, "Skins", "light.json"))
		if err != nil || json.Unmarshal(raw, &theme) != nil {
			http.Error(w, "theme unavailable", 503)
			return
		}
		state := r.URL.Query().Get("state")
		if state != "c" {
			state = "n"
		}
		data = svgVariable.ReplaceAllFunc(data, func(variable []byte) []byte {
			key := string(variable[2 : len(variable)-1])
			opacity := strings.HasSuffix(key, "#opacity")
			key = strings.TrimSuffix(key, "#opacity")
			color, ok := theme.Colors[key+"."+state]
			if !ok {
				color = theme.Colors[key]
			}
			if color == "" {
				if opacity {
					return []byte("0")
				}
				return []byte("#808080")
			}
			if strings.HasPrefix(color, "rgba ") {
				parts := strings.SplitN(color[5:], ",", 2)
				if opacity && len(parts) == 2 {
					return []byte(strings.TrimSpace(parts[1]))
				}
				return []byte("rgb(" + strings.ReplaceAll(strings.TrimSpace(parts[0]), " ", ",") + ")")
			}
			if opacity {
				return []byte("1")
			}
			return []byte(color)
		})
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	w.Write(data)
}
