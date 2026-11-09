package dashboard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWidgetAssetsAndAuthentication(t *testing.T) {
	s, url, _, _ := start(t)
	dir := t.TempDir()
	for _, sub := range []string{"MainTopPanel", "Skins"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "MainTopPanel", "icon.svg"), []byte(`<svg fill="$(topnav_ico)" fill-opacity="$(topnav_ico#opacity)"/>`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Skins", "light.json"), []byte(`{"colors":{"topnav_ico.n":"rgba 10 20 30, 0.75","topnav_ico.c":"#112233"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	s.o.AssetsPath = dir
	base := url[:strings.Index(url, "/?t=")]
	if c, b := do(t, "GET", base+"/widget", s.token, ""); c != 200 || strings.Contains(b, "__TOKEN__") || !strings.Contains(b, "Live adapter traffic") {
		t.Fatal(c, "widget page missing")
	}
	if c, _ := do(t, "GET", base+"/widget", "", ""); c == 200 {
		t.Fatal("widget served without token")
	}
	asset := base + "/api/widget-asset?name=MainTopPanel/icon.svg"
	if c, b := do(t, "GET", asset, s.token, ""); c != 200 || !strings.Contains(b, `fill="rgb(10,20,30)"`) || !strings.Contains(b, `fill-opacity="0.75"`) || strings.Contains(b, "$(") {
		t.Fatal(c, b)
	}
	if c, b := do(t, "GET", asset+"&state=c", s.token, ""); c != 200 || !strings.Contains(b, "#112233") {
		t.Fatal(c, b)
	}
	if c, _ := do(t, "GET", asset, "", ""); c != 403 {
		t.Fatal("asset served without token", c)
	}
	for _, name := range []string{"../secrets/key", "Skins/light.json", "Fonts/file.exe", "MainTopPanel/../../secret.svg"} {
		if c, _ := do(t, "GET", base+"/api/widget-asset?name="+name, s.token, ""); c != 404 {
			t.Fatal(name, c)
		}
	}
}
