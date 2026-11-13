package dashboard

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A syntax error in the embedded widget script freezes the whole GUI on load, so every
// build checks the assembled page script with node when node is available.
func TestWidgetScriptParses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	page := widgetHTML
	for marker, js := range map[string][]byte{"__SETTINGS_SCRIPT__": widgetSettings, "__SCANNER_SCRIPT__": widgetScanner, "__TOPOLOGY_SCRIPT__": widgetTopology, "__THEME_SCRIPT__": widgetTheme, "__JOURNAL_SCRIPT__": widgetJournal, "__PROTECT_SCRIPT__": widgetProtect, "__ERRORS_SCRIPT__": widgetErrors, "__ADOPT_SCRIPT__": widgetAdopt, "__INTERNET_SCRIPT__": widgetInternet, "__CLOUDFLARE_SCRIPT__": widgetCloudflare, "__SECURITY_SCRIPT__": widgetSecurity} {
		page = bytes.ReplaceAll(page, []byte(marker), js)
	}
	start := bytes.Index(page, []byte("<script>"))
	end := bytes.LastIndex(page, []byte("</script>"))
	if start < 0 || end < start {
		t.Fatal("no script block in widget.html")
	}
	file := filepath.Join(t.TempDir(), "widget.js")
	if err := os.WriteFile(file, page[start+len("<script>"):end], 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, "--check", file).CombinedOutput(); err != nil {
		t.Fatalf("widget script does not parse:\n%s", out)
	}
}
