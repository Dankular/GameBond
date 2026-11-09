package linkpolicy

import (
	"encoding/json"
	"testing"
)

func TestPolicyRejectsUnknownFields(t *testing.T) {
	for _, raw := range []string{`{"turbo":true}`, `{"role":"primary","Role":"never"}`, `{"upload_Mbps":50}`, `null`, `[]`} {
		p := Default()
		if err := json.Unmarshal([]byte(raw), &p); err == nil {
			t.Fatalf("accepted %s", raw)
		}
		if p != Default() {
			t.Fatalf("rejected input changed policy: %+v", p)
		}
	}
	var p Policy
	if err := json.Unmarshal([]byte(`{"upload_mbps":20}`), &p); err != nil {
		t.Fatal(err)
	}
	if p.UploadMbps != 20 || p.Role != "primary" || p.ResetDay != 1 {
		t.Fatal(p)
	}
}
