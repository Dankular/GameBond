package dnssync

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"gamebond.local/nativeedge/dnssync/fakecloudflare"
)

func newAccount(t *testing.T) (*fakecloudflare.Account, *Client) {
	a := fakecloudflare.New()
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	return a, &Client{API: srv.URL, Auth: Auth{Token: "good-token"}}
}

func TestVerifyToken(t *testing.T) {
	a, c := newAccount(t)
	if err := c.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	a.TokenStatus = "disabled"
	if err := c.Verify(context.Background()); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("an inactive token: %v", err)
	}
	bad := &Client{API: c.API, Auth: Auth{Token: "wrong-secret-token"}}
	err := bad.Verify(context.Background())
	if err == nil || !strings.Contains(err.Error(), "401") || strings.Contains(err.Error(), "wrong-secret-token") {
		t.Fatalf("a bad token must be refused without being echoed: %v", err)
	}
}

func TestVerifyGlobalKey(t *testing.T) {
	_, c := newAccount(t)
	k := &Client{API: c.API, Auth: Auth{Email: "me@example.com", Key: "good-key"}}
	if err := k.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	k.Auth.Email = "someone-else@example.com"
	if err := k.Verify(context.Background()); err == nil || !strings.Contains(err.Error(), "different account") {
		t.Fatalf("%v", err)
	}
	k.Auth.Key = "nope"
	if err := k.Verify(context.Background()); err == nil {
		t.Fatal("a wrong key must be refused")
	}
}

func TestZonesAreListedAcrossPages(t *testing.T) {
	a, c := newAccount(t)
	zs, err := c.Zones(context.Background())
	if err != nil || len(zs) != 2 || zs[0].Name != "example.com" {
		t.Fatalf("%v %v", zs, err)
	}
	a.Zones = nil
	for i := 0; i < 120; i++ {
		a.Zones = append(a.Zones, fakecloudflare.Zone{ID: fmt.Sprintf("z%d", i), Name: fmt.Sprintf("d%d.example", i)})
	}
	if zs, err = c.Zones(context.Background()); err != nil || len(zs) != 120 {
		t.Fatalf("pagination: %d %v", len(zs), err)
	}
}

func TestCreateNeverOverwritesAnExistingName(t *testing.T) {
	a, c := newAccount(t)
	ctx := context.Background()
	if err := c.Create(ctx, "bond-ab12.example.com", "203.0.113.5", 60); err != nil {
		t.Fatal(err)
	}
	var made *fakecloudflare.Record
	for i := range a.Records["z1"] {
		if a.Records["z1"][i].Name == "bond-ab12.example.com" {
			made = &a.Records["z1"][i]
		}
	}
	if made == nil || made.Type != "A" || made.Content != "203.0.113.5" || made.TTL != 60 || made.Proxied {
		t.Fatalf("record: %+v", made)
	}
	for _, name := range []string{"www.example.com", "blog.example.com", "bond-ab12.example.com"} {
		if err := c.Create(ctx, name, "1.2.3.4", 60); !errors.Is(err, ErrExists) {
			t.Errorf("%s must be refused: %v", name, err)
		}
	}
	if a.Records["z1"][0].Content != "9.9.9.9" {
		t.Fatal("an existing record was modified")
	}
	if err := c.Create(ctx, "bond.not-my-zone.org", "1.2.3.4", 60); err == nil || !strings.Contains(err.Error(), "no Cloudflare zone") {
		t.Fatalf("a name outside the account's zones: %v", err)
	}
}

func TestDeleteRemovesOnlyTheNamedARecords(t *testing.T) {
	a, c := newAccount(t)
	ctx := context.Background()
	c.Create(ctx, "bond-ab12.example.com", "203.0.113.5", 60)
	if err := c.Delete(ctx, "bond-ab12.example.com"); err != nil {
		t.Fatal(err)
	}
	if len(a.Records["z1"]) != 2 {
		t.Fatalf("only the minted record should go: %+v", a.Records["z1"])
	}
	if err := c.Delete(ctx, "bond-ab12.example.com"); err != nil {
		t.Fatalf("deleting a name that is already gone is not an error: %v", err)
	}
}
