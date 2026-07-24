package cpa

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/grok-free-register/grok-reg/internal/oauth"
)

func TestWriteSUBAndGrok2APIAuth(t *testing.T) {
	dir := t.TempDir()
	doc := FromCredential(oauth.Credential{
		AccessToken:   "at-1",
		RefreshToken:  "rt-1",
		IDToken:       "id-1",
		TokenType:     "Bearer",
		ExpiresIn:     3600,
		ExpiresAt:     "2026-07-24T12:00:00Z",
		LastRefresh:   "2026-07-24T11:00:00Z",
		Subject:       "user-sub",
		TokenEndpoint: "https://auth.x.ai/oauth2/token",
		Email:         "u@example.com",
	}, "u@example.com")

	subDir := filepath.Join(dir, "SUB")
	subPath, err := WriteSUBAuth(subDir, doc)
	if err != nil {
		t.Fatalf("WriteSUBAuth: %v", err)
	}
	raw, err := os.ReadFile(subPath)
	if err != nil {
		t.Fatal(err)
	}
	var sub map[string]any
	if err := json.Unmarshal(raw, &sub); err != nil {
		t.Fatal(err)
	}
	if sub["access_token"] != "at-1" || sub["refresh_token"] != "rt-1" {
		t.Fatalf("tokens missing: %v", sub)
	}
	if sub["platform"] != "grok" {
		t.Fatalf("platform=%v", sub["platform"])
	}
	if sub["base_url"] != CliproxyBase {
		t.Fatalf("base_url=%v", sub["base_url"])
	}

	gDir := filepath.Join(dir, "grok2api")
	gPath, err := WriteGrok2APIAuth(gDir, doc, "sso-token-value")
	if err != nil {
		t.Fatalf("WriteGrok2APIAuth: %v", err)
	}
	raw, err = os.ReadFile(gPath)
	if err != nil {
		t.Fatal(err)
	}
	var g map[string]any
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if g["sso"] != "sso-token-value" {
		t.Fatalf("sso=%v", g["sso"])
	}
	if g["access_token"] != "at-1" {
		t.Fatalf("access_token=%v", g["access_token"])
	}
}
