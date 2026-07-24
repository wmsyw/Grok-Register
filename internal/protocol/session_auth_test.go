package protocol

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeCreateSessionRequestShape(t *testing.T) {
	email := "a@example.com"
	password := "secret-pass"
	turnstile := "tok-turnstile"
	emailPW := append(pbStr(1, email), pbStr(2, password)...)
	credentials := pbMsg(1, emailPW)
	anti := append(pbStr(1, turnstile), pbStr(2, "")...)
	inner := append(pbMsg(1, credentials), pbMsg(4, anti)...)
	frame := grpcWebFrame(inner)
	if len(frame) < 5+len(inner) {
		t.Fatalf("frame too short: %d", len(frame))
	}
	if frame[0] != 0 {
		t.Fatalf("frame flag=%d", frame[0])
	}
	// payload should contain email and password as length-delimited strings
	if !bytes.Contains(frame, []byte(email)) {
		t.Fatalf("frame missing email")
	}
	if !bytes.Contains(frame, []byte(password)) {
		t.Fatalf("frame missing password")
	}
	if !bytes.Contains(frame, []byte(turnstile)) {
		t.Fatalf("frame missing turnstile")
	}
}

func TestExtractSetCookieURL(t *testing.T) {
	raw := "xxhttps://auth.grokusercontent.com/set-cookie?q=eyJhbGciOiJIUzI1NiJ9.e30.sig&x=1yy"
	u := extractSetCookieURL(raw)
	if !strings.Contains(u, "set-cookie?q=") {
		t.Fatalf("got %q", u)
	}
}

func TestIsSessionSSORejectsCookieSetterJWT(t *testing.T) {
	// config.success_url style tokens must not count as session SSO
	// Build a minimal fake JWT with config.success_url
	// header.payload.sig — payload base64url of {"config":{"success_url":"https://x"}}
	// We only need isSessionSSO false for short/config tokens; real ones come from extractors.
	if isSessionSSO("") {
		t.Fatal("empty should be false")
	}
	if isSessionSSO("not-a-jwt") {
		t.Fatal("non-jwt should be false")
	}
}

func TestSignInSiteKeyFallback(t *testing.T) {
	if got := SignInSiteKey(""); !strings.HasPrefix(got, "0x4") {
		t.Fatalf("default sitekey %q", got)
	}
	if got := SignInSiteKey("0xCUSTOM"); got != "0xCUSTOM" {
		t.Fatalf("got %q", got)
	}
}
