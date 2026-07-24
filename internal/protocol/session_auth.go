package protocol

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	http "github.com/bogdanfinn/fhttp"
)

const (
	ConnectCreateSession      = SiteURL + "/auth_mgmt.AuthManagement/CreateSession"
	ConnectCreateCookieSetter = SiteURL + "/auth_mgmt.AuthManagement/CreateCookieSetterLink"
	SignInURL                 = SiteURL + "/sign-in"
)

// CreateSession performs password login via gRPC-web and returns a session SSO JWT.
// turnstileToken is required by current anti-abuse; castleToken may be empty.
func (c *Client) CreateSession(email, password, turnstileToken string) (string, error) {
	return c.CreateSessionCastle(email, password, turnstileToken, "")
}

// CreateSessionCastle is CreateSession with optional Castle device token.
func (c *Client) CreateSessionCastle(email, password, turnstileToken, castleToken string) (string, error) {
	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)
	turnstileToken = strings.TrimSpace(turnstileToken)
	if email == "" || password == "" {
		return "", Failf(CodeGRPCPassword, "create session: empty email/password")
	}
	if turnstileToken == "" {
		return "", Failf(CodeTurnstile, "create session: empty turnstile token")
	}
	c.applyClearanceCookies()

	// Credentials.emailAndPassword { email=1, clearTextPassword=2 } nested as field 1 of Credentials,
	// then Credentials as field 1 of CreateSessionRequest. AntiAbuseToken is field 4.
	emailPW := append(pbStr(1, email), pbStr(2, password)...)
	credentials := pbMsg(1, emailPW)
	anti := append(pbStr(1, turnstileToken), pbStr(2, castleToken)...)
	inner := append(pbMsg(1, credentials), pbMsg(4, anti)...)
	frame := grpcWebFrame(inner)

	req, err := NewRequest(http.MethodPost, ConnectCreateSession, bytes.NewReader(frame))
	if err != nil {
		return "", err
	}
	c.setGRPCHeaders(req)
	req.Header.Set("Referer", SignInURL)

	resp, err := c.sess.Do(req)
	if err != nil {
		return "", Wrap(CodeGRPCPassword, "create session", err)
	}
	body, _ := readAllBody(resp)
	st := readGRPCStatus(resp, body)
	if st == "" {
		st = "0"
	}
	if resp.StatusCode != 200 || (st != "0" && st != "") {
		return "", Failf(CodeGRPCPassword, "create session http=%d grpc=%s", resp.StatusCode, st)
	}

	// Prefer Set-Cookie sso; fall back to JWT in protobuf body.
	if sso := sessionSSOFromCookies(resp.Cookies()); isSessionSSO(sso) {
		c.plantSSOCookie(sso)
		return sso, nil
	}
	if sso := extractSessionJWTFromGRPC(body); isSessionSSO(sso) {
		c.plantSSOCookie(sso)
		return sso, nil
	}
	if sso := c.jarSSO(); isSessionSSO(sso) {
		return sso, nil
	}
	return "", Failf(CodeSignupNoSSO, "create session ok but no session jwt")
}

// CreateCookieSetterLink mints a multi-domain set-cookie hop URL for the given success URL.
func (c *Client) CreateCookieSetterLink(successURL, errorURL string) (string, error) {
	successURL = strings.TrimSpace(successURL)
	if successURL == "" {
		return "", Failf(CodeOAuth, "cookie setter: empty success_url")
	}
	if strings.TrimSpace(errorURL) == "" {
		errorURL = SignInURL
	}
	c.applyClearanceCookies()

	inner := append(pbStr(1, successURL), pbStr(2, errorURL)...)
	frame := grpcWebFrame(inner)
	req, err := NewRequest(http.MethodPost, ConnectCreateCookieSetter, bytes.NewReader(frame))
	if err != nil {
		return "", err
	}
	c.setGRPCHeaders(req)
	req.Header.Set("Referer", SignInURL+"?redirect=oauth2-provider")

	resp, err := c.sess.Do(req)
	if err != nil {
		return "", Wrap(CodeOAuth, "cookie setter", err)
	}
	body, _ := readAllBody(resp)
	st := readGRPCStatus(resp, body)
	if st == "" {
		st = "0"
	}
	if resp.StatusCode != 200 || (st != "0" && st != "") {
		return "", Failf(CodeOAuth, "cookie setter http=%d grpc=%s", resp.StatusCode, st)
	}
	if u := firstHTTPURL(body); u != "" {
		return u, nil
	}
	// Sometimes returned only as text URL without proto framing we parse.
	if m := jwtRe.FindString(string(body)); m != "" {
		// rebuild is not possible; require explicit URL
	}
	if u := extractSetCookieURL(string(body)); u != "" {
		return u, nil
	}
	return "", Failf(CodeOAuth, "cookie setter: no set-cookie url in response")
}

// PlantSSO propagates a session JWT across x.ai auth domains via CreateCookieSetterLink
// (successURL should be an allowlisted path such as device verification / consent).
// Returns the effective SSO after set-cookie hops (may rotate) and final Location.
func (c *Client) PlantSSO(sso, successURL string) (effectiveSSO string, finalURL string, err error) {
	sso = strings.TrimSpace(sso)
	if !isSessionSSO(sso) {
		return "", "", Failf(CodeSignupNoSSO, "plant sso: invalid session token")
	}
	c.plantSSOCookie(sso)
	effectiveSSO = sso

	setter, err := c.CreateCookieSetterLink(successURL, SignInURL)
	if err != nil {
		return effectiveSSO, "", err
	}
	// Follow set-cookie hops (limited) so auth.x.ai / accounts.x.ai receive cookies.
	current := setter
	var lastLoc string
	for range 8 {
		if current == "" {
			break
		}
		req, err := NewRequest(http.MethodGet, current, nil)
		if err != nil {
			break
		}
		c.setBrowserHeaders(req)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Referer", SignInURL)
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Upgrade-Insecure-Requests", "1")

		resp, err := c.sess.DoNoRedirect(req)
		if err != nil {
			return effectiveSSO, lastLoc, Wrap(CodeOAuth, "plant sso hop", err)
		}
		body, _ := readBody(resp)
		if v := sessionSSOFromCookies(resp.Cookies()); isSessionSSO(v) {
			c.plantSSOCookie(v)
			effectiveSSO = v
		}
		if v := ExtractSSOFromText(body); isSessionSSO(v) {
			c.plantSSOCookie(v)
			effectiveSSO = v
		}
		// set-cookie JWT config.token is the real session SSO on some hops
		if jwt := jwtFromSetCookieURL(current); jwt != "" {
			if payload := jwtPayloadMap(jwt); payload != nil {
				if cfg, ok := payload["config"].(map[string]any); ok {
					if tok, ok := cfg["token"].(string); ok && isSessionSSO(tok) {
						c.plantSSOCookie(tok)
						effectiveSSO = tok
					}
				}
			}
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			// set-cookie JWT may embed success_url
			if nxt := successURLFromSetCookieURL(current); nxt != "" {
				lastLoc = nxt
			}
			break
		}
		if strings.HasPrefix(loc, "/") {
			if strings.Contains(current, "auth.x.ai") {
				loc = "https://auth.x.ai" + loc
			} else if strings.Contains(current, "accounts.x.ai") {
				loc = SiteURL + loc
			} else {
				loc = SiteURL + loc
			}
		}
		lastLoc = loc
		if !strings.Contains(loc, "set-cookie") {
			// landed on success / consent / device page
			_ = body
			break
		}
		current = loc
	}
	if lastLoc == "" {
		lastLoc = successURL
	}
	return effectiveSSO, lastLoc, nil
}

// EnsureSSOForOAuth prefers an existing session JWT; if empty, password-login via CreateSession.
func (c *Client) EnsureSSOForOAuth(email, password, sso, turnstileToken string) (string, error) {
	if isSessionSSO(sso) {
		c.plantSSOCookie(sso)
		return sso, nil
	}
	return c.CreateSession(email, password, turnstileToken)
}

func (c *Client) plantSSOCookie(sso string) {
	if c == nil || c.sess == nil || !isSessionSSO(sso) {
		return
	}
	ck := &http.Cookie{Name: "sso", Value: sso, Path: "/"}
	for _, host := range []string{
		SiteURL,
		"https://x.ai",
		"https://auth.x.ai",
		"https://accounts.x.ai",
		"https://grok.com",
		"https://auth.grokusercontent.com",
	} {
		c.sess.SetCookies(host, []*http.Cookie{ck})
	}
}

// pbMsg encodes a length-delimited nested protobuf message field.
func pbMsg(field int, inner []byte) []byte {
	tag := byte(field<<3 | 2)
	out := []byte{tag}
	out = append(out, pbVarint(len(inner))...)
	out = append(out, inner...)
	return out
}

func extractSessionJWTFromGRPC(body []byte) string {
	// grpc-web frames: scan for eyJ... JWT strings
	s := string(body)
	for _, m := range jwtRe.FindAllString(s, -1) {
		if isSessionSSO(m) {
			return m
		}
	}
	return ""
}

func firstHTTPURL(body []byte) string {
	s := string(body)
	// Prefer set-cookie URLs
	if u := extractSetCookieURL(s); u != "" {
		return u
	}
	// Generic https URL extraction from protobuf text
	const prefix = "https://"
	i := strings.Index(s, prefix)
	for i >= 0 {
		rest := s[i:]
		end := len(rest)
		for j := 0; j < len(rest); j++ {
			ch := rest[j]
			if ch < 0x20 || ch == '"' || ch == '\'' || ch == ' ' || ch == '<' || ch == '>' || ch == ')' {
				end = j
				break
			}
		}
		u := rest[:end]
		if strings.HasPrefix(u, "https://") {
			if _, err := url.Parse(u); err == nil {
				return u
			}
		}
		next := strings.Index(s[i+1:], prefix)
		if next < 0 {
			break
		}
		i = i + 1 + next
	}
	return ""
}

func extractSetCookieURL(s string) string {
	// common: https://auth.*.x.ai/set-cookie?q=...
	markers := []string{"/set-cookie?q=", "/set-cookie?token=", "set-cookie?q="}
	for _, m := range markers {
		i := strings.Index(s, m)
		if i < 0 {
			continue
		}
		// walk back to https://
		start := strings.LastIndex(s[:i], "https://")
		if start < 0 {
			start = strings.LastIndex(s[:i], "http://")
		}
		if start < 0 {
			continue
		}
		rest := s[start:]
		end := len(rest)
		for j := 0; j < len(rest); j++ {
			ch := rest[j]
			if ch < 0x20 || ch == '"' || ch == '\'' || ch == ' ' || ch == '<' || ch == '>' {
				end = j
				break
			}
		}
		return rest[:end]
	}
	return ""
}

func successURLFromSetCookieURL(raw string) string {
	// JWT in ?q= may contain config.success_url
	jwt := jwtFromSetCookieURL(raw)
	if jwt == "" {
		return ""
	}
	payload := jwtPayloadMap(jwt)
	if payload == nil {
		return ""
	}
	if cfg, ok := payload["config"].(map[string]any); ok {
		if v, ok := cfg["success_url"].(string); ok {
			return v
		}
	}
	if v, ok := payload["success_url"].(string); ok {
		return v
	}
	return ""
}

// WarmSignIn GETs sign-in page (CF probe / cookie warm).
func (c *Client) WarmSignIn() (status int, body string, err error) {
	c.applyClearanceCookies()
	req, err := NewRequest(http.MethodGet, SignInURL, nil)
	if err != nil {
		return 0, "", err
	}
	c.setBrowserHeaders(req)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Referer", "https://grok.com/")
	resp, err := c.sess.Do(req)
	if err != nil {
		return 0, "", Wrap(CodeWarm, "GET sign-in", err)
	}
	html, err := readBody(resp)
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, html, nil
}

// SignInSiteKey returns the Turnstile site key used for password CreateSession.
func SignInSiteKey(signupSiteKey string) string {
	if strings.TrimSpace(signupSiteKey) != "" {
		return strings.TrimSpace(signupSiteKey)
	}
	return "0x4AAAAAAAhr9JGVDZbrZOo0"
}

// Debug helper for callers that need a stable empty-error path.
func FormatSSOPreview(sso string) string {
	sso = strings.TrimSpace(sso)
	if len(sso) <= 24 {
		return sso
	}
	return fmt.Sprintf("%s…%s", sso[:12], sso[len(sso)-8:])
}
