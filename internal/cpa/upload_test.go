package cpa

import (
	"context"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"

	"strings"
	"testing"
	"time"
)

func TestNormalizeManagementBase(t *testing.T) {
	cases := map[string]string{
		"http://cli-proxy-api:8317":               "http://127.0.0.1:8317/v0/management",
		"http://cli-proxy-api:8317/":              "http://127.0.0.1:8317/v0/management",
		"http://cli-proxy-api:8317/v0/management": "http://127.0.0.1:8317/v0/management",
		"http://127.0.0.1:8317":                   "http://127.0.0.1:8317/v0/management",
		"http://127.0.0.1:8317/v0/management":     "http://127.0.0.1:8317/v0/management",
		"http://localhost:8317/v0/management":     "http://localhost:8317/v0/management",
	}
	for in, want := range cases {
		got := NormalizeManagementBase(in)
		if got != want {
			t.Fatalf("NormalizeManagementBase(%q)=%q want %q", in, got, want)
		}
	}
}

func TestUploadName(t *testing.T) {
	doc := Document{Email: "a@b.com", Sub: "sub1"}
	n := UploadName(doc, "{email}.json")
	if n != "a@b.com.json" {
		t.Fatalf("name=%s", n)
	}
	n2 := UploadName(doc, "{provider}-{email}.json")
	if n2 != "xai-a@b.com.json" {
		t.Fatalf("name=%s", n2)
	}
	n3 := UploadName(Document{Email: "x"}, "")
	if !strings.HasSuffix(n3, ".json") {
		t.Fatalf("suffix: %s", n3)
	}
}

func TestUploadMultipart(t *testing.T) {
	var gotName string
	var gotBody []byte
	var gotAuth string
	var gotXKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/management/auth-files" {
			http.NotFound(w, r)
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode([]string{gotName})
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotXKey = r.Header.Get("X-Management-Key")
		ct := r.Header.Get("Content-Type")
		media, params, err := mime.ParseMediaType(ct)
		if err != nil || !strings.HasPrefix(media, "multipart/") {
			http.Error(w, "want multipart", 400)
			return
		}
		mr := multipart.NewReader(r.Body, params["boundary"])
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if part.FormName() == "file" {
				gotName = part.FileName()
				gotBody, _ = io.ReadAll(part)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	u := NewUploader(UploadConfig{
		Enabled:      true,
		BaseURL:      srv.URL + "/v0/management",
		Key:          "test-key",
		TimeoutSec:   5,
		Retries:      0,
		NameTemplate: "{email}.json",
		Verify:       true,
		Mode:         "multipart",
	}, func(string, ...any) {})

	doc := Document{
		Type:        "xai",
		AccessToken: "at",
		Email:       "u@test.com",
		BaseURL:     CliproxyBase,
		AuthKind:    "oauth",
	}
	res := u.UploadDocument(doc)
	if !res.OK {
		t.Fatalf("upload failed status=%d body=%s err=%v", res.Status, res.Body, res.Err)
	}
	if gotName != "u@test.com.json" {
		t.Fatalf("filename=%s", gotName)
	}
	if gotAuth != "Bearer test-key" {
		t.Fatalf("auth=%s", gotAuth)
	}
	if gotXKey != "test-key" {
		t.Fatalf("xkey=%s", gotXKey)
	}
	if !strings.Contains(string(gotBody), "access_token") {
		t.Fatalf("body missing token")
	}
	if !res.Verified {
		t.Fatal("expected verified")
	}
}

func TestUploadJSONRaw(t *testing.T) {
	var gotCT string
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`[]`))
			return
		}
		gotCT = r.Header.Get("Content-Type")
		gotQuery = r.URL.RawQuery
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	u := NewUploader(UploadConfig{
		Enabled:    true,
		BaseURL:    srv.URL + "/v0/management",
		Key:        "k",
		TimeoutSec: 5,
		Mode:       "json",
		Verify:     false,
	}, nil)
	res := u.UploadBytes("acc.json", []byte(`{"type":"xai"}`))
	if !res.OK {
		t.Fatalf("fail %v %s", res.Err, res.Body)
	}
	if !strings.Contains(gotCT, "application/json") {
		t.Fatalf("ct=%s", gotCT)
	}
	if !strings.Contains(gotQuery, "name=acc.json") {
		t.Fatalf("query=%s", gotQuery)
	}
}

func TestUploadDisabled(t *testing.T) {
	u := NewUploader(UploadConfig{Enabled: false}, nil)
	res := u.UploadBytes("a.json", []byte(`{}`))
	if res.OK {
		t.Fatal("should skip")
	}
}

func TestUploadEmptyKeySkips(t *testing.T) {
	var logs []string
	u := NewUploader(UploadConfig{
		Enabled: true,
		BaseURL: "http://127.0.0.1:1",
		Key:     "",
	}, func(f string, a ...any) {
		logs = append(logs, f)
	})
	if u.Enabled() {
		t.Fatal("should be disabled without key")
	}
	if len(logs) == 0 {
		t.Fatal("expected warning log")
	}
}

func TestStartXAIAuth(t *testing.T) {
	var gotAuth, gotKey string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/management/xai-auth-url" || r.URL.Query().Get("is_webui") != "true" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotKey = r.Header.Get("X-Management-Key")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":     "ok",
			"url":        "https://auth.x.ai/oauth2/device?user_code=ABCD-EFGH",
			"state":      "xai-123",
			"flow":       "device",
			"user_code":  "ABCD-EFGH",
			"expires_in": 600,
		})
	}))
	defer srv.Close()

	u := NewUploader(UploadConfig{Enabled: true, BaseURL: srv.URL, Key: "secret", TimeoutSec: 2}, nil)
	session, err := u.StartXAIAuth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if session.State != "xai-123" || session.UserCode != "ABCD-EFGH" || session.ExpiresIn != 600 {
		t.Fatalf("unexpected session: %+v", session)
	}
	if gotAuth != "Bearer secret" || gotKey != "secret" {
		t.Fatalf("management auth headers missing: authorization=%q x-key=%q", gotAuth, gotKey)
	}
}

func TestStartXAIAuthRejectsInvalidResponse(t *testing.T) {
	tests := []struct {
		name    string
		payload map[string]any
		want    string
	}{
		{
			name: "untrusted URL",
			payload: map[string]any{
				"url": "https://example.com/device?user_code=ABC", "state": "xai-1", "flow": "device",
			},
			want: "untrusted verification host",
		},
		{
			name: "missing state",
			payload: map[string]any{
				"url": "https://auth.x.ai/device?user_code=ABC", "flow": "device",
			},
			want: "missing state",
		},
		{
			name: "missing user code",
			payload: map[string]any{
				"url": "https://auth.x.ai/device", "state": "xai-1", "flow": "device",
			},
			want: "missing user_code",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(tt.payload)
			}))
			defer srv.Close()
			u := NewUploader(UploadConfig{Enabled: true, BaseURL: srv.URL, Key: "k", TimeoutSec: 2}, nil)
			_, err := u.StartXAIAuth(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want substring %q", err, tt.want)
			}
		})
	}
}

func TestPollXAIAuthStatusPendingThenSuccess(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/management/get-auth-status" || r.URL.Query().Get("state") != "xai-123" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer k" || r.Header.Get("X-Management-Key") != "k" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		requests++
		status := "wait"
		if requests >= 2 {
			status = "ok"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": status})
	}))
	defer srv.Close()

	u := NewUploader(UploadConfig{Enabled: true, BaseURL: srv.URL, Key: "k", TimeoutSec: 2}, nil)
	if err := u.pollXAIAuthStatus(context.Background(), "xai-123", 200*time.Millisecond, time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests=%d want 2", requests)
	}
}

func TestPollXAIAuthStatusTerminalError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "error", "error": "access denied"})
	}))
	defer srv.Close()
	u := NewUploader(UploadConfig{Enabled: true, BaseURL: srv.URL, Key: "k", TimeoutSec: 2}, nil)
	err := u.pollXAIAuthStatus(context.Background(), "xai-1", time.Second, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("err=%v", err)
	}
}

func TestPollXAIAuthStatusTimeoutAndCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "wait"})
	}))
	defer srv.Close()
	u := NewUploader(UploadConfig{Enabled: true, BaseURL: srv.URL, Key: "k", TimeoutSec: 2}, nil)

	err := u.pollXAIAuthStatus(context.Background(), "xai-1", 10*time.Millisecond, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
		t.Fatalf("timeout err=%v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err = u.pollXAIAuthStatus(ctx, "xai-1", time.Second, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) {
		t.Fatalf("cancel err=%v", err)
	}
}

func TestPollXAIAuthStatusStopsAfterRepeatedHTTPError(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	u := NewUploader(UploadConfig{Enabled: true, BaseURL: srv.URL, Key: "k", TimeoutSec: 2}, nil)

	err := u.pollXAIAuthStatus(context.Background(), "xai-1", time.Second, time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "status=503") {
		t.Fatalf("err=%v", err)
	}
	if requests != xaiAuthMaxPollErrors {
		t.Fatalf("requests=%d want %d", requests, xaiAuthMaxPollErrors)
	}
}
