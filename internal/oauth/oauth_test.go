package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildApprovalFormAlwaysAllowsLocalizedConsent(t *testing.T) {
	tests := []struct {
		name string
		html string
	}{
		{
			name: "English buttons with empty action",
			html: `<form><input name="user_code" value="PAGE-CODE"><input name="action" value=""><input name="csrf" value="token"><button>Continue</button><button>Allow</button></form>`,
		},
		{
			name: "Chinese buttons with deny action",
			html: `<form><input name="user_code" value="PAGE-CODE"><input name="action" value="deny"><input name="csrf" value="token"><button>继续</button><button>允许</button></form>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := parseHTMLFormFields(tt.html)
			form := buildApprovalForm("not-a-jwt", "DEVICE-CODE", fields, tt.html)
			if got := form.Get("action"); got != "allow" {
				t.Fatalf("action=%q want allow", got)
			}
			if got := form.Get("user_code"); got != "DEVICE-CODE" {
				t.Fatalf("user_code=%q want device session code", got)
			}
			if got := form.Get("csrf"); got != "token" {
				t.Fatalf("csrf=%q want token", got)
			}
		})
	}
}

func TestPollTokenClassifiesEligibilityRefusal(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"Access denied"}`))
	}))
	defer server.Close()

	client := &Client{http: server.Client(), ua: "test"}
	_, err := client.PollToken(context.Background(), DeviceFlow{
		DeviceCode:    "device-code",
		ExpiresIn:     30,
		Interval:      1,
		TokenEndpoint: server.URL,
	})
	if !errors.Is(err, errOAuthEligibilityRefused) {
		t.Fatalf("err=%v want eligibility refusal", err)
	}
}
