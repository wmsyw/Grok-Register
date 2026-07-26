package oauth

import "testing"

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

func TestPrincipalFromConsentHTMLReadsEscapedRSC(t *testing.T) {
	const want = "d8a5f3c1-760c-4f42-9978-32f7a8e61234"
	html := `<script>self.__next_f.push([1,"{\"user\":{\"userId\":\"` + want + `\",\"email\":\"redacted@example.com\"}}"])</script>`
	if got := principalFromConsentHTML(html); got != want {
		t.Fatalf("principal=%q want %q", got, want)
	}
}
