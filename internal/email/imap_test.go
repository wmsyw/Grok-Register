package email

import "testing"

func TestSplitPoolLine(t *testing.T) {
	e, p, ok := splitPoolLine("a@gmail.com:abcd efgh")
	if !ok || e != "a@gmail.com" || p != "abcd efgh" {
		t.Fatalf("%v %v %v", e, p, ok)
	}
	e, p, ok = splitPoolLine("b@gmail.com|secret:with:colon")
	if !ok || e != "b@gmail.com" || p != "secret:with:colon" {
		// | form only splits on first |
		t.Fatalf("%v %v %v", e, p, ok)
	}
}
