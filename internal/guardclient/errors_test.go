package guardclient

import (
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestParseRequestErrorPreservesGuardUpstreamMetadata(t *testing.T) {
	err := parseRequestError(http.StatusTooManyRequests, "19", []byte(
		`{"error":"license service rejected request: too many requests","code":"rate_limited","upstream_status":429,"retry_after":7}`,
	), time.Now())

	var requestErr *RequestError
	if !errors.As(err, &requestErr) {
		t.Fatalf("error type = %T, want *RequestError", err)
	}
	if requestErr.Code != "rate_limited" || requestErr.StatusCode != http.StatusTooManyRequests ||
		requestErr.UpstreamStatus != http.StatusTooManyRequests || requestErr.RetryAfter != 19*time.Second {
		t.Fatalf("unexpected request metadata: %#v", requestErr)
	}
	code, status, retryAfter := ErrorMetadata(err)
	if code != "rate_limited" || status != http.StatusTooManyRequests || retryAfter != 19*time.Second {
		t.Fatalf("ErrorMetadata = (%q, %d, %v)", code, status, retryAfter)
	}
}

func TestParseRequestErrorRemainsCompatibleWithLegacyGuard(t *testing.T) {
	err := parseRequestError(http.StatusBadGateway, "", []byte(`{"error":"license service rejected request: stale slot"}`), time.Now())
	if got := err.Error(); got != "license service rejected request: stale slot" {
		t.Fatalf("Error() = %q", got)
	}
	code, status, retryAfter := ErrorMetadata(err)
	if code != "" || status != http.StatusBadGateway || retryAfter != 0 {
		t.Fatalf("legacy metadata = (%q, %d, %v)", code, status, retryAfter)
	}
}
