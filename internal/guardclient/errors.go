package guardclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// RequestError is an authenticated error returned by the local Guard. For
// license-backed operations it retains the upstream service metadata so the
// Agent and master can distinguish backoff from an operator-required change.
type RequestError struct {
	Message        string
	Code           string
	StatusCode     int
	UpstreamStatus int
	RetryAfter     time.Duration
}

func (e *RequestError) Error() string {
	if e == nil || e.Message == "" {
		return "Action Guard request failed"
	}
	return e.Message
}

func ErrorMetadata(err error) (code string, status int, retryAfter time.Duration) {
	var requestErr *RequestError
	if !errors.As(err, &requestErr) {
		return "", 0, 0
	}
	status = requestErr.UpstreamStatus
	if status == 0 {
		status = requestErr.StatusCode
	}
	return requestErr.Code, status, requestErr.RetryAfter
}

func retryAfterSeconds(delay time.Duration) int64 {
	if delay <= 0 {
		return 0
	}
	return int64((delay + time.Second - 1) / time.Second)
}

func parseRequestError(status int, retryAfterHeader string, body []byte, now time.Time) error {
	var result struct {
		Error          string `json:"error"`
		Code           string `json:"code"`
		UpstreamStatus int    `json:"upstream_status"`
		RetryAfter     int64  `json:"retry_after"`
	}
	_ = json.Unmarshal(body, &result)
	if result.Error == "" {
		result.Error = strings.TrimSpace(string(body))
	}
	if result.Error == "" {
		result.Error = http.StatusText(status)
	}
	delay := time.Duration(result.RetryAfter) * time.Second
	if headerDelay := parseRetryAfter(retryAfterHeader, now); headerDelay > delay {
		delay = headerDelay
	}
	return &RequestError{
		Message: result.Error, Code: result.Code, StatusCode: status,
		UpstreamStatus: result.UpstreamStatus, RetryAfter: delay,
	}
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil && when.After(now) {
		return when.Sub(now)
	}
	return 0
}
