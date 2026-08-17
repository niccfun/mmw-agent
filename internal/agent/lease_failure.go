package agent

import (
	"time"

	"mmw-agent/internal/guardclient"
)

// agentLeaseFailure is reported to the master only for the exact reservation
// request that failed Guard activation. Older masters ignore this additive
// object and retain their bounded missing-ACK behavior.
type agentLeaseFailure struct {
	RequestID      string `json:"request_id"`
	Error          string `json:"error"`
	Code           string `json:"code,omitempty"`
	UpstreamStatus int    `json:"upstream_status,omitempty"`
	RetryAfter     int64  `json:"retry_after,omitempty"`
}

func newAgentLeaseFailure(requestID string, err error) agentLeaseFailure {
	code, status, delay := guardclient.ErrorMetadata(err)
	retryAfter := int64(0)
	if delay > 0 {
		retryAfter = int64((delay + time.Second - 1) / time.Second)
	}
	return agentLeaseFailure{
		RequestID: requestID, Error: err.Error(), Code: code,
		UpstreamStatus: status, RetryAfter: retryAfter,
	}
}

func addAgentLeaseFailureMetadata(payload map[string]any, failure agentLeaseFailure) {
	if failure.Code != "" {
		payload["code"] = failure.Code
	}
	if failure.UpstreamStatus != 0 {
		payload["upstream_status"] = failure.UpstreamStatus
	}
	if failure.RetryAfter > 0 {
		payload["retry_after"] = failure.RetryAfter
	}
}
