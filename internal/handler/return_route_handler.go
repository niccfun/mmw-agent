package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const nextTraceVersion = "v1.7.1"

var nextTraceSHA256 = map[string]string{
	"386":   "ae188b8f4fb3f5fec70ddf4cf5adc4391d9536698ed29c0d4f25b3b4dd29ca34",
	"amd64": "093849f1012b065c29d307b8e47fedec667206829c14e105f83a852f60c628d1",
	"arm64": "8b134f6c6a7864b1ecc98b1f7cfae1d058ef6dcf8f0da862e3260752ce1858bd",
	"arm":   "71014f2707372cee22ab80f546aa6cff79d869faab0fb516005e8bb0e2d2f000",
}

var routeTargetPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

type returnRouteTarget struct {
	Carrier string `json:"carrier"`
	Region  string `json:"region"`
	Host    string `json:"host"`
	Port    int    `json:"port,omitempty"`
}

type returnRouteRequest struct {
	IPVersion int                 `json:"ip_version,omitempty"`
	Timeout   int                 `json:"timeout_seconds,omitempty"`
	Targets   []returnRouteTarget `json:"targets"`
}

type returnRouteHop struct {
	Hop     int     `json:"hop"`
	IP      string  `json:"ip"`
	ASN     string  `json:"asn,omitempty"`
	Country string  `json:"country,omitempty"`
	Region  string  `json:"region,omitempty"`
	Owner   string  `json:"owner,omitempty"`
	RTTMS   float64 `json:"rtt_ms,omitempty"`
}

type returnRouteResult struct {
	Carrier  string           `json:"carrier"`
	Region   string           `json:"region"`
	Target   string           `json:"target"`
	Success  bool             `json:"success"`
	Route    string           `json:"route_type,omitempty"`
	EntryHop *returnRouteHop  `json:"entry_hop,omitempty"`
	PathASNs []string         `json:"path_asns,omitempty"`
	Hops     []returnRouteHop `json:"hops,omitempty"`
	Reason   string           `json:"reason,omitempty"`
	Error    string           `json:"error,omitempty"`
	Source   string           `json:"source,omitempty"`
}

var ansiEscapePattern = regexp.MustCompile(`\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))`)
var traceIPPattern = regexp.MustCompile(`(?:^|[ (])((?:\d{1,3}\.){3}\d{1,3})(?:[ )]|$)`)
var traceASNPattern = regexp.MustCompile(`(?i)\bAS(\d{2,10})\b`)

// HandleReturnRouteTest is deliberately a normal child HTTP handler: the
// agent's RPC mux invokes it over the existing outbound WebSocket connection.
func (h *ManageHandler) HandleReturnRouteTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !h.authenticate(r) {
		writeError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}
	var req returnRouteRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if len(req.Targets) == 0 || len(req.Targets) > 3 {
		writeError(w, http.StatusBadRequest, "targets must contain 1 to 3 entries")
		return
	}
	if req.IPVersion != 6 {
		req.IPVersion = 4
	}
	if req.Timeout < 10 {
		req.Timeout = 25
	}
	if req.Timeout > 45 {
		req.Timeout = 45
	}
	for i := range req.Targets {
		t := &req.Targets[i]
		t.Carrier = strings.ToLower(strings.TrimSpace(t.Carrier))
		t.Host = strings.TrimSpace(t.Host)
		if (t.Carrier != "telecom" && t.Carrier != "unicom" && t.Carrier != "mobile") || !routeTargetPattern.MatchString(t.Host) {
			writeError(w, http.StatusBadRequest, "invalid carrier or target")
			return
		}
		if t.Port <= 0 || t.Port > 65535 {
			t.Port = 80
		}
	}

	bin, err := ensureNextTrace(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	results := make([]returnRouteResult, 0, len(req.Targets))
	for _, target := range req.Targets {
		results = append(results, traceReturnRoute(r.Context(), bin, target, req.IPVersion, time.Duration(req.Timeout)*time.Second))
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "results": results})
}

func ensureNextTrace(ctx context.Context) (string, error) {
	if p, err := exec.LookPath("nexttrace"); err == nil {
		return p, nil
	}
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("return-route test is unsupported on %s", runtime.GOOS)
	}
	sha, ok := nextTraceSHA256[runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("nexttrace is not bundled for architecture %s", runtime.GOARCH)
	}
	arch := runtime.GOARCH
	if arch == "arm" {
		arch = "armv7"
	}
	dir := filepath.Join(os.TempDir(), "mmwx-tools", nextTraceVersion)
	path := filepath.Join(dir, "nexttrace")
	if fileSHA256(path) == sha {
		return path, nil
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	url := fmt.Sprintf("https://github.com/nxtrace/NTrace-core/releases/download/%s/nexttrace-tiny_linux_%s", nextTraceVersion, arch)
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(dctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download nexttrace: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download nexttrace: HTTP %d", resp.StatusCode)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0755)
	if err != nil {
		return "", err
	}
	_, copyErr := io.Copy(f, io.LimitReader(resp.Body, 50<<20))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || fileSHA256(tmp) != sha {
		_ = os.Remove(tmp)
		return "", errors.New("nexttrace download failed checksum verification")
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return path, nil
}

func fileSHA256(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func traceReturnRoute(parent context.Context, bin string, target returnRouteTarget, ipVersion int, timeout time.Duration) returnRouteResult {
	result := returnRouteResult{Carrier: target.Carrier, Region: target.Region, Target: target.Host, Source: "nexttrace"}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	args := []string{"-4", "-T", "-p", strconv.Itoa(target.Port), "-q", "2", "--max-attempts", "2", "--timeout", "1500", "--no-rdns", "-j", target.Host}
	if ipVersion == 6 {
		args[0] = "-6"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb")
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			result.Error = "route trace timed out"
		} else {
			result.Error = err.Error()
		}
		return traceReturnRouteFallback(parent, target, ipVersion, timeout, result.Error)
	}
	var raw struct {
		Hops [][]struct {
			Success bool `json:"Success"`
			Address *struct {
				IP string `json:"IP"`
			} `json:"Address"`
			TTL int   `json:"TTL"`
			RTT int64 `json:"RTT"`
			Geo *struct {
				ASN       string `json:"asnumber"`
				Country   string `json:"country"`
				CountryEN string `json:"country_en"`
				Province  string `json:"prov"`
				Owner     string `json:"owner"`
				ISP       string `json:"isp"`
			} `json:"Geo"`
		} `json:"Hops"`
	}
	if err := unmarshalNextTraceJSON(out, &raw); err != nil {
		return traceReturnRouteFallback(parent, target, ipVersion, timeout, "invalid nexttrace response: "+err.Error())
	}
	seenASN := map[string]bool{}
	for _, probes := range raw.Hops {
		for _, p := range probes {
			if !p.Success || p.Address == nil {
				continue
			}
			hop := returnRouteHop{Hop: p.TTL, IP: p.Address.IP, RTTMS: float64(p.RTT) / float64(time.Millisecond)}
			if p.Geo != nil {
				hop.ASN, hop.Country, hop.Region = normalizeASN(p.Geo.ASN), p.Geo.Country, p.Geo.Province
				hop.Owner = strings.TrimSpace(strings.TrimSpace(p.Geo.Owner) + " " + strings.TrimSpace(p.Geo.ISP))
			}
			if strings.HasPrefix(hop.IP, "59.43.") {
				hop.ASN = "4809"
			}
			if strings.Contains(strings.ToLower(hop.Owner), "ctgnet") {
				hop.ASN = "23764"
			}
			result.Hops = append(result.Hops, hop)
			if hop.ASN != "" && !seenASN[hop.ASN] {
				seenASN[hop.ASN] = true
				result.PathASNs = append(result.PathASNs, hop.ASN)
			}
			if result.EntryHop == nil && isMainlandEntryHop(hop) {
				copyHop := hop
				result.EntryHop = &copyHop
			}
			break
		}
	}
	result.Route, result.Reason = classifyReturnRoute(result.EntryHop, result.PathASNs)
	if result.Route == "Unknown" && target.Carrier == "telecom" && result.EntryHop != nil {
		result.Route = "163"
		result.Reason += "；电信目标未识别到 CN2/CTG 骨干，按普通 163 线路兜底"
	}
	result.Success = len(result.Hops) > 0 && result.EntryHop != nil
	if !result.Success && result.Error == "" {
		result.Error = "no mainland China hop found"
	}
	if !result.Success {
		return traceReturnRouteFallback(parent, target, ipVersion, timeout, result.Error)
	}
	return result
}

func unmarshalNextTraceJSON(out []byte, dst any) error {
	clean := ansiEscapePattern.ReplaceAll(out, nil)
	start, end := strings.IndexByte(string(clean), '{'), strings.LastIndexByte(string(clean), '}')
	if start < 0 || end < start {
		return errors.New("JSON object not found")
	}
	return json.Unmarshal(clean[start:end+1], dst)
}

// traceReturnRouteFallback only runs after nexttrace failed. Prefer TCP MTR with
// ASN lookup; traceroute is the last resort on small Alpine/NAT installations.
func traceReturnRouteFallback(parent context.Context, target returnRouteTarget, ipVersion int, timeout time.Duration, primaryErr string) returnRouteResult {
	commands := []struct {
		name string
		args []string
	}{
		{"mtr", []string{"-4", "-T", "-P", strconv.Itoa(target.Port), "-r", "-c", "5", "-n", "-z", target.Host}},
		{"traceroute", []string{"-4", "-T", "-p", strconv.Itoa(target.Port), "-n", "-q", "2", "-w", "2", target.Host}},
	}
	if ipVersion == 6 {
		commands[0].args[0], commands[1].args[0] = "-6", "-6"
	}
	errorsSeen := []string{primaryErr}
	for _, candidate := range commands {
		path, err := exec.LookPath(candidate.name)
		if err != nil {
			errorsSeen = append(errorsSeen, candidate.name+" not installed")
			continue
		}
		ctx, cancel := context.WithTimeout(parent, timeout)
		cmd := exec.CommandContext(ctx, path, candidate.args...)
		cmd.Env = append(os.Environ(), "NO_COLOR=1", "TERM=dumb")
		out, runErr := cmd.CombinedOutput()
		cancel()
		if runErr != nil && len(out) == 0 {
			errorsSeen = append(errorsSeen, candidate.name+": "+runErr.Error())
			continue
		}
		result := parseRouteToolOutput(target, candidate.name, out)
		if result.Success {
			result.Reason = strings.TrimSpace(result.Reason + "；nexttrace 失败后使用 " + candidate.name + " 兜底")
			return result
		}
		errorsSeen = append(errorsSeen, candidate.name+": no mainland China hop found")
	}
	return returnRouteResult{Carrier: target.Carrier, Region: target.Region, Target: target.Host, Source: "nexttrace", Error: strings.Join(errorsSeen, "; ")}
}

func parseRouteToolOutput(target returnRouteTarget, source string, out []byte) returnRouteResult {
	result := returnRouteResult{Carrier: target.Carrier, Region: target.Region, Target: target.Host, Source: source}
	seenASN := map[string]bool{}
	for index, line := range strings.Split(string(ansiEscapePattern.ReplaceAll(out, nil)), "\n") {
		ipMatch := traceIPPattern.FindStringSubmatch(line)
		if len(ipMatch) < 2 {
			continue
		}
		hop := returnRouteHop{Hop: index + 1, IP: ipMatch[1]}
		if asn := traceASNPattern.FindStringSubmatch(line); len(asn) == 2 {
			hop.ASN = normalizeASN(asn[1])
		}
		if strings.HasPrefix(hop.IP, "59.43.") {
			hop.ASN = "4809"
		}
		result.Hops = append(result.Hops, hop)
		if hop.ASN != "" && !seenASN[hop.ASN] {
			seenASN[hop.ASN] = true
			result.PathASNs = append(result.PathASNs, hop.ASN)
		}
		if result.EntryHop == nil && isMainlandEntryHop(hop) {
			copyHop := hop
			result.EntryHop = &copyHop
		}
	}
	result.Route, result.Reason = classifyReturnRoute(result.EntryHop, result.PathASNs)
	if result.Route == "Unknown" && target.Carrier == "telecom" && result.EntryHop != nil {
		result.Route = "163"
		result.Reason += "；电信目标未识别到 CN2/CTG 骨干，按普通 163 线路兜底"
	}
	result.Success = result.EntryHop != nil
	return result
}

func normalizeASN(v string) string {
	return strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(v)), "AS")
}

func isMainlandChina(country string) bool {
	v := strings.ToLower(strings.TrimSpace(country))
	return (strings.Contains(v, "中国") || v == "china") && !strings.Contains(v, "香港") && !strings.Contains(v, "澳门") && !strings.Contains(v, "台湾")
}

func isMainlandEntryHop(hop returnRouteHop) bool {
	if isMainlandChina(hop.Country) || strings.HasPrefix(hop.IP, "59.43.") {
		return true
	}
	switch normalizeASN(hop.ASN) {
	case "23764", "4809", "4134", "4837", "9929", "10099", "58453", "9808", "58807", "4538", "7497":
		return true
	default:
		return false
	}
}

func classifyReturnRoute(entry *returnRouteHop, path []string) (string, string) {
	if entry == nil {
		return "Unknown", "未找到中国大陆回国跳点"
	}
	has := func(asn string) bool {
		for _, v := range path {
			if v == asn {
				return true
			}
		}
		return false
	}
	// Premium upstreams take precedence over the domestic access ASN.
	var route string
	switch {
	case has("23764"):
		route = "CTG GIA"
	case has("4809"):
		route = "CN2 GIA"
	case has("58807"):
		route = "CMIN2"
	case has("9929"):
		route = "9929"
	case has("10099"):
		route = "10099"
	case has("4134"):
		route = "163"
	case has("4837"):
		route = "4837"
	case has("58453") || has("9808"):
		route = "CMI"
	case entry.ASN == "4538":
		route = "CERNET"
	case entry.ASN == "7497":
		route = "CSTNET"
	default:
		route = "Unknown"
	}
	return route, fmt.Sprintf("回国跳点 %s (AS%s)，AS 路径 %s", entry.IP, entry.ASN, strings.Join(path, " → "))
}
