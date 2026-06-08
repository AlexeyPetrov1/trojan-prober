package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ProbeData struct {
	ALPN          string `json:"alpn"`
	BaseContent   string `json:"base_content"`
	RepeatContent string `json:"repeat_content"`
	RepeatNum     int    `json:"repeat_num"`
}

func probeJSONPath(probe string) string {
	candidates := []string{
		filepath.Join("src", "probe_json", probe+".json"),
		filepath.Join("probe_json", probe+".json"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return candidates[0]
}

func loadProbeData(probe string, overbufferRepeatOverride int) (*ProbeData, error) {
	jsonPath := probeJSONPath(probe)
	jsonData, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", jsonPath, err)
	}
	var probeData ProbeData
	if err := json.Unmarshal(jsonData, &probeData); err != nil {
		return nil, fmt.Errorf("failed to parse JSON file %s: %v", jsonPath, err)
	}
	if probe == "Overbuffer-Incomplete" && overbufferRepeatOverride > 0 {
		probeData.RepeatNum = overbufferRepeatOverride
	}
	return &probeData, nil
}

func buildRequest(probeData *ProbeData) string {
	baseContent := strings.ReplaceAll(probeData.BaseContent, `\r`, "\r")
	baseContent = strings.ReplaceAll(baseContent, `\n`, "\n")

	repeatContent := strings.ReplaceAll(probeData.RepeatContent, `\r`, "\r")
	repeatContent = strings.ReplaceAll(repeatContent, `\n`, "\n")
	repeatedContent := strings.Repeat(repeatContent, probeData.RepeatNum)

	return baseContent + repeatedContent
}

func extractBackendType(responseStr string) string {
	if strings.Contains(responseStr, "Server:") {
		lines := strings.Split(responseStr, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Server:") {
				return strings.ToLower(strings.TrimSpace(strings.Split(line, ":")[1]))
			}
		}
	} else {
		if strings.Contains(responseStr, "Microsoft-HTTPAPI") || strings.Contains(responseStr, "Microsoft-IIS") {
			return "iis"
		}
		serverTypes := []string{"nginx", "apache", "caddy", "tomcat", "lighttpd"}
		for _, server := range serverTypes {
			if strings.Contains(strings.ToLower(responseStr), strings.ToLower(server)) {
				return strings.ToLower(server)
			}
		}
	}
	return ""
}

func httpsNameFromBackend(backendType string) string {
	switch {
	case strings.Contains(backendType, "nginx"):
		return "Nginx"
	case strings.Contains(backendType, "apache"):
		return "Apache"
	case strings.Contains(backendType, "caddy"):
		return "Caddy"
	case strings.Contains(backendType, "tomcat"):
		return "Tomcat"
	case strings.Contains(backendType, "lighttpd"):
		return "Lighttpd"
	case strings.Contains(backendType, "microsoft"), strings.Contains(backendType, "iis"):
		return "IIS"
	default:
		return ""
	}
}

func setTrojanMap(m map[string]CandidateState, name string, state CandidateState) {
	if m == nil {
		return
	}
	m[name] = state
}

func setHTTPSMap(m map[string]CandidateState, name string, state CandidateState) {
	if m == nil {
		return
	}
	m[name] = state
}

func markAllTrojanExcept(m map[string]CandidateState, except string, state CandidateState) {
	for _, name := range allTrojanNames {
		if name != except {
			setTrojanMap(m, name, state)
		}
	}
}

func markAllTrojan(m map[string]CandidateState, state CandidateState) {
	for _, name := range allTrojanNames {
		setTrojanMap(m, name, state)
	}
}

func markHTTPSFromBackend(m map[string]CandidateState, backendType string, match CandidateState, others CandidateState) {
	if backendType == "" {
		return
	}
	name := httpsNameFromBackend(backendType)
	for _, n := range allHTTPServerNames {
		if n == name && name != "" {
			setHTTPSMap(m, n, match)
		} else {
			setHTTPSMap(m, n, others)
		}
	}
}
