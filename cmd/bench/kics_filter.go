package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type kicsFilter struct {
	Detail        string `json:"detail,omitempty"`
	ExcludeDetail string `json:"exclude_detail,omitempty"`
	Subject       string `json:"subject,omitempty"`
	Port          int    `json:"port,omitempty"`
	Ports         string `json:"ports,omitempty"`
}

type kicsMatcher struct {
	filter                kicsFilter
	detail, excludeDetail *regexp.Regexp
	subject               *regexp.Regexp
	knownPorts            map[int]bool
}

func compileKICSFilters(root string, queries map[string][]string, filters map[string]kicsFilter) (map[string]kicsMatcher, error) {
	matchers := make(map[string]kicsMatcher, len(filters))
	var knownPorts map[int]bool
	for query, filter := range filters {
		if _, ok := queries[query]; !ok {
			return nil, fmt.Errorf("query filter for unmapped KICS query %q", query)
		}
		m := kicsMatcher{filter: filter}
		for _, field := range []struct {
			value string
			out   **regexp.Regexp
		}{{filter.Detail, &m.detail}, {filter.ExcludeDetail, &m.excludeDetail}, {filter.Subject, &m.subject}} {
			if field.value != "" {
				expr, err := regexp.Compile(field.value)
				if err != nil {
					return nil, fmt.Errorf("KICS query %s: %w", query, err)
				}
				*field.out = expr
			}
		}
		if filter.Ports != "" {
			if (filter.Ports != "known" && filter.Ports != "unknown" && filter.Ports != "any") || filter.Port != 0 {
				return nil, fmt.Errorf("KICS query %s: invalid port selector", query)
			}
			if filter.Ports != "any" && knownPorts == nil {
				var err error
				knownPorts, err = readKICSPorts(root)
				if err != nil {
					return nil, err
				}
			}
			m.knownPorts = knownPorts
		}
		if filter.Port < 0 || filter.Port > 65535 {
			return nil, fmt.Errorf("KICS query %s: invalid port", query)
		}
		matchers[query] = m
	}
	return matchers, nil
}

var kicsPortKey = regexp.MustCompile(`(?m)^\s*(\d+):\s*"`)

func readKICSPorts(root string) (map[int]bool, error) {
	data, err := os.ReadFile(filepath.Join(root, "assets", "libraries", "common.rego"))
	if err != nil {
		return nil, fmt.Errorf("read KICS port table: %w", err)
	}
	_, tail, _ := strings.Cut(string(data), "tcpPortsMap = {")
	table, _, _ := strings.Cut(tail, "}")
	ports := map[int]bool{}
	for _, match := range kicsPortKey.FindAllStringSubmatch(table, -1) {
		port, err := strconv.Atoi(match[1])
		if err != nil || port < 0 || port > 65535 {
			return nil, fmt.Errorf("invalid KICS port %q", match[1])
		}
		ports[port] = true
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("KICS port table has no entries")
	}
	return ports, nil
}

var kicsIngressRange = regexp.MustCompile(`(?:(TCP|UDP) ports (\d+)-(\d+) are|all protocols and ports are) open to (\S+)(?: \(configured ports (\d+)-(\d+)\))?`)

func (m kicsMatcher) matches(f finding) bool {
	if (m.detail != nil && !m.detail.MatchString(f.Detail)) ||
		(m.excludeDetail != nil && m.excludeDetail.MatchString(f.Detail)) ||
		(m.subject != nil && !m.subject.MatchString(f.Subject)) {
		return false
	}
	if m.filter.Port == 0 && m.filter.Ports == "" {
		return true
	}
	portDetail := kicsIngressRange.FindStringSubmatch(f.Detail)
	if portDetail == nil {
		return false
	}
	source, err := netip.ParsePrefix(portDetail[4])
	if err != nil || source.Bits() != 0 || (m.filter.Ports != "known" && !source.Addr().IsUnspecified()) {
		return false
	}
	if m.filter.Ports == "any" {
		return true
	}
	protocol, min, max := portDetail[1], portDetail[2], portDetail[3]
	if protocol == "" {
		if m.filter.Port != 0 {
			return true // AWS ignores the configured range for protocol -1.
		}
		min, max = portDetail[5], portDetail[6]
	}
	start, firstErr := strconv.Atoi(min)
	end, lastErr := strconv.Atoi(max)
	if firstErr != nil || lastErr != nil || start < 0 || end > 65535 || start > end {
		return false
	}
	if m.filter.Port != 0 {
		return protocol == "TCP" && start <= m.filter.Port && m.filter.Port <= end
	}
	known := m.filter.Ports == "known"
	for port := start; port <= end; port++ {
		if m.knownPorts[port] == known {
			return true
		}
	}
	return false
}
