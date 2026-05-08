package rules

import (
	"regexp"
	"strings"
)

// Rule matches content against a named pattern.
type Rule struct {
	ID      string
	Pattern string
	re      *regexp.Regexp
}

// Engine evaluates signature rules against text and byte samples.
type Engine struct {
	rules []Rule
}

// NewEngine builds an engine from rule definitions (pattern is regex).
func NewEngine(defs []Rule) (*Engine, error) {
	e := &Engine{rules: make([]Rule, 0, len(defs))}
	for _, d := range defs {
		re, err := regexp.Compile(d.Pattern)
		if err != nil {
			return nil, err
		}
		d.re = re
		e.rules = append(e.rules, d)
	}
	return e, nil
}

// Match holds a fired rule.
type Match struct {
	RuleID  string
	Snippet string
}

// ScanStrings runs rules against extracted strings.
func (e *Engine) ScanStrings(strs []string) []Match {
	var hits []Match
	for _, s := range strs {
		for _, r := range e.rules {
			if loc := r.re.FindStringIndex(s); loc != nil {
				snip := s
				if len(snip) > 80 {
					snip = snip[:80] + "..."
				}
				hits = append(hits, Match{RuleID: r.ID, Snippet: snip})
			}
		}
	}
	return hits
}

// ScanBytes runs rules against raw bytes interpreted as Latin-1 text.
func (e *Engine) ScanBytes(data []byte) []Match {
	return e.ScanStrings([]string{string(data)})
}

// DefaultRules returns built-in suspicious string signatures.
func DefaultRules() []Rule {
	return []Rule{
		{ID: "cmd_powershell", Pattern: `(?i)powershell(\.exe)?\s`},
		{ID: "cmd_certutil", Pattern: `(?i)certutil(\.exe)?\s`},
		{ID: "url_http", Pattern: `https?://[^\s"']+`},
		{ID: "registry_run", Pattern: `(?i)CurrentVersion\\Run`},
	}
}

// ContainsAnyKeyword is a fast pre-filter before regex rules.
func ContainsAnyKeyword(data []byte, keywords ...string) bool {
	lower := strings.ToLower(string(data))
	for _, kw := range keywords {
		if kw == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}
