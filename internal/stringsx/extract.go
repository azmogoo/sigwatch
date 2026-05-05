package stringsx

import (
	"strings"
	"unicode"
)

// Extract finds printable ASCII/UTF-8 runs of at least minLen bytes.
func Extract(data []byte, minLen int) []string {
	if minLen < 1 {
		minLen = 4
	}
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() >= minLen {
			out = append(out, cur.String())
		}
		cur.Reset()
	}
	for _, b := range data {
		if b >= 0x20 && b <= 0x7e {
			cur.WriteByte(b)
			continue
		}
		flush()
	}
	flush()
	return out
}

// ExtractPrintable is like Extract with minLen 4.
func ExtractPrintable(data []byte) []string {
	return Extract(data, 4)
}

// Filter keeps strings matching a simple substring rule.
func Filter(strs []string, substr string) []string {
	if substr == "" {
		return strs
	}
	var kept []string
	for _, s := range strs {
		if strings.Contains(s, substr) {
			kept = append(kept, s)
		}
	}
	return kept
}

// IsMostlyPrintable reports whether runes in s are mostly printable.
func IsMostlyPrintable(s string) bool {
	if s == "" {
		return false
	}
	var ok int
	for _, r := range s {
		if unicode.IsPrint(r) {
			ok++
		}
	}
	return float64(ok)/float64(len([]rune(s))) >= 0.9
}
