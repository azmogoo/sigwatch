package entropy

import "math"

// Shannon returns Shannon entropy in bits per byte for data (0–8).
func Shannon(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	n := float64(len(data))
	var h float64
	for _, c := range freq {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// Score labels entropy for quick reporting.
func Score(data []byte) string {
	e := Shannon(data)
	switch {
	case e < 1:
		return "very_low"
	case e < 3:
		return "low"
	case e < 6:
		return "medium"
	case e < 7.2:
		return "high"
	default:
		return "very_high"
	}
}
