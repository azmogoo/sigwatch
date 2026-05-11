package ioc

import (
	"bufio"
	"os"
	"strings"
)

// Store holds SHA256 indicators of compromise (lowercase hex).
type Store struct {
	hashes map[string]struct{}
	labels map[string]string
}

// NewStore creates an empty IOC store.
func NewStore() *Store {
	return &Store{
		hashes: make(map[string]struct{}),
		labels: make(map[string]string),
	}
}

// Add registers a SHA256 hash with an optional label.
func (s *Store) Add(sha256, label string) {
	h := normalizeSHA256(sha256)
	if h == "" {
		return
	}
	s.hashes[h] = struct{}{}
	if label != "" {
		s.labels[h] = label
	}
}

// Contains reports whether sha256 is a known IOC.
func (s *Store) Contains(sha256 string) bool {
	h := normalizeSHA256(sha256)
	_, ok := s.hashes[h]
	return ok
}

// Label returns a label for a known hash, or empty.
func (s *Store) Label(sha256 string) string {
	h := normalizeSHA256(sha256)
	return s.labels[h]
}

// LoadSHA256File reads one hash per line from path.
func (s *Store) LoadSHA256File(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 1 {
			s.Add(parts[0], "")
		} else {
			s.Add(parts[0], strings.Join(parts[1:], " "))
		}
	}
	return sc.Err()
}

func normalizeSHA256(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	if len(h) != 64 {
		return ""
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return ""
		}
	}
	return h
}
