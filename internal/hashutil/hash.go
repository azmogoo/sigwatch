package hashutil

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"io"
	"os"
)

// Digests holds common hash digests for a blob.
type Digests struct {
	MD5    string
	SHA1   string
	SHA256 string
}

// HashFile reads path and returns MD5, SHA1, and SHA256 hex digests.
func HashFile(path string) (Digests, error) {
	f, err := os.Open(path)
	if err != nil {
		return Digests{}, err
	}
	defer f.Close()
	return HashReader(f)
}

// HashReader computes digests from r.
func HashReader(r io.Reader) (Digests, error) {
	md5h := md5.New()
	sha1h := sha1.New()
	sha256h := sha256.New()
	mw := io.MultiWriter(md5h, sha1h, sha256h)
	if _, err := io.Copy(mw, r); err != nil {
		return Digests{}, err
	}
	return Digests{
		MD5:    hex.EncodeToString(md5h.Sum(nil)),
		SHA1:   hex.EncodeToString(sha1h.Sum(nil)),
		SHA256: hex.EncodeToString(sha256h.Sum(nil)),
	}, nil
}

// SumHex returns the hex digest of data using h.
func SumHex(h hash.Hash, data []byte) string {
	h.Reset()
	_, _ = h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}
