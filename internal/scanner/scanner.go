package scanner

import (
	"os"

	"github.com/azmogoo/sigwatch/internal/entropy"
	"github.com/azmogoo/sigwatch/internal/format"
	"github.com/azmogoo/sigwatch/internal/hashutil"
	"github.com/azmogoo/sigwatch/internal/ioc"
	"github.com/azmogoo/sigwatch/internal/rules"
	"github.com/azmogoo/sigwatch/internal/stringsx"
)

// Report is the result of analyzing a single file.
type Report struct {
	Path         string
	Size         int64
	Format       format.Kind
	Entropy      float64
	EntropyLabel string
	Digests      hashutil.Digests
	Strings      []string
	Matches      []rules.Match
	IOCHit       bool
	IOCLabel     string
}

// Scanner runs the static analysis pipeline.
type Scanner struct {
	Engine *rules.Engine
	IOCs   *ioc.Store
}

// New returns a scanner with default rules unless engine is nil.
func New(engine *rules.Engine, store *ioc.Store) (*Scanner, error) {
	if engine == nil {
		var err error
		engine, err = rules.NewEngine(rules.DefaultRules())
		if err != nil {
			return nil, err
		}
	}
	if store == nil {
		store = ioc.NewStore()
	}
	return &Scanner{Engine: engine, IOCs: store}, nil
}

// AnalyzeFile reads path and produces a report.
func (s *Scanner) AnalyzeFile(path string) (Report, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Report{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Report{}, err
	}
	digests, err := hashutil.HashFile(path)
	if err != nil {
		return Report{}, err
	}
	kind, _ := format.Detect(data)
	strs := stringsx.ExtractPrintable(data)
	matches := s.Engine.ScanStrings(strs)
	rep := Report{
		Path:         path,
		Size:         info.Size(),
		Format:       kind,
		Entropy:      entropy.Shannon(data),
		EntropyLabel: entropy.Score(data),
		Digests:      digests,
		Strings:      strs,
		Matches:      matches,
	}
	if s.IOCs.Contains(digests.SHA256) {
		rep.IOCHit = true
		rep.IOCLabel = s.IOCs.Label(digests.SHA256)
	}
	return rep, nil
}
