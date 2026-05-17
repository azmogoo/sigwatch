package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/azmogoo/sigwatch/internal/scanner"
)

type cliConfig struct {
	output   string
	iocFile  string
	maxStr   int
}

func run(args []string) error {
	fs := flag.NewFlagSet("sigwatch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var cfg cliConfig
	fs.StringVar(&cfg.output, "o", "text", "output mode: text or json")
	fs.StringVar(&cfg.iocFile, "ioc", "", "path to SHA256 IOC list")
	fs.IntVar(&cfg.maxStr, "max-strings", 20, "max strings shown in text mode")
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) != 1 {
		return fmt.Errorf("usage: sigwatch [-o text|json] [-ioc file] <path>")
	}
	path := rest[0]

	sc, err := scanner.New(nil, nil)
	if err != nil {
		return err
	}
	if cfg.iocFile != "" {
		if err := sc.IOCs.LoadSHA256File(cfg.iocFile); err != nil {
			return err
		}
	}
	rep, err := sc.AnalyzeFile(path)
	if err != nil {
		return err
	}

	switch strings.ToLower(cfg.output) {
	case "json":
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case "text":
		printText(rep, cfg.maxStr)
		return nil
	default:
		return fmt.Errorf("unknown output mode %q", cfg.output)
	}
}

func printText(rep scanner.Report, maxStr int) {
	fmt.Printf("path:     %s\n", rep.Path)
	fmt.Printf("size:     %d\n", rep.Size)
	fmt.Printf("format:   %s\n", rep.Format)
	fmt.Printf("entropy:  %.4f (%s)\n", rep.Entropy, rep.EntropyLabel)
	fmt.Printf("md5:      %s\n", rep.Digests.MD5)
	fmt.Printf("sha1:     %s\n", rep.Digests.SHA1)
	fmt.Printf("sha256:   %s\n", rep.Digests.SHA256)
	if rep.IOCHit {
		fmt.Printf("ioc:      HIT")
		if rep.IOCLabel != "" {
			fmt.Printf(" (%s)", rep.IOCLabel)
		}
		fmt.Println()
	}
	if len(rep.Matches) > 0 {
		fmt.Println("signatures:")
		for _, m := range rep.Matches {
			fmt.Printf("  - %s: %s\n", m.RuleID, m.Snippet)
		}
	}
	if maxStr > 0 && len(rep.Strings) > 0 {
		n := len(rep.Strings)
		if n > maxStr {
			n = maxStr
		}
		fmt.Printf("strings (%d shown):\n", n)
		for i := 0; i < n; i++ {
			fmt.Printf("  %s\n", rep.Strings[i])
		}
	}
}
