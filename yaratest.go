package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hillu/go-yara/v4"
)

type TestConfig struct {
	PositivePaths []string
	RulePaths     []string
}

func checksum(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func RunTest(tc TestConfig) error {
	yc, err := yara.NewCompiler()
	if err != nil {
		return fmt.Errorf("yara compiler: %w")
	}
	for _, path := range tc.RulePaths {
		log.Printf("loading rule: %s", path)
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open: %w", err)
		}

		if err := yc.AddFile(f, path); err != nil {
			return fmt.Errorf("yara addfile: %w", err)
		}
	}

	rules, err := yc.GetRules()
	if err != nil {
		return fmt.Errorf("get rules: %w", err)
	}

	expected := map[string][]string{}
	for _, r := range rules.GetRules() {
		rid := r.Identifier()
		for _, m := range r.Metas() {
			if !strings.HasPrefix(m.Identifier, "hash") {
				continue
			}
			val := fmt.Sprintf("%s", m.Value)
			log.Printf("%s - %s=%s", rid, m.Identifier, val)
			expected[rid] = append(expected[rid], val)
		}
	}

	for _, d := range tc.PositivePaths {
		log.Printf("scanning %s", d)
		err = filepath.Walk(d, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || info.Size() < 64 {
				return nil
			}

			var m yara.MatchRules
			if err := rules.ScanFile(path, 0, 0, &m); err != nil {
				return fmt.Errorf("scanfile: %w", err)
			}
			sha256, err := checksum(path)
			if err != nil {
				return fmt.Errorf("checksum: %w", err)
			}

			log.Printf("%d matches: %s [%s]", len(m), path, sha256)

			for rid, hashes := range expected {
				if slices.Contains(hashes, sha256) {
					log.Printf("I WAS EXPECTED BY %s", rid)
				}
			}

			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func main() {
	positiveFlag := flag.String("positive", "", "Directory to find positive matches within")
	flag.Parse()
	args := flag.Args()

	tc := TestConfig{PositivePaths: []string{*positiveFlag}, RulePaths: args}
	if err := RunTest(tc); err != nil {
		log.Printf("test failed: %v", err)
		os.Exit(1)
	}

}
