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

func matchStrings(ms []yara.MatchString) []string {
	s := []string{}
	lastData := ""

	for _, m := range ms {
		text := fmt.Sprintf("%s: %s", strings.Replace(m.Name, "$", "", 1), m.Data)
		if slices.Contains(s, text) {
			continue
		}
		if lastData != "" && strings.Contains(lastData, string(m.Data)) {
			continue
		}
		s = append(s, text)
		lastData = string(m.Data)
	}
	return s
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

	// hash to rules
	expected := map[string][]string{}
	for _, r := range rules.GetRules() {
		ruleID := r.Identifier()
		for _, m := range r.Metas() {
			if !strings.HasPrefix(m.Identifier, "hash") {
				continue
			}
			val := fmt.Sprintf("%s", m.Value)
			expected[val] = append(expected[val], ruleID)
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

			var mrs yara.MatchRules
			if err := rules.ScanFile(path, 0, 0, &mrs); err != nil {
				return fmt.Errorf("scanfile: %w", err)
			}
			sha256, err := checksum(path)
			if err != nil {
				return fmt.Errorf("checksum: %w", err)
			}

			if len(mrs) > 0 || len(expected[sha256]) > 0 {
				fmt.Printf("\n%s\n", path)
				for _, m := range mrs {
					fmt.Printf("  * %s\n", m.Rule)
					for _, s := range matchStrings(m.Strings) {
						fmt.Printf("    - %s\n", s)
					}
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
