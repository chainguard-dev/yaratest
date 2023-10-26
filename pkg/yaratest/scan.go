package yaratest

import (
	"fmt"
	"io/fs"
	"log"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/hillu/go-yara/v4"
)

func Scan(c Config) (Result, error) {
	start := time.Now()
	res := Result{
		TruePositive:    map[string]bool{},
		TrueNegative:    map[string]bool{},
		FalseNegative:   map[string]bool{},
		FalsePositive:   map[string]bool{},
		ScanErrors:      []string{},
		SHA256:          map[string]string{},
		FailedHashCheck: map[string][]string{},
	}

	rules := c.Rules
	res.RuleCount = len(rules.GetRules())

	// hash to rules
	expected := map[string][]string{}
	hashName := map[string]string{}
	for _, r := range rules.GetRules() {
		ruleID := r.Identifier()
		for _, m := range r.Metas() {
			if !strings.HasPrefix(m.Identifier, "hash") {
				continue
			}
			hash := fmt.Sprintf("%s", m.Value)
			res.HashCount++
			expected[hash] = append(expected[hash], ruleID)
			hashName[hash] = strings.ReplaceAll(m.Identifier, "hash_", "")
		}
	}

	paths := []string{}
	paths = append(paths, c.ReferencePaths...)
	paths = append(paths, c.ScanPaths...)
	res.NewHashMatches = []Match{}

	fmt.Printf("🔎 Scanning %d paths ...\n", len(paths))

	for _, d := range paths {
		if d == "" {
			continue
		}
		expectedPositive := false
		if slices.Contains(c.ReferencePaths, d) {
			expectedPositive = true
		}

		err := filepath.Walk(d, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				log.Printf("unable to walk %s: %v", path, err)
				res.ScanErrors = append(res.ScanErrors, path)
				return nil
			}
			if !info.Mode().IsRegular() || info.Size() < 16 || strings.Contains(path, "/.git/") || strings.Contains(path, "/tools/") {
				return nil
			}

			if c.CachedReferenceHit[path] {
				res.ReferenceFilesSkipped++
				res.TruePositive[path] = true
				return nil
			}

			if c.CachedScanMiss[path] {
				res.ScanFilesSkipped++
				res.TrueNegative[path] = true
				return nil
			}

			programKind := programKind(path)
			if c.ProgramsOnly && programKind == "" {
				// log.Printf("skipping %s (not a program)", path)
				return nil
			}
			for _, kind := range c.ExcludeProgramKinds {
				if kind != "" && strings.Contains(programKind, kind) {
					log.Printf("skipping %s (%q programs are excluded)", path, kind)
					return nil
				}
			}

			var mrs yara.MatchRules
			if err := rules.ScanFile(path, 0, 0, &mrs); err != nil {
				res.ScanErrors = append(res.ScanErrors, path)
				log.Printf("scan %s: %v", path, err)
				return nil
			}

			res.Duration = time.Since(start)

			// Stats updates
			res.FilesSeen++
			if expectedPositive {
				res.ReferenceFilesSeen++
				if len(mrs) > 0 {
					res.TruePositive[path] = true
				} else {
					res.FalseNegative[path] = true
				}
			} else {
				res.ScanFilesSeen++
				if len(mrs) > 0 {
					res.FalsePositive[path] = true
				} else {
					res.TrueNegative[path] = true
				}
			}

			sha256, err := checksum(path)
			if err != nil {
				return fmt.Errorf("checksum: %w", err)
			}

			res.SHA256[path] = sha256

			hitRules := []string{}
			fail := false

			for _, m := range mrs {
				hitRules = append(hitRules, m.Rule)
			}

			for _, rule := range expected[sha256] {
				if !slices.Contains(hitRules, rule) {
					fail = true
					res.FailedHashCheck[path] = append(res.FailedHashCheck[path], rule)
				}
			}

			if expectedPositive && len(mrs) == 0 {
				fmt.Printf("\nFAILED TO MATCH: %s - %d bytes [%s - %s]\n", path, info.Size(), programKind, sha256)
				fail = true
			}

			if len(mrs) > 0 || len(expected[sha256]) > 0 {
				if !expectedPositive {
					fail = true
				}

				sev := severityRating(mrs)
				if fail || !c.Quiet {
					fmt.Printf("\n%s %s\n", sev.Name, path)
				}

				for _, m := range mrs {
					if expectedPositive && !slices.Contains(expected[sha256], m.Rule) {
						res.NewHashMatches = append(res.NewHashMatches, Match{Path: path, RuleName: m.Rule, SHA256: sha256})
					}
					if fail || !c.Quiet {
						fmt.Printf("  * %s\n", m.Rule)
						for _, s := range matchStrings(m.Strings) {
							fmt.Printf("      %s\n", s)
						}
					}
				}

				if !c.Quiet || (expectedPositive && fail) {
					if len(expected[sha256]) > 0 {
						fmt.Printf("  - sha256: %s (%s)\n", sha256, hashName[sha256])
					} else {
						fmt.Printf("  - sha256: %s\n", sha256)
					}
				}

				if !expectedPositive {
					if c.ExitOnFailure {
						return fmt.Errorf("expected %s [%s] to have zero matches", path, sha256)
					}
				}

			}

			for _, rule := range expected[sha256] {
				if slices.Contains(hitRules, rule) {
					res.HashesConfirmed++
					continue
				}

				fmt.Printf("  ^-- ERROR: expected rule match: %s\n", rule)
				res.HashFailures++
				if c.ExitOnFailure {
					return fmt.Errorf("%s does not match %q", path, rule)
				}
			}

			return nil
		})

		if err != nil {
			return res, err
		}
	}

	return res, nil
}
