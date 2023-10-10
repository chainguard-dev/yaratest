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
	"regexp"
	"slices"
	"strings"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
	"github.com/fsnotify/fsnotify"
	"github.com/hillu/go-yara/v4"
)

var (
	notAlpha   = regexp.MustCompile(`\W+`)
	multiUnder = regexp.MustCompile(`_+`)
)

type TestConfig struct {
	PositivePaths []string
	NegativePaths []string
	RulePaths     []string
	ExitOnFailure bool
	Quiet         bool
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
		text := fmt.Sprintf("%-16.16s: %s", strings.Replace(m.Name, "$", "", 1), m.Data)
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

type Severity struct {
	Score int
	Name  string

	MatchingRules   int
	MatchingStrings int
}

func severityRating(ym yara.MatchRules) Severity {
	// The theory: the importance of a rule is relative to the complexity of the rule

	score := 0
	stringCount := 0

	// for each matching rule ...
	for _, y := range ym {
		points := 1
		hashes := 0
		for _, m := range y.Metas {
			if strings.Contains(m.Identifier, "hash") {
				hashes++
			}
		}
		hitName := map[string]bool{}
		for _, s := range y.Strings {
			hitName[s.Name] = true
		}

		if hashes > 0 {
			points = points + max(len(hitName), 5)
		}

		stringCount += len(hitName)
		score += points
	}

	name := "INFO"
	switch {
	case score >= 10:
		name = "CRITICAL"
	case score >= 8:
		name = "HIGH"
	case score >= 5:
		name = "MEDIUM"
	case score >= 3:
		name = "LOW"
	default:
		name = "INFO"
	}

	return Severity{Name: name, Score: score, MatchingRules: len(ym), MatchingStrings: stringCount}
}

type Match struct {
	Path     string
	SHA256   string
	RuleName string
}

func RunTest(tc TestConfig) ([]Match, error) {
	yc, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara compiler: %w", err)
	}
	for _, path := range tc.RulePaths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open: %w", err)
		}

		if err := yc.AddFile(f, path); err != nil {
			return nil, fmt.Errorf("yara addfile %s: %w", path, err)
		}
	}

	rules, err := yc.GetRules()
	if err != nil {
		return nil, fmt.Errorf("get rules: %w", err)
	}

	if !tc.Quiet {
		log.Printf("Loaded %d rules\n", len(rules.GetRules()))
	}

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
			expected[hash] = append(expected[hash], ruleID)
			hashName[hash] = strings.ReplaceAll(m.Identifier, "hash_", "")
		}
	}

	scanPaths := []string{}
	for _, p := range tc.PositivePaths {
		if p != "" {
			scanPaths = append(scanPaths, p)
		}
	}
	for _, p := range tc.NegativePaths {
		if p != "" {
			scanPaths = append(scanPaths, p)
		}
	}

	scanSubTotal := 0
	newMatches := []Match{}

	for _, d := range scanPaths {
		log.Printf("scanning %s ...", d)
		scanSubTotal = 0

		err = filepath.Walk(d, func(path string, info fs.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || info.Size() < 64 {
				return nil
			}

			if filepath.Dir(path) == ".git" {
				return nil
			}

			var mrs yara.MatchRules
			scanSubTotal++
			if err := rules.ScanFile(path, 0, 0, &mrs); err != nil {
				return fmt.Errorf("scanfile: %w", err)
			}
			sha256, err := checksum(path)
			if err != nil {
				return fmt.Errorf("checksum: %w", err)
			}

			hitRules := []string{}
			fail := false

			for _, m := range mrs {
				hitRules = append(hitRules, m.Rule)
			}

			for _, rule := range expected[sha256] {
				if !slices.Contains(hitRules, rule) {
					fail = true
				}
			}

			if len(mrs) > 0 || len(expected[sha256]) > 0 {
				if slices.Contains(tc.NegativePaths, d) {
					fail = true
				}

				sev := severityRating(mrs)
				if fail || !tc.Quiet {
					fmt.Printf("\n%s %s\n", sev.Name, path)
				}

				for _, m := range mrs {
					if !slices.Contains(expected[sha256], m.Rule) {
						fmt.Printf("%s is not expected?\n", sha256)
						newMatches = append(newMatches, Match{Path: path, RuleName: m.Rule, SHA256: sha256})
					}
					if fail || !tc.Quiet {
						fmt.Printf("  * %s\n", m.Rule)
						for _, s := range matchStrings(m.Strings) {
							fmt.Printf("    - %s\n", s)
						}
					}
				}

				if fail || !tc.Quiet {
					if len(expected[sha256]) > 0 {
						fmt.Printf("  - sha256: %s (%s)\n", sha256, hashName[sha256])
					} else {

						fmt.Printf("  - sha256: %s\n", sha256)
					}
				}

				if slices.Contains(tc.NegativePaths, d) {
					fmt.Printf("  ^-- ERROR: expected no match\n")
					if tc.ExitOnFailure {
						return fmt.Errorf("expected %s [%s] to have zero matches", path, sha256)
					}
				}

			}

			for _, rule := range expected[sha256] {
				if !slices.Contains(hitRules, rule) {
					fmt.Printf("  ^-- ERROR: expected rule match: %s\n", rule)
					if tc.ExitOnFailure {
						return fmt.Errorf("%s does not match %q", path, rule)
					}
				}
			}

			return nil
		})

		log.Printf("scanned %d files in %s. %d new matches identified", scanSubTotal, d, len(newMatches))

		if err != nil {
			return newMatches, err
		}
	}

	return newMatches, nil
}

func hashName(m Match, rules []*ast.Rule) string {

	// see if there is an existing name first
	for _, r := range rules {
		for _, meta := range r.Meta {
			if strings.HasPrefix(meta.Key, "hash") {
				val := fmt.Sprintf("%s", meta.Value)
				if m.SHA256 == val {
					return meta.Key
				}
			}
		}
	}

	i, err := os.Stat(m.Path)
	year := "0000"
	if err == nil {
		year = i.ModTime().Format("2006")
	}

	name := "hash_" + year + "_" + filepath.Base(filepath.Dir(m.Path)) + "_"
	base := filepath.Base(m.Path)
	base = strings.Replace(base, filepath.Ext(base), "", 1)

	if !strings.Contains(name, base) {
		if strings.Contains(base, m.SHA256) {
			name = name + m.SHA256[0:4]
		} else {
			name = name + base
		}
	}

	name = notAlpha.ReplaceAllString(name, "_")
	name = multiUnder.ReplaceAllString(name, "_")
	name = strings.TrimRight(name, "_")
	return name
}

func updateRuleFile(path string, ms map[string][]Match, maxRules int) error {
	if len(ms) == 0 {
		return nil
	}

	log.Printf("loading rule: %s", path)

	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	// hillu doesn't seem to allow for metadata updates :(
	rs, err := gyp.Parse(f)
	if err != nil {
		log.Fatalf(`Error parsing rules: %v`, err)
	}

	updated := 0

	for _, r := range rs.Rules {
		hashes := 0
		for _, m := range r.Meta {
			if strings.HasPrefix(m.Key, "hash") {
				hashes++
			}
		}

		for _, update := range ms[r.Identifier] {
			// We will never delete hashes, but we can refuse to add more
			if hashes >= maxRules {
				log.Printf("%s has %d hashes - won't add %s from %s", r.Identifier, hashes, update.SHA256, update.Path)
				break
			}
			key := hashName(update, rs.Rules)
			log.Printf("adding %s=%q to %s", key, update.SHA256, r.Identifier)
			r.Meta = append(r.Meta, &ast.Meta{Key: key, Value: update.SHA256})
			hashes++
			updated++
		}
	}
	f.Close()

	if updated == 0 {
		fmt.Printf("no updates for %s\n", path)
		return nil
	}

	wf, err := os.OpenFile(path, os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}

	if err = rs.WriteSource(wf); err != nil {
		log.Fatalf(`Error writing rules: %v`, err)
	}
	return wf.Close()
}

func updateRules(paths []string, matches []Match, maxNum int) error {

	updates := map[string][]Match{}
	for _, m := range matches {
		updates[m.RuleName] = append(updates[m.RuleName], m)
	}

	for _, path := range paths {
		if err := updateRuleFile(path, updates, maxNum); err != nil {
			return err
		}
	}

	return nil
}

func watchAndRunTests(tc TestConfig) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// run once
	RunTest(tc)

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					log.Println("modified file:", event.Name)
					_, err := RunTest(tc)
					if err != nil {
						log.Printf("test failed: %v", err)
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	fmt.Printf("watching %s\n", strings.Join(tc.RulePaths, " "))
	for _, path := range tc.RulePaths {
		err = watcher.Add(path)
		if err != nil {
			log.Fatal(err)
		}
	}
	<-make(chan struct{})
	return nil
}

func main() {
	positiveFlag := flag.String("positive", "", "Directory to find positive matches within")
	negativeFlag := flag.String("negative", "", "Directory to find positive matches within")
	exitEarlyFlag := flag.Bool("exit-on-failure", false, "Exit as soon as a problem comes up")
	quietFlag := flag.Bool("quiet", false, "Quiet mode")
	watchFlag := flag.Bool("watch", false, "Watch for changes and rescan")
	addHashesFlag := flag.Bool("add-hashes", false, "Add hashes")
	hashMaxFlag := flag.Int("hash-max", 8, "Do not add more than this many hashes to any rule")
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		fmt.Printf("usage: yaratest [flags] <yara paths>\n")
		os.Exit(2)
	}

	tc := TestConfig{
		PositivePaths: []string{*positiveFlag},
		NegativePaths: []string{*negativeFlag},
		RulePaths:     args,
		ExitOnFailure: *exitEarlyFlag,
		Quiet:         *quietFlag,
	}

	if *watchFlag {
		err := watchAndRunTests(tc)
		if err != nil {
			log.Printf("watch and run failed: %v", err)
			os.Exit(1)
		}

	}
	newMatches, err := RunTest(tc)
	if err != nil {
		log.Printf("test failed: %v", err)
		os.Exit(1)
	}

	if *addHashesFlag {
		updateRules(args, newMatches, *hashMaxFlag)
	}
}
