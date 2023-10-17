package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
	"github.com/fsnotify/fsnotify"
	"github.com/hillu/go-yara/v4"
	"github.com/liamg/magic"
)

var (
	notAlpha   = regexp.MustCompile(`\W+`)
	multiUnder = regexp.MustCompile(`_+`)
)

type TestConfig struct {
	ReferencePaths      []string
	ScanPaths           []string
	RulePaths           []string
	Rules               *yara.Rules
	ProgramsOnly        bool
	ExcludeProgramKinds []string
	ExitOnFailure       bool
	Quiet               bool
	PlaySounds          bool

	CachedReferenceHit map[string]bool
	CachedScanMiss     map[string]bool
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

type Result struct {
	Duration        time.Duration
	RuleCount       int
	FilesSeen       int
	HashCount       int
	HashesConfirmed int
	HashFailures    int
	ScanErrors      []string

	ReferenceFilesSeen    int
	ReferenceFilesSkipped int
	ScanFilesSeen         int
	ScanFilesSkipped      int

	NewHashMatches []Match
	TruePositive   map[string]bool
	TrueNegative   map[string]bool
	FalsePositive  map[string]bool
	FalseNegative  map[string]bool

	SHA256 map[string]string

	FailedHashCheck map[string][]string
}

func programKind(path string) string {
	r, err := os.Open(path)
	if err != nil {
		log.Printf("open %s failed: %v", path, err)
		return ""
	}
	defer r.Close()

	var header [263]byte
	desc := ""
	_, err = io.ReadFull(r, header[:])
	if err == nil {
		kind, err := magic.Lookup(header[:])
		if err == nil {
			desc = kind.Description
		}
	}

	// By Magic
	d := strings.ToLower(desc)
	if strings.Contains(d, "executable") || strings.Contains(d, "mach-o") || strings.Contains(d, "script") {
		return desc
	}

	// By Filename
	switch {
	case strings.Contains(path, "systemd"):
		return "systemd"
	case strings.Contains(path, ".elf"):
		return "Linux ELF binary"
	case strings.Contains(path, ".xcoff"):
		return "XCOFF progam"
	}

	switch filepath.Ext(path) {
	case ".scpt":
		return "compiled AppleScript"
	case ".sh":
		return "Shell script"
	case ".rb":
		return "Ruby script"
	case ".py":
		return "Python script"
	case ".pl":
		return "PERL script"
	case ".expect":
		return "Expect script"
	case ".php":
		return "PHP file"
	case ".js":
		return "Javascript"
	case ".7z":
		return ""
	case ".java":
		return "Java source"
	case ".jar":
		return "Java program"
	case ".asm":
		return ""
	case ".c":
		return "C source"
	}

	// By string match
	s := string(header[:])
	switch {
	case strings.Contains(s, "import"):
		return "Python"
	case strings.HasPrefix(s, "#!/bin/sh") || strings.HasPrefix(s, "#!/bin/bash"):
		return "Shell"
	case strings.HasPrefix(s, "#!"):
		return "script"
	case strings.Contains(s, "#include <"):
		return "C Program"
	}

	// fmt.Printf("File %s string: %s", path, s)
	// fmt.Printf("File %s: desc: %s\n", path, desc)
	return ""
}

func RunTest(tc TestConfig) (Result, error) {
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

	rules := tc.Rules
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
	paths = append(paths, tc.ReferencePaths...)
	paths = append(paths, tc.ScanPaths...)
	res.NewHashMatches = []Match{}

	fmt.Printf("🔎 Scanning %d paths ...\n", len(paths))

	for _, d := range paths {
		if d == "" {
			continue
		}
		expectedPositive := false
		if slices.Contains(tc.ReferencePaths, d) {
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

			if tc.CachedReferenceHit[path] {
				res.ReferenceFilesSkipped++
				res.TruePositive[path] = true
				return nil
			}

			if tc.CachedScanMiss[path] {
				res.ScanFilesSkipped++
				res.TrueNegative[path] = true
				return nil
			}

			programKind := programKind(path)
			if tc.ProgramsOnly && programKind == "" {
				// log.Printf("skipping %s (not a program)", path)
				return nil
			}
			for _, kind := range tc.ExcludeProgramKinds {
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
				if fail || !tc.Quiet {
					fmt.Printf("\n%s %s\n", sev.Name, path)
				}

				for _, m := range mrs {
					if expectedPositive && !slices.Contains(expected[sha256], m.Rule) {
						res.NewHashMatches = append(res.NewHashMatches, Match{Path: path, RuleName: m.Rule, SHA256: sha256})
					}
					if fail || !tc.Quiet {
						fmt.Printf("  * %s\n", m.Rule)
						for _, s := range matchStrings(m.Strings) {
							fmt.Printf("      %s\n", s)
						}
					}
				}

				if !tc.Quiet || (expectedPositive && fail) {
					if len(expected[sha256]) > 0 {
						fmt.Printf("  - sha256: %s (%s)\n", sha256, hashName[sha256])
					} else {
						fmt.Printf("  - sha256: %s\n", sha256)
					}
				}

				if !expectedPositive {
					if tc.ExitOnFailure {
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
				if tc.ExitOnFailure {
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

func LogResult(res Result) {
	truePositiveRate := float64(len(res.TruePositive)) / float64(res.ReferenceFilesSeen+res.ReferenceFilesSkipped) * 100
	falsePositiveRate := float64(len(res.FalsePositive)) / float64(res.ScanFilesSeen+res.ScanFilesSkipped) * 100
	skipped := res.ScanFilesSkipped + res.ReferenceFilesSkipped
	fmt.Printf("\n")

	ds := res.Duration.Seconds()

	if skipped > 0 {
		fmt.Printf("✅ processed:       %d files in %.1fs, skipped %d files (cache)\n", res.FilesSeen, ds, skipped)
	} else {
		fmt.Printf("✅ processed:       %d files in %.1fs\n", res.FilesSeen, ds)
	}
	if res.ScanFilesSeen > 0 {
		fmt.Printf("✅ scan paths:      %d unexpected hits (%.2f%%)\n", len(res.FalsePositive), falsePositiveRate)
	}
	if res.ReferenceFilesSeen > 0 {
		fmt.Printf("✅ reference paths: %d hits (%.2f%%)\n", len(res.TruePositive), truePositiveRate)
	}
	if res.HashCount > 0 {
		hashesSeen := res.HashesConfirmed + res.HashFailures
		hashFailRate := float64(res.HashFailures) / float64(hashesSeen) * 100
		fmt.Printf("✅ test hashes:     %d defined, %d seen, %d failed (%.2f%%)\n", res.HashCount, res.HashesConfirmed, res.HashFailures, hashFailRate)
	}

	hashFails := []string{}
	for k, vs := range res.FailedHashCheck {
		for _, v := range vs {
			if strings.Contains(k, res.SHA256[k]) {
				hashFails = append(hashFails, fmt.Sprintf("  %s - %s", v, k))
			} else {
				hashFails = append(hashFails, fmt.Sprintf("  %q - %s [%s]", v, k, res.SHA256[k]))
			}
		}
	}

	if len(hashFails) > 0 {
		fmt.Printf("❌ %d test hash failures:\n", len(hashFails))
		sort.Strings(hashFails)
		for _, s := range hashFails {
			fmt.Printf("  %s\n", s)
		}
	}

	// if len(res.ScanErrors) > 0 {
	// 	fmt.Printf("! unable to scan %d paths: %v\n", len(res.ScanErrors), strings.Join(res.ScanErrors, " "))
	// }
}

func playSoundBite(name string) {
	exec.Command("afplay", filepath.Join("/System/Library/Sounds", name+".aiff")).Run()
}

func LogResultDiff(res Result, last Result, playSound bool) {
	// How many more reference files did we hit?
	// Make sure to compare against previous FN list, in case of newly added files
	sound := "Pop"

	tpGained := []string{}
	for p := range res.TruePositive {
		// log.Printf("checking %s against %d fn (%d vs %d)", p, len(last.FalseNegative), len(res.TruePositive), len(last.TruePositive))
		if last.FalseNegative[p] {
			// log.Printf("%s was FN, now TP", p)
			tpGained = append(tpGained, p)
		}
	}

	if last.HashFailures > res.HashFailures {
		sound = "Frog"
		fmt.Printf("🔥 Iteration fixed %d test hash failures - only %d remain!\n", last.HashFailures-res.HashFailures, res.HashFailures)
	}

	if last.HashFailures < res.HashFailures {
		sound = "Basso"
		fmt.Printf("🚒 Iteration added %d test hash failures\n", res.HashFailures-last.HashFailures)
	}

	if len(tpGained) > 0 {
		sound = "Hero"
		fmt.Printf("😎 Iteration gained %d true positives (now %d)\n", len(tpGained), len(res.TruePositive))
	}

	tpLost := []string{}
	for p := range res.FalseNegative {
		if last.TruePositive[p] {
			tpLost = append(tpLost, p)
		}
	}

	if len(tpLost) > 0 {
		sound = "Basso"
		fmt.Printf("😭 Iteration lost %d true positives (now %d): %s\n", len(tpLost), len(res.TruePositive), strings.Join(tpLost, " "))
	}

	fpGained := []string{}
	for p := range res.FalsePositive {
		if last.TrueNegative[p] {
			fpGained = append(fpGained, p)
		}
	}
	if len(fpGained) > 0 {
		sound = "Sosumi"
		fmt.Printf("💣 Iteration added %d false positives (now %d): %s\n", len(fpGained), len(res.FalsePositive), strings.Join(fpGained, " "))
	}

	fpLost := []string{}
	for p := range res.TrueNegative {
		if last.FalsePositive[p] {
			fpLost = append(fpLost, p)
		}
	}

	if len(fpLost) > 0 {
		sound = "Funk"
		fmt.Printf("🎉 Iteration removed %d false positives - only %d remain!\n", len(fpLost), len(res.FalsePositive))
	}

	if playSound {
		playSoundBite(sound)
	}
}

func watchAndRunTests(tc TestConfig) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// run once
	firstRes, err := RunTest(tc)
	LogResult(firstRes)
	if err != nil {
		log.Printf("test failed: %v", err)
	}
	lastRes := firstRes
	var res Result

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					rules, err := compileRules(tc.RulePaths)
					if err != nil {
						log.Printf("failed to compile rules: %v", err)
						if tc.PlaySounds {
							playSoundBite("submarine")
						}
						continue
					}

					// The cache is based on the first run, and not renewed subsequently
					// to avoid missing flip-flops until our cache is rule-aware.

					tc.CachedReferenceHit = firstRes.TruePositive
					tc.CachedScanMiss = firstRes.TrueNegative

					// Don't cache hash failures
					for p := range res.FailedHashCheck {
						tc.CachedReferenceHit[p] = false
					}
					for p := range firstRes.FailedHashCheck {
						tc.CachedReferenceHit[p] = false
					}

					// cache-flush hack until the cache is truly rule aware
					if len(rules.GetRules()) > len(tc.Rules.GetRules()) {
						tc.CachedScanMiss = map[string]bool{}
					}
					if len(rules.GetRules()) < len(tc.Rules.GetRules()) {
						tc.CachedReferenceHit = map[string]bool{}
					}

					tc.Rules = rules
					res, err = RunTest(tc)

					LogResult(res)
					LogResultDiff(res, lastRes, tc.PlaySounds)
					lastRes = res
					if err != nil {
						log.Printf("failed: %v", err)
					}
					fmt.Printf("\n⏳ watching %d YARA rule paths for updates ...\n", len(tc.RulePaths))
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	fmt.Printf("\n⏳ watching %d YARA rule paths for updates ...\n", len(tc.RulePaths))
	for _, path := range tc.RulePaths {
		err = watcher.Add(path)
		if err != nil {
			log.Fatal(err)
		}
	}
	<-make(chan struct{})
	return nil
}

func compileRules(paths []string) (*yara.Rules, error) {
	yc, err := yara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara compiler: %w", err)
	}
	for _, path := range paths {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open: %w", err)
		}

		if err := yc.AddFile(f, path); err != nil {
			return nil, fmt.Errorf("yara addfile %s: %w", path, err)
		}
	}

	return yc.GetRules()
}

func main() {
	referenceFlag := flag.String("reference", "", "Malware reference file or directory that contains true positives")
	scanFlag := flag.String("scan", "", "File or directories to scan - can be : delimited")
	exitEarlyFlag := flag.Bool("exit-on-failure", false, "Exit immediately when an unexpected hit occurs")
	programsOnlyFlag := flag.Bool("programs-only", true, "Only scan programs, such as scripts & executables (based on magic)")
	excludeProgamTypesFlag := flag.String("exclude-program-types", "", "comma-separated kinds of programs to exclude (DOS, Windows, Java)")
	quietFlag := flag.Bool("quiet", false, "Quiet mode")
	watchFlag := flag.Bool("watch", false, "Watch for YARA rule changes and rescan")
	addHashesFlag := flag.Bool("add-hashes", false, "Add true positive hashes to YARA rules")
	hashMaxFlag := flag.Int("hash-max", 8, "Do not add more than this many true positive hashes to any YARA rule")
	soundFlag := flag.Bool("sound", true, "Play success/fail sounds (currently macOS only)")
	flag.Parse()
	args := flag.Args()

	if len(args) == 0 {
		fmt.Printf("usage: yaratest [flags] <yara paths>\n")
		os.Exit(2)
	}

	rules, err := compileRules(args)
	if err != nil {
		log.Printf("rules: %v", err)
		os.Exit(3)
	}

	tc := TestConfig{
		ScanPaths:           strings.Split(*scanFlag, ":"),
		ReferencePaths:      strings.Split(*referenceFlag, ":"),
		RulePaths:           args,
		Rules:               rules,
		ExitOnFailure:       *exitEarlyFlag,
		ProgramsOnly:        *programsOnlyFlag,
		ExcludeProgramKinds: strings.Split(*excludeProgamTypesFlag, ","),
		PlaySounds:          *soundFlag,
		Quiet:               *quietFlag,
	}

	if *watchFlag {
		err := watchAndRunTests(tc)
		if err != nil {
			log.Printf("watch and run failed: %v", err)
			os.Exit(1)
		}

	}

	res, err := RunTest(tc)
	LogResult(res)

	if err != nil {
		log.Printf("failed: %v", err)
		os.Exit(1)
	}

	if *addHashesFlag {
		updateRules(args, res.NewHashMatches, *hashMaxFlag)
	}
}
