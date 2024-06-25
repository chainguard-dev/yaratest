package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/VirusTotal/gyp"
	"github.com/VirusTotal/gyp/ast"
	"github.com/chainguard-dev/yato/pkg/yaratest"
	"github.com/fsnotify/fsnotify"
	"github.com/hillu/go-yara/v4"
)

var (
	notAlpha   = regexp.MustCompile(`\W+`)
	multiUnder = regexp.MustCompile(`_+`)
)

func humanReadableHashName(m yaratest.Match, rules []*ast.Rule) string {

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

func updateRuleFile(path string, ms map[string][]yaratest.Match, maxRules int, removeHashes bool) error {
	if len(ms) == 0 && !removeHashes {
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
	f.Close()

	updated := 0
	rules := 0

	for _, r := range rs.Rules {
		hashes := 0
		rules++

		newMeta := []*ast.Meta{}
		for _, m := range r.Meta {
			if strings.HasPrefix(m.Key, "hash") {
				if removeHashes {
					updated++
					continue
				}
				hashes++
			}
			newMeta = append(newMeta, m)
		}

		for _, update := range ms[r.Identifier] {
			// We will never delete hashes, but we can refuse to add more
			if hashes >= maxRules {
				log.Printf("%s has %d hashes - won't add %s from %s", r.Identifier, hashes, update.SHA256, update.Path)
				break
			}
			key := humanReadableHashName(update, rs.Rules)
			log.Printf("adding %s=%q to %s", key, update.SHA256, r.Identifier)
			newMeta = append(newMeta, &ast.Meta{Key: key, Value: update.SHA256})
			hashes++
			updated++
		}

		r.Meta = newMeta
	}

	if updated == 0 {
		return nil
	}

	// write to temp buffer to see if it avoids weird data corruption issues we've seen
	var b bytes.Buffer
	w := bufio.NewWriter(&b)
	if err = rs.WriteSource(w); err != nil {
		log.Fatalf(`Error writing rules: %v`, err)
	}
	w.Flush()

	bs := b.Bytes()
	if len(bs) == 0 {
		log.Fatalf("0 bytes for %s? %d len? rs: %+v - %d rules", path, b.Len(), rs, rules)
	}
	log.Printf("writing %d bytes to: %s", len(bs), path)
	return os.WriteFile(path, bs, 0o644)
}

func updateRules(paths []string, matches []yaratest.Match, maxNum int, removeHashes bool) error {
	updates := map[string][]yaratest.Match{}
	for _, m := range matches {
		updates[m.RuleName] = append(updates[m.RuleName], m)
	}

	for _, path := range paths {
		if err := updateRuleFile(path, updates, maxNum, removeHashes); err != nil {
			return err
		}
	}

	return nil
}

func LogResult(res *yaratest.Result) {
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

func LogResultDiff(res *yaratest.Result, last *yaratest.Result, playSound bool) {
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

func watchAndRunTests(c yaratest.Config) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()

	// run once
	firstRes, err := yaratest.Scan(c)
	LogResult(firstRes)
	if err != nil {
		log.Printf("test failed: %v", err)
	}
	lastRes := firstRes
	var res *yaratest.Result

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					rules, err := compileRules(c.RulePaths)
					if err != nil {
						log.Printf("failed to compile rules: %v", err)
						if c.PlaySounds {
							playSoundBite("submarine")
						}
						continue
					}

					if len(c.Tags) > 0 {
						disableUnwantedRules(rules, c.Tags)
					}

					// The cache is based on the first run, and not renewed subsequently
					// to avoid missing flip-flops until our cache is rule-aware.

					c.CachedReferenceHit = firstRes.TruePositive
					c.CachedScanMiss = firstRes.TrueNegative

					// Don't cache hash failures
					for p := range firstRes.FailedHashCheck {
						c.CachedReferenceHit[p] = false
					}
					for p := range firstRes.FailedHashCheck {
						c.CachedReferenceHit[p] = false
					}

					// cache-flush hack until the cache is truly rule aware
					if len(rules.GetRules()) > len(c.Rules.GetRules()) {
						c.CachedScanMiss = map[string]bool{}
					}
					if len(rules.GetRules()) < len(c.Rules.GetRules()) {
						c.CachedReferenceHit = map[string]bool{}
					}

					c.Rules = rules
					res, err = yaratest.Scan(c)

					LogResult(res)
					LogResultDiff(res, lastRes, c.PlaySounds)
					lastRes = res
					if err != nil {
						log.Printf("failed: %v", err)
					}
					fmt.Printf("\n⏳ watching %d YARA rule paths for updates ...\n", len(c.RulePaths))
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("error:", err)
			}
		}
	}()

	fmt.Printf("\n⏳ watching %d YARA rule paths for updates ...\n", len(c.RulePaths))
	for _, path := range c.RulePaths {
		err = watcher.Add(path)
		if err != nil {
			log.Fatal(err)
		}
	}
	<-make(chan struct{})
	return nil
}

func disableUnwantedRules(rules *yara.Rules, tags []string) {
	want := map[string]bool{}
	for _, t := range tags {
		want[t] = true
	}

	// disable rules that don't watch our rules
	for _, r := range rules.GetRules() {
		wanted := false
		for _, t := range r.Tags() {
			if want[t] {
				wanted = true
			}
		}
		if !wanted {
			log.Printf("disabling %s/%s", r.Namespace(), r.Identifier())
			r.Disable()
		}
	}
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
	tagsFlag := flag.String("tags", "", "YARA tags to filter by")
	addHashesFlag := flag.Bool("add-hashes", false, "Add true positive hashes to YARA rules")
	removeHashesFlag := flag.Bool("remove-hashes", false, "Remove hashes from YARA rules")
	hashMaxFlag := flag.Int("hash-max", 3, "Do not add more than this many true positive hashes to any YARA rule")
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

	if *tagsFlag != "" {
		disableUnwantedRules(rules, strings.Split(*tagsFlag, ","))
	}

	tc := yaratest.Config{
		ScanPaths:           strings.Split(*scanFlag, ":"),
		ReferencePaths:      strings.Split(*referenceFlag, ":"),
		RulePaths:           args,
		Rules:               rules,
		Tags:                strings.Split(*tagsFlag, ","),
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

	res, err := yaratest.Scan(tc)
	LogResult(res)

	if err != nil {
		log.Printf("failed: %v", err)
		os.Exit(1)
	}

	if *addHashesFlag || *removeHashesFlag {
		if err := updateRules(args, res.NewHashMatches, *hashMaxFlag, *removeHashesFlag); err != nil {
			log.Printf("Failed to update: %v", err)
			os.Exit(2)
		}
	}
}
