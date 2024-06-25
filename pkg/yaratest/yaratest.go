package yaratest

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/hillu/go-yara/v4"
)

type Match struct {
	Path     string
	SHA256   string
	RuleName string
}

type Severity struct {
	Score int
	Name  string

	MatchingRules   int
	MatchingStrings int
}

type Config struct {
	ReferencePaths      []string
	ScanPaths           []string
	RulePaths           []string
	Tags                []string
	Rules               *yara.Rules
	ProgramsOnly        bool
	ExcludeProgramKinds []string
	ExitOnFailure       bool
	Quiet               bool
	PlaySounds          bool

	CachedReferenceHit map[string]bool
	CachedScanMiss     map[string]bool

	expectedRulesForHash map[string][]string
	humanNameForHash     map[string]string
	expectedPositive     bool
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
