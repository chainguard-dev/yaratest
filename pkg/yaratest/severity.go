package yaratest

import (
	"strings"

	"github.com/hillu/go-yara/v4"
)

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
