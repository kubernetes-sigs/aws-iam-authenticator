package arn

import (
	"fmt"
	"regexp"
	"strings"
)

const (
	arnDelimiter        = ":"
	arnSectionsExpected = 6
	arnPrefix           = "arn:"

	// zero-indexed
	sectionPartition = 1
	sectionService   = 2
	sectionRegion    = 3
	sectionAccountID = 4
	sectionResource  = 5

	// errors
	invalidPrefix   = "invalid prefix"
	invalidSections = "not enough sections"
)

// ArnLike takes an ARN and returns true if it is matched by the pattern.
// Each component of the ARN is matched individually as per
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html#Conditions_ARN
func ArnLike(arn, pattern string) (bool, error) {
	// "parse" the input arn into sections
	arnSections, err := parse(arn)
	if err != nil {
		return false, fmt.Errorf("Could not parse input arn: %v", err)
	}
	patternSections, err := parse(pattern)
	if err != nil {
		return false, fmt.Errorf("Could not parse ArnLike string: %v", err)
	}

	// Tidy regexp special characters. Escape the ones not used in ArnLike.
	// Replace multiple * with .* - we're assuming `\` is not allowed in ARNs
	preparePatternSections(patternSections)

	for index := range arnSections {
		patternGlob, err := regexp.Compile(patternSections[index])
		if err != nil {
			return false, fmt.Errorf("Could not parse %s: %v", patternSections[index], err)
		}

		if !patternGlob.MatchString(arnSections[index]) {
			return false, nil
		}
	}

	return true, nil
}

// parse is a copy of arn.Parse from the AWS SDK but represents the ARN as []string
func parse(input string) ([]string, error) {
	if !strings.HasPrefix(input, arnPrefix) {
		return nil, fmt.Errorf(invalidPrefix)
	}
	arnSections := strings.SplitN(input, arnDelimiter, arnSectionsExpected)
	if len(arnSections) != arnSectionsExpected {
		return nil, fmt.Errorf(invalidSections)
	}

	return arnSections, nil
}

// preparePatternSections goes through each section of the arnLike slice and escapes any meta characters, except for
// `*` and `?` which are replaced by `.*` and `.?` respectively. ^ and $ are added as we require an exact match
func preparePatternSections(arnLikeSlice []string) {
	for index, section := range arnLikeSlice {
		quotedString := quoteMeta(section)
		arnLikeSlice[index] = `^` + quotedString + `$`
	}
}

// the below is based on regexp.QuoteMeta to escape metacharacters except for `?` and `*`, changing them to `*` and `.*`

// quoteMeta returns a string that escapes all regular expression metacharacters
// inside the argument text; the returned string is a regular expression matching
// the literal text.
func quoteMeta(s string) string {
	const specialChars = `\.+()|[]{}^$`

	var i int
	b := make([]byte, 2*len(s)-i)
	copy(b, s[:i])
	j := i
	for ; i < len(s); i++ {
		if strings.Contains(specialChars, s[i:i+1]) {
			b[j] = '\\'
			j++
		} else if s[i] == '*' || s[i] == '?' {
			b[j] = '.'
			j++
		}
		b[j] = s[i]
		j++
	}
	return string(b[:j])
}
