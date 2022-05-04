package arn

import (
	"strings"
	"testing"
)

type arnLikeInput struct {
	arn, pattern string
}

type quoteMetaInput struct {
	input, expected string
}

func TestArnLikePostiveMatches(t *testing.T) {
	inputs := []arnLikeInput{
		{
			arn:     `arn:aws:iam::000000000000:role/some-role`,
			pattern: `arn:aws:iam::000000000000:role/some-role`,
		},
		{
			arn:     `arn:aws:iam::000000000000:role/some-role`,
			pattern: `arn:aws:iam::000000000000:*`,
		},
		{
			arn:     `arn:aws:iam::000000000000:role/some-role`,
			pattern: `arn:*:*:*:*:*`,
		},
		{
			arn:     `arn:aws:iam::000000000000:role/some-role`,
			pattern: `arn:aws:iam::000000000000:**`,
		},
		{
			arn:     `arn:aws:iam::000000000000:role/some-role`,
			pattern: `arn:aws:iam::000000000000:*role*`,
		},
		{
			arn:     `arn:aws:iam::000000000000:role/some-role`,
			pattern: `arn:aws:iam::000000000000:ro*`,
		},
		{
			arn:     `arn:aws:iam::000000000000:role/some-role`,
			pattern: `arn:aws:iam::000000000000:??????????????`,
		},
		{
			arn:     `arn:aws:testservice::000000000000:some/wacky-new-[resource]{with}\metacharacters`,
			pattern: `arn:aws:testservice::000000000000:some/wacky-new-[resource]{with}\metacharacters`,
		},
		{
			arn:     `arn:aws:testservice::000000000000:some/wacky-new-[resource]{with}\metacharacters`,
			pattern: `arn:aws:testservice::000000000000:some/wacky-new-[reso*`,
		},
	}

	for _, v := range inputs {
		ok, err := ArnLike(v.arn, v.pattern)
		if err != nil {
			t.Errorf("Expected no error for input arn: %s pattern: %s", v.arn, v.pattern)
		}

		if !ok {
			t.Errorf("Expected true for input arn: %s pattern: %s", v.arn, v.pattern)
		}
	}
}

func TestArnLikeNetagiveMatches(t *testing.T) {
	inputs := []arnLikeInput{
		{
			arn:     `arn:aws:iam::111111111111:role/some-role`,
			pattern: `arn:aws:iam::000000000000:role/some-role`,
		},
		{
			arn:     `arn:aws:testservice::000000000000:some/wacky:resource:with:colon:delims`,
			pattern: `arn:aws:testservice::**:delims`,
		},
	}

	for _, v := range inputs {
		ok, err := ArnLike(v.arn, v.pattern)
		if err != nil {
			t.Errorf("Expected no error for input arn: %s pattern: %s", v.arn, v.pattern)
		}

		if ok {
			t.Errorf("Expected false for input arn: %s pattern: %s", v.arn, v.pattern)
		}
	}
}

func TestArnLikeInvalidArns(t *testing.T) {
	invalidPrefixArn := `nar:aws:iam::000000000000:role/some-role`
	invalidSectionsArn := `arn:aws:iam:000000000000:role/some-role`
	validArn := `arn:aws:iam::000000000000:role/some-role`

	// invalid prefix
	ok, err := ArnLike(invalidPrefixArn, validArn)
	if ok {
		t.Errorf("Expected false result on error for input arn: %s, pattern: %s", invalidPrefixArn, validArn)
	}

	expectedErrorText := "Could not parse input arn: invalid prefix"
	if !strings.EqualFold(expectedErrorText, err.Error()) {
		t.Errorf("Did not receive expected error text. Expected: '%s', got: '%s'", expectedErrorText, err.Error())
	}

	// invalid sections
	ok, err = ArnLike(invalidSectionsArn, validArn)
	if ok {
		t.Errorf("Expected false result on error for input arn: %s, pattern: %s", invalidSectionsArn, validArn)
	}

	expectedErrorText = "Could not parse input arn: not enough sections"
	if !strings.EqualFold(expectedErrorText, err.Error()) {
		t.Errorf("Did not receive expected error text. Expected: '%s', got: '%s'", expectedErrorText, err.Error())
	}
}

func TestQuoteMeta(t *testing.T) {
	inputs := []quoteMetaInput{
		{
			input:    `**`,
			expected: `.*.*`,
		},
		{
			input:    `??`,
			expected: `.?.?`,
		},
		{
			input:    `abdcEFG`,
			expected: `abdcEFG`,
		},
		{
			input:    `abd.EFG`,
			expected: `abd\.EFG`,
		},
		{
			input:    `\.+()|[]{}^$`,
			expected: `\\\.\+\(\)\|\[\]\{\}\^\$`,
		},
		{
			input:    `\.+()|[]{}^$*?`,
			expected: `\\\.\+\(\)\|\[\]\{\}\^\$.*.?`,
		},
	}

	for _, v := range inputs {
		output := quoteMeta(v.input)
		if !strings.EqualFold(v.expected, output) {
			t.Errorf("Did not get expected output from quoteMeta. Expected: '%s', got: '%s'", v.expected, output)
		}
	}
}
