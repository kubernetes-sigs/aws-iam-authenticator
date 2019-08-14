package version // import "go.hein.dev/go-version"

import (
	"encoding/json"
	"fmt"

	"sigs.k8s.io/yaml"
)

var (
	// JSON returns json so that we can change the output
	JSON = "json"
	// YAML returns yaml so that we can change the output
	YAML = "yaml"
)

// Info creates a formattable struct for output
type Info struct {
	Version string `json:"Version,omitempty"`
	Commit  string `json:"Commit,omitempty"`
	Date    string `json:"Date,omitempty"`
}

// New will create a pointer to a new version object
func New(version string, commit string, date string) *Info {
	return &Info{
		Version: version,
		Commit:  commit,
		Date:    date,
	}
}

// Func will return the versioning code with only JSON and raw text support
func Func(shortened bool, version, commit, date string) string {
	return FuncWithOutput(shortened, version, commit, date, JSON)
}

// FuncWithOutput will add the versioning code
func FuncWithOutput(shortened bool, version, commit, date, output string) string {
	var response string
	versionOutput := New(version, commit, date)

	if shortened {
		response = versionOutput.ToShortened()
	} else {
		switch output {
		case YAML:
			response = versionOutput.ToYAML()
		case JSON:
			response = versionOutput.ToJSON()
		default: // JSON as the default
			response = versionOutput.ToJSON()
		}
	}
	return fmt.Sprintf("%s", response)
}

// ToJSON converts the Info into a JSON String
func (v *Info) ToJSON() string {
	bytes, _ := json.Marshal(v)
	return string(bytes) + "\n"
}

// ToYAML converts the Info into a JSON String
func (v *Info) ToYAML() string {
	bytes, _ := yaml.Marshal(v)
	return string(bytes)
}

// ToShortened converts the Info into a JSON String
func (v *Info) ToShortened() string {
	return v.ToYAML()
}

func deleteEmpty(s []string) []string {
	var r []string
	for _, str := range s {
		if str != "" {
			r = append(r, str)
		}
	}
	return r
}
