// Package security defines repository security features and their canonical order.
package security

import (
	"fmt"
	"slices"
)

// Feature identifies a security feature group by its canonical command-line name.
type Feature string

const (
	// BranchProtection identifies legacy protection for the default branch.
	BranchProtection Feature = "branch-protection"
	// VulnerabilityReporting identifies private vulnerability reporting.
	VulnerabilityReporting Feature = "vulnerability-reporting"
	// SecretScanning identifies secret scanning push protection.
	SecretScanning Feature = "secret-scanning"
	// Dependabot groups vulnerability alerts and automated security updates.
	Dependabot Feature = "dependabot"
	// CodeScanning identifies CodeQL default setup.
	CodeScanning Feature = "code-scanning"
)

// FeatureDefinition describes a feature's command-line names and help text.
type FeatureDefinition struct {
	// Name is the canonical feature name.
	Name Feature
	// Alias is the shorthand accepted in place of Name.
	Alias string
	// Description explains the feature in command help.
	Description string
}

var featureRegistry = []FeatureDefinition{
	{BranchProtection, "bp", "Protect the default branch"},
	{VulnerabilityReporting, "vr", "Allow private vulnerability reports"},
	{SecretScanning, "ss", "Enable secret scanning push protection"},
	{Dependabot, "dep", "Enable alerts and security updates (not version updates)"},
	{CodeScanning, "cs", "Configure CodeQL default setup"},
}

// Features returns a copy of the feature registry in canonical execution order.
func Features() []FeatureDefinition {
	return slices.Clone(featureRegistry)
}

// SelectFeatures resolves names and aliases, deduplicating them in canonical order.
// An empty selection includes all features; an unknown name returns an error
// without a partial selection.
func SelectFeatures(names []string) ([]Feature, error) {
	selected := make(map[Feature]bool, len(names))
	for _, name := range names {
		found := false
		for _, feature := range featureRegistry {
			if name == string(feature.Name) || name == feature.Alias {
				selected[feature.Name] = true
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown feature %q", name)
		}
	}

	result := make([]Feature, 0, len(featureRegistry))
	for _, feature := range featureRegistry {
		if len(names) == 0 || selected[feature.Name] {
			result = append(result, feature.Name)
		}
	}
	return result, nil
}
