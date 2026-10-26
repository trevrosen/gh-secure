package security

import (
	"reflect"
	"testing"
)

// TestSelectFeatures checks defaults, canonical ordering, and deduplication.
func TestSelectFeatures(t *testing.T) {
	all := []Feature{BranchProtection, VulnerabilityReporting, SecretScanning, Dependabot, CodeScanning}
	tests := []struct {
		name  string
		input []string
		want  []Feature
	}{
		{"default all", nil, all},
		{"long names reversed", []string{"code-scanning", "dependabot", "secret-scanning", "vulnerability-reporting", "branch-protection"}, all},
		{"aliases reversed", []string{"cs", "dep", "ss", "vr", "bp"}, all},
		{"mixed duplicates", []string{"cs", "bp", "branch-protection", "code-scanning", "dep", "dep"}, []Feature{BranchProtection, Dependabot, CodeScanning}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := SelectFeatures(test.input)
			if err != nil || !reflect.DeepEqual(got, test.want) {
				t.Fatalf("SelectFeatures(%v) = %v, %v; want %v", test.input, got, err, test.want)
			}
		})
	}
}

// TestFeatureNamesAndAliases checks every supported spelling independently.
func TestFeatureNamesAndAliases(t *testing.T) {
	tests := []struct {
		name  string
		alias string
		want  Feature
	}{
		{"branch-protection", "bp", BranchProtection},
		{"vulnerability-reporting", "vr", VulnerabilityReporting},
		{"secret-scanning", "ss", SecretScanning},
		{"dependabot", "dep", Dependabot},
		{"code-scanning", "cs", CodeScanning},
	}
	for _, test := range tests {
		for _, name := range []string{test.name, test.alias} {
			t.Run(name, func(t *testing.T) {
				got, err := SelectFeatures([]string{name})
				if err != nil || !reflect.DeepEqual(got, []Feature{test.want}) {
					t.Fatalf("SelectFeatures(%q) = %v, %v", name, got, err)
				}
			})
		}
	}
}

// TestUnknownFeature checks that invalid names do not produce partial selections.
func TestUnknownFeature(t *testing.T) {
	for _, name := range []string{"", "BP", "status", "unknown", "--yes"} {
		t.Run(name, func(t *testing.T) {
			got, err := SelectFeatures([]string{"bp", name})
			if err == nil || got != nil {
				t.Fatalf("SelectFeatures must reject %q without returning a partial selection: %v, %v", name, got, err)
			}
		})
	}
}

// TestRegistryCannotBeMutatedByCaller checks that registry copies are independent.
func TestRegistryCannotBeMutatedByCaller(t *testing.T) {
	features := Features()
	features[0].Name = "changed"
	if Features()[0].Name != BranchProtection {
		t.Fatal("caller mutated the canonical registry")
	}
}
