package ui

import (
	"testing"

	"github.com/GitHubSecurityLab/gh-secure/internal/security"
)

// TestFeatureGuidanceCoversRegistry keeps every registered feature's plan
// explanation and documentation link from rendering blank.
func TestFeatureGuidanceCoversRegistry(t *testing.T) {
	for _, feature := range security.Features() {
		guidance := featureGuidance[feature.Name]
		if guidance.why == "" || guidance.docs == "" {
			t.Errorf("feature %q lacks guidance: %+v", feature.Name, guidance)
		}
	}
}
