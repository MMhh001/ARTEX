package db

import (
	"errors"
	"fmt"
	"strings"
)

const (
	AccessModeStandard        = "standard"
	AccessModeSourceAssisted  = "source_assisted"
	AccessModeUnauthenticated = "unauthenticated"

	CoordinationModeOrchestrated = "orchestrated"
)

var ErrTaskModeInvalid = errors.New("invalid task mode")

// NormalizeTaskModes validates the two task-level execution dimensions. Agent
// Profile selects the four concrete agents; access mode narrows what evidence
// and authentication state they may use; coordination mode describes how those
// four roles cooperate. Only the existing orchestrated coordination is enabled
// in this release. Blank values preserve the old behavior.
func NormalizeTaskModes(profileKey, accessMode, coordinationMode string) (string, string, error) {
	profileKey = NormalizeAgentProfileKey(profileKey)
	accessMode = strings.TrimSpace(strings.ToLower(accessMode))
	coordinationMode = strings.TrimSpace(strings.ToLower(coordinationMode))
	if accessMode == "" {
		if profileKey == VulnerabilityAgentProfileKey {
			accessMode = AccessModeSourceAssisted
		} else {
			accessMode = AccessModeStandard
		}
	}
	if coordinationMode == "" {
		coordinationMode = CoordinationModeOrchestrated
	}

	switch accessMode {
	case AccessModeStandard:
		if profileKey == VulnerabilityAgentProfileKey {
			return "", "", fmt.Errorf("%w: vulnerability research requires source_assisted or unauthenticated access", ErrTaskModeInvalid)
		}
	case AccessModeSourceAssisted, AccessModeUnauthenticated:
		if profileKey != VulnerabilityAgentProfileKey {
			return "", "", fmt.Errorf("%w: %s access requires the vulnerability research profile", ErrTaskModeInvalid, accessMode)
		}
	default:
		return "", "", fmt.Errorf("%w: unknown access mode %q", ErrTaskModeInvalid, accessMode)
	}
	if coordinationMode != CoordinationModeOrchestrated {
		return "", "", fmt.Errorf("%w: coordination mode %q is not available yet", ErrTaskModeInvalid, coordinationMode)
	}
	return accessMode, coordinationMode, nil
}
