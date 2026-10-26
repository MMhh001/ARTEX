package db

import (
	"errors"
	"testing"
)

func TestNormalizeTaskModes(t *testing.T) {
	tests := []struct {
		name, profile, access, coordination string
		wantAccess, wantCoordination        string
		wantErr                             bool
	}{
		{name: "legacy pentest", wantAccess: AccessModeStandard, wantCoordination: CoordinationModeOrchestrated},
		{name: "legacy research", profile: VulnerabilityAgentProfileKey, wantAccess: AccessModeSourceAssisted, wantCoordination: CoordinationModeOrchestrated},
		{name: "u agent", profile: VulnerabilityAgentProfileKey, access: AccessModeUnauthenticated, coordination: CoordinationModeOrchestrated, wantAccess: AccessModeUnauthenticated, wantCoordination: CoordinationModeOrchestrated},
		{name: "u agent requires research profile", profile: DefaultAgentProfileKey, access: AccessModeUnauthenticated, wantErr: true},
		{name: "future collaboration remains closed", profile: VulnerabilityAgentProfileKey, access: AccessModeUnauthenticated, coordination: "collaborative", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			access, coordination, err := NormalizeTaskModes(tt.profile, tt.access, tt.coordination)
			if tt.wantErr {
				if !errors.Is(err, ErrTaskModeInvalid) {
					t.Fatalf("err=%v, want ErrTaskModeInvalid", err)
				}
				return
			}
			if err != nil || access != tt.wantAccess || coordination != tt.wantCoordination {
				t.Fatalf("got access=%q coordination=%q err=%v", access, coordination, err)
			}
		})
	}
}
