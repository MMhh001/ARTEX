package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

const (
	DefaultAgentProfileKey       = "pentest"
	VulnerabilityAgentProfileKey = "vuln_research"
)

var (
	ErrAgentProfileNotFound   = errors.New("agent profile not found")
	ErrAgentProfileIncomplete = errors.New("agent profile is incomplete")
)

// AgentProfileRoleKeys is the concrete Agent identity used for each fixed task
// engine role. The engine topology remains goals -> planner/worker + main.
type AgentProfileRoleKeys struct {
	Goals   string `json:"goals"`
	Planner string `json:"planner"`
	Worker  string `json:"worker"`
	Main    string `json:"main"`
}

func (r AgentProfileRoleKeys) Complete() bool {
	return r.Goals != "" && r.Planner != "" && r.Worker != "" && r.Main != ""
}

// AgentProfile is a selectable task execution preset.
type AgentProfile struct {
	Key                    string               `json:"key"`
	Name                   string               `json:"name"`
	Description            string               `json:"description"`
	Builtin                bool                 `json:"builtin"`
	DefaultCoverageEnabled bool                 `json:"default_coverage_enabled"`
	Roles                  AgentProfileRoleKeys `json:"roles"`
}

func NormalizeAgentProfileKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return DefaultAgentProfileKey
	}
	return key
}

func scanAgentProfile(sc interface{ Scan(...any) error }) (*AgentProfile, error) {
	var p AgentProfile
	err := sc.Scan(&p.Key, &p.Name, &p.Description, &p.Builtin, &p.DefaultCoverageEnabled,
		&p.Roles.Goals, &p.Roles.Planner, &p.Roles.Worker, &p.Roles.Main)
	if err != nil {
		return nil, err
	}
	if !p.Roles.Complete() {
		return nil, fmt.Errorf("%w: %s", ErrAgentProfileIncomplete, p.Key)
	}
	return &p, nil
}

const agentProfileSelect = `
SELECT p.key,p.name,p.description,p.builtin,p.default_coverage_enabled,
       COALESCE(MAX(r.agent_key) FILTER (WHERE r.role='goals'),''),
       COALESCE(MAX(r.agent_key) FILTER (WHERE r.role='planner'),''),
       COALESCE(MAX(r.agent_key) FILTER (WHERE r.role='worker'),''),
       COALESCE(MAX(r.agent_key) FILTER (WHERE r.role='main'),'')
FROM agent_profiles p
LEFT JOIN agent_profile_roles r ON r.profile_key=p.key`

func (d *DB) AgentProfileByKey(key string) (*AgentProfile, error) {
	key = NormalizeAgentProfileKey(key)
	p, err := scanAgentProfile(d.QueryRow(agentProfileSelect+` WHERE p.key=$1 GROUP BY p.key,p.name,p.description,p.builtin,p.default_coverage_enabled`, key))
	if err == sql.ErrNoRows {
		return nil, ErrAgentProfileNotFound
	}
	return p, err
}

func (d *DB) ListAgentProfiles() ([]*AgentProfile, error) {
	rows, err := d.Query(agentProfileSelect + ` GROUP BY p.key,p.name,p.description,p.builtin,p.default_coverage_enabled ORDER BY p.builtin DESC,p.key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*AgentProfile{}
	for rows.Next() {
		p, err := scanAgentProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// seedAgentProfiles runs after seedBuiltins, so every role mapping can safely
// reference its concrete Agent row. Upserts keep shipped profiles authoritative.
func (d *DB) seedAgentProfiles() error {
	profiles := []struct {
		key, name, description string
		coverage               bool
		roles                  AgentProfileRoleKeys
	}{
		{DefaultAgentProfileKey, "渗透测试", "现有授权渗透测试编排：目标拆解、规划、执行与主 Agent。", true,
			AgentProfileRoleKeys{Goals: "goals", Planner: "planner", Worker: "worker", Main: "mainagent"}},
		{VulnerabilityAgentProfileKey, "漏洞挖掘", "面向源码、版本与本地制品的漏洞研究、复现与证据沉淀。", false,
			AgentProfileRoleKeys{Goals: "vuln_goals", Planner: "vuln_planner", Worker: "vuln_worker", Main: "vuln_mainagent"}},
	}
	for _, profile := range profiles {
		if _, err := d.Exec(`INSERT INTO agent_profiles(key,name,description,builtin,default_coverage_enabled)
VALUES ($1,$2,$3,true,$4)
ON CONFLICT (key) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,builtin=true,default_coverage_enabled=EXCLUDED.default_coverage_enabled`,
			profile.key, profile.name, profile.description, profile.coverage); err != nil {
			return err
		}
		roles := map[string]string{"goals": profile.roles.Goals, "planner": profile.roles.Planner, "worker": profile.roles.Worker, "main": profile.roles.Main}
		for role, agentKey := range roles {
			if _, err := d.Exec(`INSERT INTO agent_profile_roles(profile_key,role,agent_key) VALUES ($1,$2,$3)
ON CONFLICT (profile_key,role) DO UPDATE SET agent_key=EXCLUDED.agent_key`, profile.key, role, agentKey); err != nil {
				return fmt.Errorf("profile %s role %s: %w", profile.key, role, err)
			}
		}
	}
	return nil
}
