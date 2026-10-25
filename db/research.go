package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var ErrInvalidHypothesis = errors.New("invalid vulnerability hypothesis")

var hypothesisStates = map[string]bool{
	"suspected": true, "reachable": true, "controllable": true,
	"boundary_broken": true, "reproduced": true,
	"independently_reproduced": true, "rejected": true, "blocked": true,
}

var hypothesisFields = map[string]bool{
	"title": true, "hypothesis": true, "entry": true,
	"attacker_controlled_input": true, "call_chain": true,
	"trust_boundary": true, "sink": true, "evidence": true,
	"counterevidence": true, "next_step": true,
	"evidence_node_ids": true, "asset_ids": true,
}

// CreateHypothesis stores a structured research hypothesis in the task graph.
func (s *ExplorationStore) CreateHypothesis(payload map[string]any) (int64, error) {
	if strings.TrimSpace(stringValue(payload["title"])) == "" || strings.TrimSpace(stringValue(payload["hypothesis"])) == "" {
		return 0, fmt.Errorf("%w: title and hypothesis are required", ErrInvalidHypothesis)
	}
	if err := validateHypothesisPayload(payload); err != nil {
		return 0, err
	}
	return s.AddNode(KindHypothesis, payload, 5, "suspected", "vuln_research", nil)
}

// UpdateHypothesis merges structured evidence and advances the maturity state.
// Reaching reproduced atomically creates exactly one independent-review intent.
// independently_reproduced is accepted only from the system-created review intent.
func (s *ExplorationStore) UpdateHypothesis(id int64, patch map[string]any, state string, verifierIntentID int64) (int64, error) {
	if id <= 0 {
		return 0, fmt.Errorf("%w: hypothesis_id is required", ErrInvalidHypothesis)
	}
	if state != "" && !hypothesisStates[state] {
		return 0, fmt.Errorf("%w: unsupported maturity state %q", ErrInvalidHypothesis, state)
	}
	for key := range patch {
		if !hypothesisFields[key] {
			return 0, fmt.Errorf("%w: field %q cannot be updated", ErrInvalidHypothesis, key)
		}
	}
	if err := validateHypothesisPayload(patch); err != nil {
		return 0, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	var raw []byte
	var currentState string
	err = tx.QueryRow(`SELECT payload, state FROM exploration_nodes
		WHERE id=$1 AND exploration_id=$2 AND kind=$3 FOR UPDATE`, id, s.expID, KindHypothesis).Scan(&raw, &currentState)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("hypothesis #%d not found in this task", id)
	}
	if err != nil {
		return 0, err
	}
	merged := map[string]any{}
	if err := json.Unmarshal(raw, &merged); err != nil {
		return 0, err
	}
	for key, value := range patch {
		merged[key] = value
	}
	if state == "" {
		state = currentState
	}
	if state == "independently_reproduced" {
		var valid bool
		if verifierIntentID > 0 {
			err = tx.QueryRow(`SELECT EXISTS(
				SELECT 1 FROM exploration_nodes
				WHERE id=$1 AND exploration_id=$2 AND kind='intent' AND state IN ('running','done')
				  AND origin='system_review'
				  AND payload->>'work_mode'='independent_verification'
				  AND payload->>'hypothesis_id'=$3
			)`, verifierIntentID, s.expID, fmt.Sprint(id)).Scan(&valid)
			if err != nil {
				return 0, err
			}
		}
		if !valid {
			return 0, fmt.Errorf("%w: independently_reproduced requires the system-created review intent for this hypothesis", ErrInvalidHypothesis)
		}
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		return 0, err
	}
	if len(encoded) > 128*1024 {
		return 0, fmt.Errorf("%w: payload exceeds 128 KB", ErrInvalidHypothesis)
	}
	if _, err := tx.Exec(`UPDATE exploration_nodes SET payload=$1, state=$2, content_version=content_version+1
		WHERE id=$3 AND exploration_id=$4 AND kind=$5`, jsonbClean(encoded), state, id, s.expID, KindHypothesis); err != nil {
		return 0, err
	}

	var reviewIntentID int64
	if state == "reproduced" {
		reviewIntentID, err = ensureIndependentReviewTx(tx, s.expID, id, merged)
		if err != nil {
			return 0, err
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return reviewIntentID, nil
}

func ensureIndependentReviewTx(tx *sql.Tx, explorationID, hypothesisID int64, payload map[string]any) (int64, error) {
	var id int64
	err := tx.QueryRow(`SELECT id FROM exploration_nodes
		WHERE exploration_id=$1 AND kind='intent' AND origin='system_review'
		  AND payload->>'work_mode'='independent_verification'
		  AND payload->>'hypothesis_id'=$2
		ORDER BY id LIMIT 1`, explorationID, fmt.Sprint(hypothesisID)).Scan(&id)
	if err == nil {
		return id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	title := strings.TrimSpace(stringValue(payload["title"]))
	if title == "" {
		title = strings.TrimSpace(stringValue(payload["hypothesis"]))
	}
	reviewPayload := map[string]any{
		"summary":       fmt.Sprintf("独立复核漏洞假设 #%d：%s", hypothesisID, title),
		"work_mode":     "independent_verification",
		"hypothesis_id": hypothesisID,
	}
	if assets, ok := payload["asset_ids"]; ok {
		reviewPayload["asset_ids"] = assets
	}
	encoded, err := json.Marshal(reviewPayload)
	if err != nil {
		return 0, err
	}
	if err := tx.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
		VALUES ($1,$2,$3,10,'open','system_review') RETURNING id`, explorationID, KindIntent, jsonbClean(encoded)).Scan(&id); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(`INSERT INTO exploration_edges(exploration_id,src_id,rel,dst_id)
		VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, explorationID, hypothesisID, RelDerivedFrom, id); err != nil {
		return 0, err
	}
	return id, nil
}

func (s *ExplorationStore) SaveResearchCheckpoint(payload map[string]any) (int64, error) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return 0, err
	}
	if len(encoded) > 128*1024 {
		return 0, fmt.Errorf("research checkpoint exceeds 128 KB")
	}
	var id int64
	err = s.db.QueryRow(`INSERT INTO exploration_nodes(exploration_id,kind,payload,priority,state,origin)
		VALUES ($1,$2,$3,0,'active','planner')
		ON CONFLICT (exploration_id) WHERE kind='checkpoint'
		DO UPDATE SET payload=EXCLUDED.payload, content_version=exploration_nodes.content_version+1
		RETURNING id`, s.expID, KindCheckpoint, jsonbClean(encoded)).Scan(&id)
	return id, err
}

func (s *ExplorationStore) ResearchCheckpoint() (*Node, error) {
	return s.GetNodeByKind(KindCheckpoint)
}

func (s *ExplorationStore) GetNodeByKind(kind string) (*Node, error) {
	n, err := scanNode(s.db.QueryRow(`SELECT `+nodeCols+` FROM exploration_nodes
		WHERE exploration_id=$1 AND kind=$2 ORDER BY id DESC LIMIT 1`, s.expID, kind))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return n, err
}

func validateHypothesisPayload(payload map[string]any) error {
	for key, value := range payload {
		if key == "evidence_node_ids" || key == "asset_ids" {
			continue
		}
		if text, ok := value.(string); ok && len(text) > 32*1024 {
			return fmt.Errorf("%w: %s exceeds 32 KB", ErrInvalidHypothesis, key)
		}
	}
	return nil
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}
