package models

// CapabilityFusion summarizes declared and observed capabilities.
type CapabilityFusion struct {
	Declared           []string           `json:"declared"`
	Observed           []string           `json:"observed"`
	Matched            []string           `json:"matched"`
	Overreach          []string           `json:"overreach"`
	Underdeclare       []string           `json:"underdeclare"`
	ObservedConfidence map[string]float64 `json:"observed_confidence,omitempty"`
	Score              float64            `json:"score"`
	RiskScore          float64            `json:"risk_score"`
	RiskLevel          string             `json:"risk_level"`
	Blocked            bool               `json:"blocked"`
	BlockReasons       []string           `json:"block_reasons,omitempty"`
}
