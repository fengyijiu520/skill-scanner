package models

// Report represents a scan report stored in the system.
type Report struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Team      string `json:"team"` // team of the user who created the report
	FileName  string `json:"file_name"`
	FilePath  string `json:"file_path"`
	CreatedAt int64  `json:"created_at"`
	// 旧的兼容字段
	FindingCount int               `json:"finding_count"`
	HighRisk     int               `json:"high_risk"`
	MediumRisk   int               `json:"medium_risk"`
	LowRisk      int               `json:"low_risk"`
	NoRisk       bool              `json:"no_risk"`
	Findings     []ReportFinding   `json:"findings,omitempty"`
	Capability   *CapabilityFusion `json:"capability,omitempty"`
	// 新的审查引擎字段
	BaseScore           float64            `json:"base_score"`
	CapabilityScore     float64            `json:"capability_score"`
	BaseWeight          float64            `json:"base_weight"`
	CapabilityWeight    float64            `json:"capability_weight"`
	Score               float64            `json:"score"`
	RiskLevel           string             `json:"risk_level"` // low, medium, high, critical
	P0Blocked           bool               `json:"p0_blocked"`
	P0Reasons           []string           `json:"p0_reasons"`
	WhitelistSuppressed int                `json:"whitelist_suppressed"`
	WhitelistByRule     map[string]int     `json:"whitelist_by_rule,omitempty"`
	ItemScores          map[string]float64 `json:"item_scores"`
	LLMStatedIntent     string             `json:"llm_stated_intent,omitempty"`
	LLMActualBehavior   string             `json:"llm_actual_behavior,omitempty"`
	LLMIntentConfidence int                `json:"llm_intent_confidence,omitempty"`
}

type ReportFinding struct {
	PluginName  string `json:"plugin_name"`
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	CodeSnippet string `json:"code_snippet,omitempty"`
}
