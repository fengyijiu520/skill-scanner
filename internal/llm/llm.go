package llm

import (
"context"
"regexp"
)

// Client LLM 客户端接口
type Client interface {
AnalyzeCode(ctx context.Context, name, description, codeSummary string) (*AnalysisResult, error)
}

// AnalysisResult LLM 分析结果
type AnalysisResult struct {
StatedIntent      string     `json:"stated_intent"`
ActualBehavior    string     `json:"actual_behavior"`
IntentConsistency int        `json:"intent_consistency"`
Risks             []RiskItem `json:"risks"`
}

// RiskItem 风险项
type RiskItem struct {
Title       string `json:"title"`
Severity    string `json:"severity"`
Description string `json:"description"`
Evidence    string `json:"evidence"`
}

var jsonRegex = regexp.MustCompile(`(?s)\{.*\}`)

// extractJSON 从 LLM 回复中提取 JSON 内容
func extractJSON(s string) string {
match := jsonRegex.FindString(s)
if match != "" {
return match
}
return s
}

// NewDeepSeekClient 创建 DeepSeek 客户端
func NewDeepSeekClient(apiKey string) Client {
return &deepseekClient{apiKey: apiKey}
}

// NewMiniMaxClient 创建 MiniMax 客户端
func NewMiniMaxClient(groupID, apiKey string) Client {
return &minimaxClient{groupID: groupID, apiKey: apiKey}
}
