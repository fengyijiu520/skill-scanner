package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"skill-scanner/internal/config"
)

type sample struct {
	ID              string  `json:"id"`
	LabelRisk       bool    `json:"label_risk"`
	BaseScore       float64 `json:"base_score"`
	CapabilityScore float64 `json:"capability_score"`
}

type fpSample struct {
	ID          string `json:"id"`
	RuleID      string `json:"rule_id"`
	FilePath    string `json:"file_path"`
	Line        string `json:"line"`
	Context     string `json:"context"`
	ShouldAlert bool   `json:"should_alert"`
}

type confusion struct {
	TP int
	FP int
	TN int
	FN int
}

type metrics struct {
	Precision float64
	Recall    float64
	F1        float64
	Support   int
	Conf      confusion
}

type fpEvalResult struct {
	Support             int
	FPBefore            int
	FPAfter             int
	SuppressedFP        int
	SuppressedTotal     int
	BeforeByRule        map[string]int
	AfterByRule         map[string]int
	SuppressedByRule    map[string]int
	SuppressedFPByRule  map[string]int
	MissingRuleSamples  int
	NonPatternRuleCount int
}

func main() {
	input := flag.String("input", "data/benchmarks/r3_eval_samples.json", "R3 评估样本 JSON 路径")
	fpInput := flag.String("fp-input", "data/benchmarks/precision_false_positive_set.json", "Precision 误报样本 JSON 路径")
	rulesPath := flag.String("rules", "config/rules.yaml", "规则配置路径")
	threshold := flag.Float64("threshold", 60, "风险判定阈值（score < threshold 视为风险）")
	baseWeight := flag.Float64("base-weight", 0.65, "增强模型基线分权重")
	capWeight := flag.Float64("capability-weight", 0.35, "增强模型能力分权重")
	flag.Parse()

	samples, err := loadSamples(*input)
	if err != nil {
		fmt.Printf("加载样本失败: %v\n", err)
		os.Exit(1)
	}
	if len(samples) == 0 {
		fmt.Println("样本为空，无法评估")
		os.Exit(1)
	}

	bw, cw := normalizeWeights(*baseWeight, *capWeight)

	baseline := evaluate(samples, func(s sample) bool {
		return s.BaseScore < *threshold
	})

	enhanced := evaluate(samples, func(s sample) bool {
		score := s.BaseScore*bw + s.CapabilityScore*cw
		return score < *threshold
	})

	printMetrics("增强前（BaseScore）", baseline)
	printMetrics("增强后（融合得分）", enhanced)
	fmt.Println("---- 指标变化 ----")
	fmt.Printf("Precision: %.4f -> %.4f (delta %+0.4f)\n", baseline.Precision, enhanced.Precision, enhanced.Precision-baseline.Precision)
	fmt.Printf("Recall:    %.4f -> %.4f (delta %+0.4f)\n", baseline.Recall, enhanced.Recall, enhanced.Recall-baseline.Recall)
	fmt.Printf("F1:        %.4f -> %.4f (delta %+0.4f)\n", baseline.F1, enhanced.F1, enhanced.F1-baseline.F1)

	cfg, err := config.Load(*rulesPath)
	if err != nil {
		fmt.Printf("加载规则失败，跳过 Precision 误报评估: %v\n", err)
		return
	}

	fpSamples, err := loadFPSamples(*fpInput)
	if err != nil {
		fmt.Printf("加载 Precision 误报样本失败，跳过该评估: %v\n", err)
		return
	}
	if len(fpSamples) == 0 {
		fmt.Println("Precision 误报样本为空，跳过该评估")
		return
	}

	fpResult := evaluateFalsePositives(cfg, fpSamples)
	printFPEval(fpResult)
}

func loadSamples(path string) ([]sample, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var samples []sample
	if err := json.Unmarshal(b, &samples); err != nil {
		return nil, err
	}
	return samples, nil
}

func loadFPSamples(path string) ([]fpSample, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var samples []fpSample
	if err := json.Unmarshal(b, &samples); err != nil {
		return nil, err
	}
	return samples, nil
}

func normalizeWeights(baseWeight, capabilityWeight float64) (float64, float64) {
	if baseWeight < 0 {
		baseWeight = 0
	}
	if capabilityWeight < 0 {
		capabilityWeight = 0
	}
	total := baseWeight + capabilityWeight
	if total <= 0 {
		return 0.65, 0.35
	}
	return baseWeight / total, capabilityWeight / total
}

func evaluate(samples []sample, pred func(sample) bool) metrics {
	conf := confusion{}
	for _, s := range samples {
		predRisk := pred(s)
		if predRisk && s.LabelRisk {
			conf.TP++
			continue
		}
		if predRisk && !s.LabelRisk {
			conf.FP++
			continue
		}
		if !predRisk && s.LabelRisk {
			conf.FN++
			continue
		}
		conf.TN++
	}

	p := safeDiv(float64(conf.TP), float64(conf.TP+conf.FP))
	r := safeDiv(float64(conf.TP), float64(conf.TP+conf.FN))
	f1 := safeDiv(2*p*r, p+r)

	return metrics{
		Precision: p,
		Recall:    r,
		F1:        f1,
		Support:   len(samples),
		Conf:      conf,
	}
}

func evaluateFalsePositives(cfg *config.Config, samples []fpSample) fpEvalResult {
	ruleMap := make(map[string]config.Rule)
	for _, rule := range cfg.Rules {
		ruleMap[rule.ID] = rule
	}

	result := fpEvalResult{
		Support:            len(samples),
		BeforeByRule:       make(map[string]int),
		AfterByRule:        make(map[string]int),
		SuppressedByRule:   make(map[string]int),
		SuppressedFPByRule: make(map[string]int),
	}

	for _, s := range samples {
		rule, ok := ruleMap[s.RuleID]
		if !ok {
			result.MissingRuleSamples++
			continue
		}
		if rule.Detection.Type != "pattern" {
			result.NonPatternRuleCount++
			continue
		}

		lineText := s.Line
		if strings.TrimSpace(lineText) == "" {
			lineText = s.Context
		}
		if strings.TrimSpace(lineText) == "" {
			continue
		}

		beforeAlert := matchedByAny(rule.Detection.Patterns, lineText)
		if beforeAlert && !s.ShouldAlert {
			result.FPBefore++
			result.BeforeByRule[rule.ID]++
		}

		suppressed := false
		if beforeAlert {
			deny := matchedByAny(rule.WhitelistDeny, lineText)
			if !deny {
				suppressed = matchedByAny(rule.Whitelist, s.FilePath+"\n"+lineText)
			}
			if !suppressed && strings.TrimSpace(s.Context) != "" {
				denyCtx := matchedByAny(rule.WhitelistDeny, s.Context)
				if !denyCtx {
					suppressed = matchedByAny(rule.WhitelistCtx, s.FilePath+"\n"+s.Context)
				}
			}
		}
		if suppressed {
			result.SuppressedTotal++
			result.SuppressedByRule[rule.ID]++
			if !s.ShouldAlert {
				result.SuppressedFP++
				result.SuppressedFPByRule[rule.ID]++
			}
		}

		afterAlert := beforeAlert && !suppressed
		if afterAlert && !s.ShouldAlert {
			result.FPAfter++
			result.AfterByRule[rule.ID]++
		}
	}

	return result
}

func matchedByAny(patterns []string, text string) bool {
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

func safeDiv(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}

func printMetrics(title string, m metrics) {
	fmt.Printf("==== %s ====\n", title)
	fmt.Printf("Samples: %d\n", m.Support)
	fmt.Printf("TP/FP/TN/FN: %d/%d/%d/%d\n", m.Conf.TP, m.Conf.FP, m.Conf.TN, m.Conf.FN)
	fmt.Printf("Precision: %.4f\n", m.Precision)
	fmt.Printf("Recall: %.4f\n", m.Recall)
	fmt.Printf("F1: %.4f\n", m.F1)
}

func printFPEval(r fpEvalResult) {
	fmt.Println("==== Precision 误报评估（白名单前后） ====")
	fmt.Printf("Samples: %d\n", r.Support)
	fmt.Printf("FP Before: %d\n", r.FPBefore)
	fmt.Printf("FP After: %d\n", r.FPAfter)
	fmt.Printf("Suppressed Total: %d\n", r.SuppressedTotal)
	fmt.Printf("Suppressed FP: %d\n", r.SuppressedFP)
	if r.MissingRuleSamples > 0 {
		fmt.Printf("Skipped (missing rule): %d\n", r.MissingRuleSamples)
	}
	if r.NonPatternRuleCount > 0 {
		fmt.Printf("Skipped (non-pattern rule): %d\n", r.NonPatternRuleCount)
	}

	printRuleCounter("FP Before by Rule", r.BeforeByRule)
	printRuleCounter("FP After by Rule", r.AfterByRule)
	printRuleCounter("Suppressed by Rule", r.SuppressedByRule)
	printRuleCounter("Suppressed FP by Rule", r.SuppressedFPByRule)
}

func printRuleCounter(title string, counter map[string]int) {
	fmt.Printf("---- %s ----\n", title)
	if len(counter) == 0 {
		fmt.Println("(empty)")
		return
	}
	type pair struct {
		RuleID string
		Count  int
	}
	items := make([]pair, 0, len(counter))
	for k, v := range counter {
		items = append(items, pair{RuleID: k, Count: v})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].RuleID < items[j].RuleID
		}
		return items[i].Count > items[j].Count
	})
	for _, item := range items {
		fmt.Printf("%s: %d\n", item.RuleID, item.Count)
	}
}
