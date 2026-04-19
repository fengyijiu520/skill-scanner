package evaluator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"skill-scanner/internal/analyzer"
	"skill-scanner/internal/config"
	"skill-scanner/internal/embedder"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/similarity"
)

// Dependency 技能依赖项
type Dependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SourceFile 源代码文件
type SourceFile struct {
	Path     string `json:"path"`
	Content  string `json:"content"`
	Language string `json:"language"`
}

// Skill 待审查的技能信息
type Skill struct {
	Name         string       `json:"name"`
	Description  string       `json:"description"`
	Code         string       `json:"code"`
	Files        []SourceFile `json:"files"`
	Dependencies []Dependency `json:"dependencies"`
	Permissions  []string     `json:"permissions"`
}

// EvaluationResult 审查结果
type EvaluationResult struct {
	Passed              bool                         `json:"passed"`
	Score               float64                      `json:"score"`
	P0Blocked           bool                         `json:"p0_blocked"`
	P0Reasons           []string                     `json:"p0_reasons"`
	WhitelistSuppressed int                          `json:"whitelist_suppressed"`
	WhitelistByRule     map[string]int               `json:"whitelist_by_rule,omitempty"`
	ItemScores          map[string]float64           `json:"item_scores"`
	RiskLevel           string                       `json:"risk_level"`
	Analysis            *analyzer.CodeAnalysisResult `json:"analysis,omitempty"`
	FindingDetails      []FindingDetail              `json:"finding_details,omitempty"`
	LLMStatedIntent     string                       `json:"llm_stated_intent,omitempty"`
	LLMActualBehavior   string                       `json:"llm_actual_behavior,omitempty"`
	LLMIntentConfidence int                          `json:"llm_intent_confidence,omitempty"`
}

// FindingDetail 详细发现项
type FindingDetail struct {
	RuleID      string
	Severity    string
	Title       string
	Description string
	Location    string
	CodeSnippet string
}

// Thresholds 评分阈值配置
type Thresholds struct {
	PassScore      float64
	ReviewScore    float64
	SimilarityLow  float64
	SimilarityHigh float64
}

// CacheItem 缓存项
type CacheItem struct {
	Result   *EvaluationResult
	ExpireAt time.Time
}

// Evaluator 技能审查引擎
type Evaluator struct {
	embedder   embedder.Embedder
	llmClient  llm.Client
	config     *config.Config
	funcMap    map[string]DetectionFunc
	thresholds Thresholds
	cache      map[string]CacheItem
	cacheMutex sync.RWMutex
}

// DetectionFunc 检测函数签名
type DetectionFunc func(skill *Skill, rule config.Rule) (score float64, blocked bool, reason string, details []FindingDetail)

// Rule 审查规则接口
type Rule interface {
	Evaluate(ctx context.Context, skill *Skill) (score float64, reason string, blocked bool)
}

var DefaultThresholds = Thresholds{
	PassScore:      80,
	ReviewScore:    60,
	SimilarityLow:  0.5,
	SimilarityHigh: 0.75,
}

// NewEvaluator 创建新的审查引擎
func NewEvaluator(embedder embedder.Embedder, llmClient llm.Client, cfg *config.Config) *Evaluator {
	e := &Evaluator{
		embedder:   embedder,
		llmClient:  llmClient,
		config:     cfg,
		funcMap:    make(map[string]DetectionFunc),
		thresholds: DefaultThresholds,
		cache:      make(map[string]CacheItem),
	}
	e.registerBuiltinFuncs()
	return e
}

func (e *Evaluator) registerBuiltinFuncs() {
	e.funcMap["detectDataExfiltration"] = e.detectDataExfiltrationFunc
	e.funcMap["detectHardcodedCredential"] = e.detectHardcodedCredentialFunc
	e.funcMap["detectMCPAbuse"] = e.detectMCPAbuseFunc
	e.funcMap["evaluateDependencyVulns"] = e.evaluateDependencyVulnsFunc
	e.funcMap["evaluatePermissions"] = e.evaluatePermissionsFunc
	e.funcMap["evaluateInjectionRisk"] = e.evaluateInjectionRiskFunc
	e.funcMap["evaluateContextLeak"] = e.evaluateContextLeakFunc
	e.funcMap["evaluateSoftDependencies"] = e.evaluateSoftDependenciesFunc
	e.funcMap["evaluateCredentialIsolation"] = e.evaluateCredentialIsolationFunc
	e.funcMap["evaluateHiddenContent"] = e.evaluateHiddenContentFunc
	e.funcMap["evaluateResourceRisk"] = e.evaluateResourceRiskFunc
	e.funcMap["evaluateMemoryIsolation"] = e.evaluateMemoryIsolationFunc
	e.funcMap["detectFileUploadVulnerabilities"] = e.detectFileUploadVulnerabilitiesFunc
	e.funcMap["detectPrivacyCompliance"] = e.detectPrivacyComplianceFunc
	e.funcMap["detectPromptInjectionProtection"] = e.detectPromptInjectionProtectionFunc
	e.funcMap["detectContentSafety"] = e.detectContentSafetyFunc
}

func (e *Evaluator) SetThresholds(t Thresholds) {
	e.thresholds = t
}

type CacheKey struct {
	CodeHash        string
	DescHash        string
	DepsHash        string
	PermissionsHash string
}

func (c *CacheKey) String() string {
	return fmt.Sprintf("eval:%s:%s:%s:%s", c.CodeHash[:8], c.DescHash[:8], c.DepsHash[:8], c.PermissionsHash[:8])
}

func generateCacheKey(skill *Skill) CacheKey {
	var filesContent strings.Builder
	for _, file := range skill.Files {
		filesContent.WriteString(file.Path)
		filesContent.WriteString(file.Content)
	}
	codeHash := sha256.Sum256([]byte(filesContent.String()))
	descHash := sha256.Sum256([]byte(skill.Description))
	depsStr := fmt.Sprintf("%v", skill.Dependencies)
	depsHash := sha256.Sum256([]byte(depsStr))
	permStr := fmt.Sprintf("%v", skill.Permissions)
	permHash := sha256.Sum256([]byte(permStr))
	return CacheKey{
		CodeHash:        hex.EncodeToString(codeHash[:]),
		DescHash:        hex.EncodeToString(descHash[:]),
		DepsHash:        hex.EncodeToString(depsHash[:]),
		PermissionsHash: hex.EncodeToString(permHash[:]),
	}
}

// EvaluateWithCascade 级联审查
func (e *Evaluator) EvaluateWithCascade(ctx context.Context, skill *Skill) (*EvaluationResult, error) {
	cacheKey := generateCacheKey(skill)
	cacheStr := cacheKey.String()
	e.cacheMutex.RLock()
	if item, ok := e.cache[cacheStr]; ok && item.ExpireAt.After(time.Now()) {
		e.cacheMutex.RUnlock()
		return item.Result, nil
	}
	e.cacheMutex.RUnlock()

	result := &EvaluationResult{
		Passed:          true,
		Score:           100,
		WhitelistByRule: make(map[string]int),
		ItemScores:      make(map[string]float64),
		RiskLevel:       "low",
		Analysis:        e.runStaticAnalysis(skill),
	}

	compensationMap := make(map[string]bool)
	totalDeduction := 0.0
	blocked := false

	// 1. 执行 P0 阻断层规则（合并相邻行，去重文件）
	detailMap := make(map[string]*FindingDetail) // 键：文件路径+规则ID
	reasonSet := make(map[string]bool)

	for _, rule := range e.config.Rules {
		if rule.Layer != "P0" {
			continue
		}
		if rule.Detection.Type == "pattern" {
			patternRegex := compileRegexList(rule.Detection.Patterns)
			whitelistRegex := compileRegexList(rule.Whitelist)
			whitelistContextRegex := compileRegexList(rule.WhitelistCtx)
			whitelistDenyRegex := compileRegexList(rule.WhitelistDeny)
			// 按文件分组匹配行
			for _, file := range skill.Files {
				lines := strings.Split(file.Content, "\n")
				matchedLines := make(map[int]bool) // 记录哪些行匹配
				for lineNum, line := range lines {
					for _, re := range patternRegex {
						if re.MatchString(line) {
							if isDenyMatched(line, whitelistDenyRegex) {
								matchedLines[lineNum] = true
								break
							}
							if isWhitelistedLine(file.Path, line, whitelistRegex) || isWhitelistedByContext(file.Path, lines, lineNum, whitelistContextRegex) {
								result.WhitelistSuppressed++
								result.WhitelistByRule[rule.ID]++
								continue
							}
							matchedLines[lineNum] = true
							break // 只要匹配一个模式即可
						}
					}
				}

				if len(matchedLines) == 0 {
					continue
				}

				// 将连续行合并为区间
				var intervals [][2]int
				var start, end int
				inBlock := false
				for i := 0; i < len(lines); i++ {
					if matchedLines[i] {
						if !inBlock {
							start = i
							inBlock = true
						}
						end = i
					} else {
						if inBlock {
							intervals = append(intervals, [2]int{start, end})
							inBlock = false
						}
					}
				}
				if inBlock {
					intervals = append(intervals, [2]int{start, end})
				}

				// 为每个区间生成一条 FindingDetail
				for _, interval := range intervals {
					startLine := interval[0]
					endLine := interval[1]

					// 代码上下文：从 startLine-2 到 endLine+2
					contextStart := startLine - 2
					if contextStart < 0 {
						contextStart = 0
					}
					contextEnd := endLine + 3
					if contextEnd > len(lines) {
						contextEnd = len(lines)
					}

					var codeBuilder strings.Builder
					for i := contextStart; i < contextEnd; i++ {
						prefix := "  "
						if i >= startLine && i <= endLine {
							prefix = "> "
						}
						codeBuilder.WriteString(fmt.Sprintf("%s%4d | %s\n", prefix, i+1, lines[i]))
					}

					// 生成唯一键（文件+规则ID+起始行，确保同一区间不重复）
					key := fmt.Sprintf("%s:%s:%d", file.Path, rule.ID, startLine)
					if _, exists := detailMap[key]; !exists {
						loc := fmt.Sprintf("%s:%d", filepath.Base(file.Path), startLine+1)
						if endLine > startLine {
							loc = fmt.Sprintf("%s:%d-%d", filepath.Base(file.Path), startLine+1, endLine+1)
						}
						detailMap[key] = &FindingDetail{
							RuleID:      rule.ID,
							Severity:    "高风险",
							Title:       rule.Name,
							Description: rule.OnFail.Reason,
							Location:    loc,
							CodeSnippet: codeBuilder.String(),
						}
					}

					if rule.OnFail.Action == "block" {
						blocked = true
						result.P0Blocked = true
						if !reasonSet[rule.OnFail.Reason] {
							reasonSet[rule.OnFail.Reason] = true
							result.P0Reasons = append(result.P0Reasons, rule.OnFail.Reason)
						}
					}
				}
			}
			result.ItemScores[rule.ID] = 0
			continue
		}
		// 其他类型保持原有调用方式
		score, ruleBlocked, reason, details := e.executeRule(ctx, skill, rule)
		if len(details) > 0 {
			result.FindingDetails = append(result.FindingDetails, details...)
		}
		if ruleBlocked {
			blocked = true
			result.P0Blocked = true
			if !reasonSet[reason] {
				reasonSet[reason] = true
				result.P0Reasons = append(result.P0Reasons, reason)
			}
		}
		result.ItemScores[rule.ID] = score
	}

	// 将合并后的详情存入 result
	for _, detail := range detailMap {
		result.FindingDetails = append(result.FindingDetails, *detail)
	}

	// 2. LLM 深度分析
	if e.llmClient != nil {
		codeSummary := extractCodeSummaryFromFiles(skill.Files)
		llmResult, err := e.llmClient.AnalyzeCode(ctx, skill.Name, skill.Description, codeSummary)
		if err == nil && llmResult != nil {
			result.LLMStatedIntent = strings.TrimSpace(llmResult.StatedIntent)
			result.LLMActualBehavior = strings.TrimSpace(llmResult.ActualBehavior)
			result.LLMIntentConfidence = llmResult.IntentConsistency
			seen := make(map[string]bool)
			for _, risk := range llmResult.Risks {
				loc, snippet, found := e.locateRiskInFiles(skill, risk)
				if !found {
					continue // 无具体位置，不生成该项
				}
				key := risk.Title + "|" + loc
				if seen[key] {
					continue
				}
				seen[key] = true

				severity := "高风险"
				if risk.Severity == "high" {
					severity = "高风险"
					blocked = true
					result.P0Blocked = true
					result.P0Reasons = append(result.P0Reasons, fmt.Sprintf("LLM深度检测: %s - %s", risk.Title, risk.Description))
				} else if risk.Severity == "medium" {
					severity = "中风险"
					totalDeduction += 5
				} else {
					severity = "低风险"
					totalDeduction += 2
				}

				detail := FindingDetail{
					RuleID:      "LLM-DETECT",
					Severity:    severity,
					Title:       fmt.Sprintf("LLM检测: %s", risk.Title),
					Description: buildLLMRiskDescription(risk, llmResult),
					Location:    loc,
					CodeSnippet: snippet,
				}
				result.FindingDetails = append(result.FindingDetails, detail)
			}
			if llmResult.IntentConsistency < 80 {
				totalDeduction += float64(100-llmResult.IntentConsistency) * 0.3
			}
		}
	}

	// 3. P1 层
	for _, rule := range e.config.Rules {
		if rule.Layer != "P1" {
			continue
		}
		var score float64
		var details []FindingDetail
		if rule.Detection.Type == "pattern" {
			score, details = e.evaluatePatternRule(skill, rule)
		} else {
			score, _, _, details = e.executeRule(ctx, skill, rule)
		}
		result.ItemScores[rule.ID] = score
		if len(details) > 0 {
			result.FindingDetails = append(result.FindingDetails, details...)
		}
		result.ItemScores[rule.ID] = score
		deduction := rule.Weight - score
		if deduction < 0 {
			deduction = 0
		}
		hasComp := compensationMap[rule.ID] || !rule.Compensation
		if deduction > 0 {
			if !hasComp && rule.OnFail.NoCompensationBlock {
				blocked = true
				result.P0Blocked = true
				result.P0Reasons = append(result.P0Reasons, fmt.Sprintf("%s 无补偿且未通过", rule.Name))
			}
			if hasComp {
				totalDeduction += rule.OnFail.DefaultDeduction
			} else {
				totalDeduction += rule.ScoreDeduction
			}
		}
	}

	// 4. P2 层
	for _, rule := range e.config.Rules {
		if rule.Layer != "P2" {
			continue
		}
		var score float64
		var details []FindingDetail
		if rule.Detection.Type == "pattern" {
			score, details = e.evaluatePatternRule(skill, rule)
		} else {
			score, _, _, details = e.executeRule(ctx, skill, rule)
		}
		result.ItemScores[rule.ID] = score
		if len(details) > 0 {
			result.FindingDetails = append(result.FindingDetails, details...)
		}
		result.ItemScores[rule.ID] = score
		deduction := rule.Weight - score
		if deduction < 0 {
			deduction = 0
		}
		hasComp := compensationMap[rule.ID] || !rule.Compensation
		if deduction > 0 {
			if hasComp {
				totalDeduction += rule.OnFail.DefaultDeduction
			} else {
				totalDeduction += rule.ScoreDeduction
			}
		}
	}

	finalScore := 100.0 - totalDeduction
	if finalScore < 0 {
		finalScore = 0
	}
	result.Score = finalScore

	if blocked {
		result.Passed = false
		result.RiskLevel = "critical"
		result.Score = 0
	} else {
		for _, rl := range e.config.RiskLevels {
			if finalScore >= rl.Threshold {
				result.RiskLevel = rl.Level
				result.Passed = rl.AutoApprove
				if rl.Block {
					result.Passed = false
					result.P0Blocked = true
					result.P0Reasons = append(result.P0Reasons, fmt.Sprintf("总分 %.1f 低于安全阈值", finalScore))
				}
				break
			}
		}
	}

	e.cacheResult(cacheStr, result)
	return result, nil
}

func (e *Evaluator) executeRule(ctx context.Context, skill *Skill, rule config.Rule) (score float64, blocked bool, reason string, details []FindingDetail) {
	switch rule.Detection.Type {
	case "pattern":
		// pattern 类型已经在 EvaluateWithCascade 中单独处理，这里不会调用到
		return rule.Weight, false, "", nil
	case "semantic":
		// 语义检测，目前不返回位置
		if e.embedder == nil {
			return rule.Weight, false, "", nil
		}
		codeSummary := extractCodeSummaryFromFiles(skill.Files)
		vectors, err := e.embedder.BatchEmbed([]string{skill.Description, codeSummary})
		if err != nil {
			return rule.Weight, false, "", nil
		}
		sim := similarity.CosineSimilarity(vectors[0], vectors[1])
		if sim < rule.Detection.ThresholdLow {
			if rule.OnFail.Action == "block" {
				return 0, true, rule.OnFail.Reason, nil
			}
			return 0, false, "", nil
		} else if sim < rule.Detection.ThresholdHigh {
			return rule.Weight / 2, false, "", nil
		}
		return rule.Weight, false, "", nil
	case "function":
		fn, ok := e.funcMap[rule.Detection.Function]
		if !ok {
			return rule.Weight, false, "", nil
		}
		// 调用新的签名
		return fn(skill, rule)
	default:
		return rule.Weight, false, "", nil
	}
}

func (e *Evaluator) evaluatePatternRule(skill *Skill, rule config.Rule) (float64, []FindingDetail) {
	var details []FindingDetail
	score := rule.Weight
	matchedCount := 0
	patternRegex := compileRegexList(rule.Detection.Patterns)
	whitelistRegex := compileRegexList(rule.Whitelist)
	whitelistContextRegex := compileRegexList(rule.WhitelistCtx)
	whitelistDenyRegex := compileRegexList(rule.WhitelistDeny)

	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		fileMatched := false
		for i, line := range lines {
			for _, re := range patternRegex {
				if re.MatchString(line) {
					if isDenyMatched(line, whitelistDenyRegex) {
						continue
					}
					if isWhitelistedLine(file.Path, line, whitelistRegex) || isWhitelistedByContext(file.Path, lines, i, whitelistContextRegex) {
						continue
					}
					matchedCount++
					fileMatched = true
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "中风险",
						Title:       rule.Name,
						Description: rule.Description,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break
				}
			}
		}
		_ = fileMatched
	}

	if matchedCount > 0 {
		score = rule.Weight * 0.3
	}
	return score, details
}

func (e *Evaluator) runStaticAnalysis(skill *Skill) *analyzer.CodeAnalysisResult {
	result := &analyzer.CodeAnalysisResult{}
	for _, file := range skill.Files {
		var fileResult *analyzer.CodeAnalysisResult
		switch file.Language {
		case "go":
			fileResult = analyzer.AnalyzeGoCode(file.Content, file.Path)
		case "javascript", "typescript":
			fileResult = analyzer.AnalyzeJavaScriptCode(file.Content, file.Path)
		}
		if fileResult != nil {
			result.DangerousCalls = append(result.DangerousCalls, fileResult.DangerousCalls...)
			result.HasHardcoded = result.HasHardcoded || fileResult.HasHardcoded
		}
	}
	return result
}

func (e *Evaluator) cacheResult(key string, result *EvaluationResult) {
	e.cacheMutex.Lock()
	defer e.cacheMutex.Unlock()
	e.cache[key] = CacheItem{Result: result, ExpireAt: time.Now().Add(24 * time.Hour)}
}

func compileRegexList(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if strings.TrimSpace(p) == "" {
			continue
		}
		re, err := regexp.Compile(p)
		if err != nil {
			continue
		}
		out = append(out, re)
	}
	return out
}

func isWhitelistedLine(filePath, line string, whitelist []*regexp.Regexp) bool {
	if len(whitelist) == 0 {
		return false
	}
	target := filePath + "\n" + line
	for _, re := range whitelist {
		if re.MatchString(target) {
			return true
		}
	}
	return false
}

func isWhitelistedByContext(filePath string, lines []string, idx int, whitelist []*regexp.Regexp) bool {
	if len(whitelist) == 0 || len(lines) == 0 || idx < 0 || idx >= len(lines) {
		return false
	}
	start := idx - 2
	if start < 0 {
		start = 0
	}
	end := idx + 2
	if end >= len(lines) {
		end = len(lines) - 1
	}
	window := strings.Join(lines[start:end+1], "\n")
	target := filePath + "\n" + window
	for _, re := range whitelist {
		if re.MatchString(target) {
			return true
		}
	}
	return false
}

func isDenyMatched(line string, deny []*regexp.Regexp) bool {
	if len(deny) == 0 {
		return false
	}
	for _, re := range deny {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// -------- 检测函数实现 --------
var maliciousPatterns = []*regexp.Regexp{
	regexp.MustCompile(`rm\s+-rf\s+/`),
	regexp.MustCompile(`dd\s+if=/dev/zero`),
	regexp.MustCompile(`nc\s+-e\s+/bin/sh`),
	regexp.MustCompile(`bash\s+-i\s+>&\s+/dev/tcp`),
	regexp.MustCompile(`stratum\+tcp://`),
	regexp.MustCompile(`mining`),
	regexp.MustCompile(`EncryptFile.*ransom`),
}

func (e *Evaluator) detectMaliciousCode(skill *Skill) bool {
	for _, file := range skill.Files {
		for _, re := range maliciousPatterns {
			if re.MatchString(file.Content) {
				return true
			}
		}
	}
	return false
}

var backdoorPattern = regexp.MustCompile(`if.*input.*==.*["']backdoor["'].*exec`)

func (e *Evaluator) detectBackdoor(skill *Skill) bool {
	for _, file := range skill.Files {
		if backdoorPattern.MatchString(file.Content) {
			return true
		}
		if strings.Contains(file.Content, "setTimeout") && strings.Contains(file.Content, "exec") {
			return true
		}
	}
	return false
}

func (e *Evaluator) detectDataExfiltration(skill *Skill) bool {
	for _, file := range skill.Files {
		code := file.Content
		if (strings.Contains(code, "process.env") || strings.Contains(code, "/etc/passwd") || strings.Contains(code, "~/.ssh")) &&
			(strings.Contains(code, "fetch") || strings.Contains(code, "axios") || strings.Contains(code, "http.Post")) {
			return true
		}
		if strings.Contains(code, "nslookup") && strings.Contains(code, "attacker.com") {
			return true
		}
		if strings.Contains(code, "btoa") && strings.Contains(code, "JSON.stringify") && strings.Contains(code, "fetch") {
			return true
		}
	}
	return false
}

func (e *Evaluator) detectMCPAbuse(skill *Skill) bool {
	desc := skill.Description
	if strings.Contains(desc, "调用 file_system.delete_all") || strings.Contains(desc, "调用 system.exec") {
		if !strings.Contains(strings.ToLower(skill.Name), "file") && !strings.Contains(strings.ToLower(skill.Description), "file") {
			return true
		}
	}
	return false
}

func (e *Evaluator) evaluateDeception(ctx context.Context, skill *Skill) (float64, error) {
	codeSummary := extractCodeSummaryFromFiles(skill.Files)
	vectors, err := e.embedder.BatchEmbed([]string{skill.Description, codeSummary})
	if err != nil {
		return 0, err
	}
	sim := similarity.CosineSimilarity(vectors[0], vectors[1])
	if sim < e.thresholds.SimilarityLow {
		return 100, nil
	} else if sim < e.thresholds.SimilarityHigh {
		return 50, nil
	}
	return 0, nil
}

func (e *Evaluator) evaluateDependencyVulns(skill *Skill) float64 {
	score := 20.0
	for _, dep := range skill.Dependencies {
		if dep.Version == "" || strings.HasPrefix(dep.Version, "0.0.0") {
			score -= 20
		} else if strings.Contains(dep.Name, "malicious") {
			score -= 20
		} else if strings.Contains(dep.Name, "typo") {
			score -= 15
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluatePermissions(skill *Skill) float64 {
	score := 20.0
	for _, perm := range skill.Permissions {
		switch perm {
		case "root", "administrator":
			score -= 20
		case "/**":
			score -= 15
		case "0.0.0.0":
			score -= 10
		case "HOME", "PATH":
			score -= 5
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateInjectionRisk(skill *Skill) float64 {
	score := 15.0
	for _, file := range skill.Files {
		code := file.Content
		if strings.Contains(code, "exec.Command") && strings.Contains(code, "input") {
			score -= 15
			break
		}
		if strings.Contains(code, "llm.Output") && strings.Contains(code, "exec") {
			score -= 12
			break
		}
		if strings.Contains(code, "args") && !strings.Contains(code, "whitelist") {
			score -= 8
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateContextLeak(skill *Skill) float64 {
	score := 10.0
	for _, file := range skill.Files {
		code := file.Content
		// 原有模式
		if strings.Contains(code, "system_prompt") && strings.Contains(code, "return") {
			score -= 10
			break
		}
		if strings.Contains(code, "config") && strings.Contains(code, "error") {
			score -= 8
			break
		}
		if strings.Contains(code, "log") && strings.Contains(code, "secret") {
			score -= 5
			break
		}
		// 新增模式：日志中输出敏感变量
		if strings.Contains(code, "log.") && (strings.Contains(code, "password") || strings.Contains(code, "token") || strings.Contains(code, "key")) {
			score -= 6
			break
		}
		// 新增模式：错误信息中返回敏感数据
		if strings.Contains(code, "fmt.Errorf") && strings.Contains(code, "%v") && (strings.Contains(code, "secret") || strings.Contains(code, "password")) {
			score -= 7
			break
		}
		// 新增模式：将敏感信息拼接到 HTTP 响应
		if strings.Contains(code, "http.") && strings.Contains(code, "Write") && (strings.Contains(code, "password") || strings.Contains(code, "token")) {
			score -= 8
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateSoftDependencies(skill *Skill) float64 {
	score := 10.0
	for _, file := range skill.Files {
		code := file.Content
		if strings.Contains(code, "http.Get") && strings.Contains(code, ".js") && !strings.Contains(code, "hash") {
			score -= 10
			break
		}
		if strings.Contains(code, "http.Get") && !strings.Contains(code, "https://") {
			score -= 5
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateCredentialIsolation(skill *Skill) float64 {
	score := 10.0
	for _, file := range skill.Files {
		code := file.Content
		if strings.Contains(code, "global.credential") {
			score -= 10
			break
		}
		if strings.Contains(code, "session") && strings.Contains(code, "credential") {
			score -= 8
			break
		}
		if strings.Contains(code, "log") && strings.Contains(code, "credential") {
			score -= 10
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateHiddenContent(skill *Skill) float64 {
	score := 5.0
	base64Count := 0
	highEntropyFound := false
	for _, file := range skill.Files {
		code := file.Content
		if strings.Contains(code, "\u202E") {
			score -= 5
			break
		}
		if strings.Contains(code, "btoa") {
			base64Count++
		}
		if strings.Contains(code, "atob") {
			base64Count++
		}
		if !highEntropyFound && analyzer.CalculateEntropy(code) > 5.0 {
			highEntropyFound = true
		}
	}
	if base64Count >= 2 {
		score -= 3
	}
	if highEntropyFound {
		score -= 2
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateResourceRisk(skill *Skill) float64 {
	score := 5.0
	for _, file := range skill.Files {
		code := file.Content
		if strings.Contains(code, "for") && !strings.Contains(code, "break") && !strings.Contains(code, "len") {
			score -= 5
			break
		}
		if strings.Contains(code, "recursive") && !strings.Contains(code, "depth") {
			score -= 3
			break
		}
		if strings.Contains(code, "http.Get") && !strings.Contains(code, "Timeout") {
			score -= 2
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

func (e *Evaluator) evaluateMemoryIsolation(skill *Skill) float64 {
	score := 5.0
	for _, file := range skill.Files {
		code := file.Content
		if strings.Contains(code, "memory.write") && strings.Contains(code, "input") {
			score -= 5
			break
		}
		if strings.Contains(code, "memory.read") && !strings.Contains(code, "permission") {
			score -= 3
			break
		}
		if strings.Contains(code, "memory.share") {
			score -= 5
			break
		}
	}
	if score < 0 {
		score = 0
	}
	return score
}

// -------- 辅助函数 --------
func extractCodeSummary(code string) string {
	var summary strings.Builder
	functions := extractFunctionSignatures(code)
	for _, f := range functions {
		summary.WriteString(f.Name + " ")
	}
	imports := extractImports(code)
	for _, imp := range imports {
		summary.WriteString(imp + " ")
	}
	comments := extractComments(code)
	for _, c := range comments {
		if len(c) > 10 {
			summary.WriteString(c + " ")
		}
	}
	strings := extractStringLiterals(code)
	for _, s := range strings {
		if len(s) > 5 && len(s) < 50 {
			summary.WriteString(s + " ")
		}
	}
	return summary.String()
}

func extractCodeSummaryFromFiles(files []SourceFile) string {
	var summary strings.Builder
	for _, file := range files {
		summary.WriteString(extractCodeSummary(file.Content))
		summary.WriteString(" ")
	}
	return summary.String()
}

func extractFunctionSignatures(code string) []struct{ Name string } {
	var res []struct{ Name string }
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "func ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				res = append(res, struct{ Name string }{Name: parts[1]})
			}
		}
	}
	return res
}

func extractImports(code string) []string {
	var res []string
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "import ") {
			parts := strings.Fields(line)
			for _, p := range parts[1:] {
				if strings.HasPrefix(p, `"`) {
					res = append(res, strings.Trim(p, `"`))
				}
			}
		}
	}
	return res
}

func extractComments(code string) []string {
	var res []string
	lines := strings.Split(code, "\n")
	for _, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			res = append(res, strings.TrimSpace(strings.TrimPrefix(line, "//")))
		}
	}
	return res
}

func extractStringLiterals(code string) []string {
	var res []string
	re := regexp.MustCompile(`"([^"\\]|\\.)*"`)
	matches := re.FindAllString(code, -1)
	for _, m := range matches {
		res = append(res, strings.Trim(m, `"`))
	}
	return res
}

func formatCodeContext(lines []string, centerLine int, radius int) string {
	start := centerLine - radius
	if start < 0 {
		start = 0
	}
	end := centerLine + radius + 1
	if end > len(lines) {
		end = len(lines)
	}
	var builder strings.Builder
	for i := start; i < end; i++ {
		prefix := "  "
		if i == centerLine {
			prefix = "> "
		}
		builder.WriteString(fmt.Sprintf("%s%4d | %s\n", prefix, i+1, lines[i]))
	}
	return builder.String()
}

// -------- 包装函数 --------
func (e *Evaluator) detectHardcodedCredentialFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	// 遍历所有文件查找硬编码凭证
	credPatterns := []string{
		`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']+["']`,
		`(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*["'][^"']+["']`,
		`(?i)(private[_-]?key|privkey)\s*[:=]\s*["'][^"']+["']`,
	}
	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			for _, pat := range credPatterns {
				if matched, _ := regexp.MatchString(pat, line); matched {
					// ⭐ 新增排除逻辑：如果是空字符串或明显占位符则跳过，避免误报
					lowerLine := strings.ToLower(line)
					if strings.Contains(lowerLine, `""`) || strings.Contains(lowerLine, `''`) ||
						strings.Contains(lowerLine, `"your_`) || strings.Contains(lowerLine, `"example`) ||
						strings.Contains(lowerLine, `"test`) || strings.Contains(lowerLine, `"xxx`) ||
						strings.Contains(lowerLine, `"0xYOUR`) {
						continue // 跳过这条匹配，不生成告警
					}

					// 找到硬编码凭证
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "高风险",
						Title:       rule.Name,
						Description: rule.OnFail.Reason,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break // 一行只记录一次
				}
			}
		}
	}
	if len(details) > 0 {
		if rule.OnFail.Action == "block" {
			return 0, true, rule.OnFail.Reason, details
		}
		return 0, false, "", details
	}
	return rule.Weight, false, "", nil
}

func (e *Evaluator) detectDataExfiltrationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	patterns := []struct {
		pattern string
		desc    string
	}{
		{`(process\.env|/etc/passwd|~/.ssh).*(fetch|axios|http\.Post)`, "读取敏感文件并通过网络发送"},
		{`nslookup.*attacker\.com`, "DNS外带数据"},
		{`btoa.*JSON\.stringify.*fetch`, "Base64编码数据后外发"},
	}
	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			for _, p := range patterns {
				if matched, _ := regexp.MatchString(p.pattern, line); matched {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "高风险",
						Title:       rule.Name,
						Description: rule.OnFail.Reason + ": " + p.desc,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break
				}
			}
		}
	}
	if len(details) > 0 {
		if rule.OnFail.Action == "block" {
			return 0, true, rule.OnFail.Reason, details
		}
		return 0, false, "", details
	}
	return rule.Weight, false, "", nil
}

func (e *Evaluator) detectMCPAbuseFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	// 检测描述中的滥用
	if strings.Contains(skill.Description, "调用 file_system.delete_all") ||
		strings.Contains(skill.Description, "调用 system.exec") {
		if !strings.Contains(strings.ToLower(skill.Name), "file") &&
			!strings.Contains(strings.ToLower(skill.Description), "file") {
			detail := FindingDetail{
				RuleID:      rule.ID,
				Severity:    "高风险",
				Title:       rule.Name,
				Description: rule.OnFail.Reason,
				Location:    "技能描述",
				CodeSnippet: skill.Description,
			}
			details = append(details, detail)
		}
	}
	// 检测代码中是否包含MCP相关调用（示例）
	for _, file := range skill.Files {
		if strings.Contains(file.Content, "mcp__") || strings.Contains(file.Content, "call_tool") {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				if strings.Contains(line, "delete_all") || strings.Contains(line, "system.exec") {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "高风险",
						Title:       rule.Name,
						Description: rule.OnFail.Reason,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break
				}
			}
		}
	}
	if len(details) > 0 {
		if rule.OnFail.Action == "block" {
			return 0, true, rule.OnFail.Reason, details
		}
		return 0, false, "", details
	}
	return rule.Weight, false, "", nil
}

func (e *Evaluator) evaluateDependencyVulnsFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateDependencyVulns(skill)
	var details []FindingDetail
	if score < rule.Weight {
		details = append(details, FindingDetail{
			RuleID:      rule.ID,
			Severity:    "中风险",
			Title:       rule.Name,
			Description: fmt.Sprintf("该项得分: %.1f / %.0f，依赖项存在安全风险", score, rule.Weight),
			Location:    "请检查 go.mod 或 package.json 中的依赖项",
		})
	}
	return score, false, "", details
}

func (e *Evaluator) evaluatePermissionsFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluatePermissions(skill)
	var details []FindingDetail
	if score < rule.Weight {
		// 列出过度申请的权限
		excessive := []string{}
		for _, perm := range skill.Permissions {
			if perm == "root" || perm == "administrator" || perm == "/**" || perm == "0.0.0.0" {
				excessive = append(excessive, perm)
			}
		}
		detail := FindingDetail{
			RuleID:      rule.ID,
			Severity:    "中风险",
			Title:       rule.Name,
			Description: fmt.Sprintf("该项得分: %.1f / %.0f，申请了过高权限: %s", score, rule.Weight, strings.Join(excessive, ", ")),
			Location:    "用户声明的权限",
			CodeSnippet: strings.Join(skill.Permissions, ", "),
		}
		details = append(details, detail)
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateContextLeakFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateContextLeak(skill)
	var details []FindingDetail
	if score < rule.Weight {
		found := false
		for _, file := range skill.Files {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				if (strings.Contains(line, "system_prompt") && strings.Contains(line, "return")) ||
					(strings.Contains(line, "config") && strings.Contains(line, "error")) ||
					(strings.Contains(line, "log") && strings.Contains(line, "secret")) ||
					(strings.Contains(line, "log.") && (strings.Contains(line, "password") || strings.Contains(line, "token") || strings.Contains(line, "key"))) ||
					(strings.Contains(line, "fmt.Errorf") && strings.Contains(line, "%v") && (strings.Contains(line, "secret") || strings.Contains(line, "password"))) ||
					(strings.Contains(line, "http.") && strings.Contains(line, "Write") && (strings.Contains(line, "password") || strings.Contains(line, "token"))) {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "中风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("该项得分: %.1f / %.0f，可能泄露敏感上下文", score, rule.Weight),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found && len(skill.Files) > 0 {
			// 兜底：显示第一个文件名
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "中风险",
				Title:       rule.Name,
				Description: fmt.Sprintf("该项得分: %.1f / %.0f，可能泄露敏感上下文", score, rule.Weight),
				Location:    filepath.Base(skill.Files[0].Path),
				CodeSnippet: "未定位到具体行，请检查该文件中的日志输出或错误处理。",
			})
		}
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateSoftDependenciesFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateSoftDependencies(skill)
	var details []FindingDetail
	if score < rule.Weight {
		found := false
		for _, file := range skill.Files {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				if strings.Contains(line, "http.Get") && !strings.Contains(line, "hash") {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "中风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("该项得分: %.1f / %.0f，外部软依赖缺少完整性校验", score, rule.Weight),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found && len(skill.Files) > 0 {
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "中风险",
				Title:       rule.Name,
				Description: fmt.Sprintf("该项得分: %.1f / %.0f", score, rule.Weight),
				Location:    filepath.Base(skill.Files[0].Path),
				CodeSnippet: "未定位到具体行，请检查外部资源加载代码。",
			})
		}
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateCredentialIsolationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateCredentialIsolation(skill)
	var details []FindingDetail
	if score < rule.Weight {
		// 从文件中找一个相关位置
		for _, file := range skill.Files {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				if strings.Contains(line, "credential") || strings.Contains(line, "session") || strings.Contains(line, "global.") {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "中风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("该项得分: %.1f / %.0f，存在凭据隔离风险", score, rule.Weight),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break
				}
			}
			if len(details) > 0 {
				break
			}
		}
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateHiddenContentFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateHiddenContent(skill)
	var details []FindingDetail
	if score < rule.Weight {
		for _, file := range skill.Files {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				// 具体检测内容
				if strings.Contains(line, "\u202E") {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("检测到 Unicode 方向覆盖字符 (U+202E)，可能用于隐藏恶意代码"),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
				if strings.Contains(line, "btoa") {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("使用 btoa 进行 Base64 编码，可能用于混淆数据"),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
				if strings.Contains(line, "atob") {
					details = append(details, FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("使用 atob 解码 Base64，可能用于隐藏执行"),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					})
				}
			}
		}
		// 高熵检测（全文件级别）
		for _, file := range skill.Files {
			if analyzer.CalculateEntropy(file.Content) > 5.0 {
				details = append(details, FindingDetail{
					RuleID:      rule.ID,
					Severity:    "低风险",
					Title:       rule.Name,
					Description: fmt.Sprintf("文件整体熵值过高 (%.2f)，可能包含加密或压缩数据", analyzer.CalculateEntropy(file.Content)),
					Location:    filepath.Base(file.Path),
					CodeSnippet: "整个文件熵值异常",
				})
				break
			}
		}
	}
	// 如果分数被扣但未生成任何详情（理论上不会，但做兜底）
	if len(details) == 0 && score < rule.Weight && len(skill.Files) > 0 {
		details = append(details, FindingDetail{
			RuleID:      rule.ID,
			Severity:    "低风险",
			Title:       rule.Name,
			Description: fmt.Sprintf("该项得分: %.1f / %.0f，可能存在隐藏内容", score, rule.Weight),
			Location:    filepath.Base(skill.Files[0].Path),
			CodeSnippet: "未定位到具体行，请检查是否存在混淆代码或高熵数据。",
		})
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateResourceRiskFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateResourceRisk(skill)
	var details []FindingDetail
	if score < rule.Weight {
		found := false
		for _, file := range skill.Files {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				if (strings.Contains(line, "for") && !strings.Contains(line, "break")) ||
					(strings.Contains(line, "recursive") && !strings.Contains(line, "depth")) ||
					(strings.Contains(line, "http.Get") && !strings.Contains(line, "Timeout")) {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("该项得分: %.1f / %.0f，存在资源耗尽风险", score, rule.Weight),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found && len(skill.Files) > 0 {
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "低风险",
				Title:       rule.Name,
				Description: fmt.Sprintf("该项得分: %.1f / %.0f，存在资源耗尽风险", score, rule.Weight),
				Location:    filepath.Base(skill.Files[0].Path),
				CodeSnippet: "未定位到具体行，请检查死循环、无限递归或缺少超时的网络请求。",
			})
		}
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateMemoryIsolationFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateMemoryIsolation(skill)
	var details []FindingDetail
	if score < rule.Weight {
		found := false
		for _, file := range skill.Files {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				if strings.Contains(line, "memory.write") || strings.Contains(line, "memory.read") || strings.Contains(line, "memory.share") {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("该项得分: %.1f / %.0f，记忆隔离不足", score, rule.Weight),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found && len(skill.Files) > 0 {
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "低风险",
				Title:       rule.Name,
				Description: fmt.Sprintf("该项得分: %.1f / %.0f，记忆隔离不足", score, rule.Weight),
				Location:    filepath.Base(skill.Files[0].Path),
				CodeSnippet: "未定位到具体行，请检查跨任务数据共享或内存读写操作。",
			})
		}
	}
	return score, false, "", details
}

func (e *Evaluator) evaluateInjectionRiskFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	score := e.evaluateInjectionRisk(skill)
	var details []FindingDetail
	if score < rule.Weight {
		found := false
		for _, file := range skill.Files {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				if (strings.Contains(line, "exec.Command") && strings.Contains(line, "input")) ||
					(strings.Contains(line, "os.system") && strings.Contains(line, "input")) ||
					(strings.Contains(line, "eval(")) {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "中风险",
						Title:       rule.Name,
						Description: fmt.Sprintf("该项得分: %.1f / %.0f，存在命令注入风险", score, rule.Weight),
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found && len(skill.Files) > 0 {
			details = append(details, FindingDetail{
				RuleID:      rule.ID,
				Severity:    "中风险",
				Title:       rule.Name,
				Description: fmt.Sprintf("该项得分: %.1f / %.0f，存在命令注入风险", score, rule.Weight),
				Location:    filepath.Base(skill.Files[0].Path),
				CodeSnippet: "未定位到具体行，请检查动态命令执行或 eval 调用。",
			})
		}
	}
	return score, false, "", details
}

// locateRiskInFiles 根据 LLM 风险描述尝试在代码中定位具体行
func (e *Evaluator) locateRiskInFiles(skill *Skill, risk llm.RiskItem) (location, snippet string, found bool) {
	text := strings.ToLower(risk.Title + " " + risk.Description)

	// 硬编码敏感信息
	if strings.Contains(text, "hardcode") || strings.Contains(text, "硬编码") {
		patterns := []string{
			`(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']+["']`,
			`(?i)(api[_-]?key|apikey|secret|token)\s*[:=]\s*["'][^"']+["']`,
			`(?i)(private[_-]?key|privkey)\s*[:=]\s*["'][^"']+["']`,
		}
		for _, file := range skill.Files {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
					continue
				}
				for _, pat := range patterns {
					if matched, _ := regexp.MatchString(pat, line); matched {
						return fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
							formatCodeContext(lines, i, 2), true
					}
				}
			}
		}
	}

	// 许可证/配置问题
	if strings.Contains(text, "license") || strings.Contains(text, "许可证") {
		for _, file := range skill.Files {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
					continue
				}
				if matched, _ := regexp.MatchString(`(?i)(license|verify|localhost:8080)`, line); matched {
					return fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						formatCodeContext(lines, i, 2), true
				}
			}
		}
	}

	// 错误处理问题：查找仅记录日志但未返回或处理的错误
	if strings.Contains(text, "error") && (strings.Contains(text, "handling") || strings.Contains(text, "处理")) {
		for _, file := range skill.Files {
			lines := strings.Split(file.Content, "\n")
			for i, line := range lines {
				if matched, _ := regexp.MatchString(`log.*(Error|error|ERROR).*\)\s*$`, line); matched {
					return fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						formatCodeContext(lines, i, 2), true
				}
			}
		}
	}

	// 未找到，回退静态分析
	if result := e.runStaticAnalysis(skill); result != nil && len(result.DangerousCalls) > 0 {
		call := result.DangerousCalls[0]
		return fmt.Sprintf("示例: 行 %d", call.Line), fmt.Sprintf("危险调用: %s", call.Function), true
	}
	return "", "", false
}

// extractKeywordsFromRisk 从风险标题/描述中提取搜索关键词
func extractKeywordsFromRisk(risk llm.RiskItem) []string {
	text := strings.ToLower(risk.Title + " " + risk.Description)
	var keywords []string
	if strings.Contains(text, "硬编码") || strings.Contains(text, "hardcode") {
		keywords = append(keywords, "private_key", "apikey", "password", "secret", "token")
	}
	if strings.Contains(text, "许可证") || strings.Contains(text, "license") {
		keywords = append(keywords, "license", "verify", "localhost:8080")
	}
	if strings.Contains(text, "输入验证") || strings.Contains(text, "validation") {
		keywords = append(keywords, "input", "validate", "sanitize")
	}
	// 默认返回通用敏感词
	if len(keywords) == 0 {
		keywords = []string{"key", "secret", "token", "password", "http://", "https://"}
	}
	return keywords
}

func buildLLMRiskDescription(risk llm.RiskItem, llmResult *llm.AnalysisResult) string {
	parts := make([]string, 0, 4)
	if d := strings.TrimSpace(risk.Description); d != "" {
		parts = append(parts, d)
	}
	if ev := strings.TrimSpace(risk.Evidence); ev != "" {
		parts = append(parts, "关键证据: "+ev)
	}
	if llmResult != nil {
		if stated := strings.TrimSpace(llmResult.StatedIntent); stated != "" {
			parts = append(parts, "声明意图: "+stated)
		}
		if actual := strings.TrimSpace(llmResult.ActualBehavior); actual != "" {
			parts = append(parts, "实际行为: "+actual)
		}
	}
	if len(parts) == 0 {
		return "LLM 检测到潜在风险，但未返回可展示的解释信息"
	}
	return strings.Join(parts, "；")
}

func (e *Evaluator) detectFileUploadVulnerabilitiesFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	patterns := []struct {
		pattern string
		desc    string
	}{
		{`upload.*file`, "检测到文件上传功能"},
		{`multipart/form-data`, "检测到 Multipart 表单上传"},
		{`file\.path\.ext`, "检测到文件扩展名处理"},
	}
	hasTypeCheck := false
	hasSizeCheck := false
	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			if matched, _ := regexp.MatchString(`(?i)(file_type|filetype|mime|content.type)`, line); matched && !hasTypeCheck {
				hasTypeCheck = true
			}
			if matched, _ := regexp.MatchString(`(?i)(file_size|filesize|max.*size|size.*limit)`, line); matched && !hasSizeCheck {
				hasSizeCheck = true
			}
			for _, p := range patterns {
				if matched, _ := regexp.MatchString(p.pattern, line); matched {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "高风险",
						Title:       rule.Name,
						Description: rule.OnFail.Reason + ": " + p.desc,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break
				}
			}
		}
	}
	if len(details) > 0 {
		if !hasTypeCheck || !hasSizeCheck {
			return 0, true, rule.OnFail.Reason, details
		}
		return 0, false, "检测到文件上传功能但存在基本检查", details
	}
	return rule.Weight, false, "", nil
}

func (e *Evaluator) detectPrivacyComplianceFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	patterns := []struct {
		pattern string
		desc    string
	}{
		{`(?i)(身份证|IDcard|id_card)`, "检测到身份证号收集"},
		{`(?i)(手机|phone|mobile).*(验证|采集|存储)`, "检测到手机号收集"},
		{`(?i)(人脸|face|生物)`, "检测到生物特征收集"},
		{`(?i)(location|地理位置|gps|坐标)`, "检测到位置信息收集"},
		{`(?i)(bank.*card|银行卡|信用卡)`, "检测到金融信息收集"},
	}
	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			for _, p := range patterns {
				if matched, _ := regexp.MatchString(p.pattern, line); matched {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "高风险",
						Title:       rule.Name,
						Description: rule.OnFail.Reason + ": " + p.desc,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break
				}
			}
		}
	}
	if len(details) > 0 {
		return 0, false, rule.OnFail.Reason, details
	}
	return rule.Weight, false, "", nil
}

func (e *Evaluator) detectPromptInjectionProtectionFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	injectionPatterns := []string{
		`(?i)(ignore|disregard).*instruction`,
		`(?i)system.*prompt`,
		`(?i)你是.*(扮演|假装)`,
		`<!--.*-->`,
		`\{%.*%\}`,
	}
	protectionPatterns := []string{
		`(?i)sanitize`,
		`(?i)validate.*input`,
		`(?i)filter.*prompt`,
		`(?i)escape`,
	}
	hasProtection := false
	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			for _, p := range protectionPatterns {
				if matched, _ := regexp.MatchString(p, line); matched {
					hasProtection = true
					break
				}
			}
			for _, p := range injectionPatterns {
				if matched, _ := regexp.MatchString(p, line); matched {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "高风险",
						Title:       rule.Name,
						Description: rule.OnFail.Reason + ": 检测到潜在注入模式",
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break
				}
			}
		}
	}
	if len(details) > 0 {
		if !hasProtection {
			return 0, true, rule.OnFail.Reason, details
		}
		return 0, false, "检测到注入风险但存在防护措施", details
	}
	return rule.Weight, false, "", nil
}

func (e *Evaluator) detectContentSafetyFunc(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail) {
	var details []FindingDetail
	patterns := []struct {
		pattern string
		desc    string
	}{
		{`(?i)(output.*filter|content.*filter|output.*check)`, "检测到输出过滤"},
		{`(?i)(toxic|harmful|offensive).*detect`, "检测到有害内容检测"},
		{`(?i)(敏感词|违禁词|黑名单)`, "检测到敏感词过滤"},
	}
	for _, file := range skill.Files {
		lines := strings.Split(file.Content, "\n")
		for i, line := range lines {
			for _, p := range patterns {
				if matched, _ := regexp.MatchString(p.pattern, line); matched {
					detail := FindingDetail{
						RuleID:      rule.ID,
						Severity:    "低风险",
						Title:       rule.Name,
						Description: p.desc,
						Location:    fmt.Sprintf("%s:%d", filepath.Base(file.Path), i+1),
						CodeSnippet: formatCodeContext(lines, i, 2),
					}
					details = append(details, detail)
					break
				}
			}
		}
	}
	if len(details) > 0 {
		return rule.Weight, false, "", details
	}
	return rule.Weight * 0.5, false, "未检测到内容安全审核机制", details
}
