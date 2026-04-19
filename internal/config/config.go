package config

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

// Config 整体配置结构
type Config struct {
	Version          string                 `yaml:"version"`
	RiskLevels       []RiskLevel            `yaml:"risk_levels"`
	Rules            []Rule                 `yaml:"rules"`
	P0Rules          []Rule                 `yaml:"p0_rules"`
	P1Rules          []Rule                 `yaml:"p1_rules"`
	P2Rules          []Rule                 `yaml:"p2_rules"`
	CapabilityFusion CapabilityFusionConfig `yaml:"capability_fusion"`
	Thresholds       EvaluationThresholds   `yaml:"thresholds"`
	Cache            CacheConfig            `yaml:"cache"`
}

// RiskLevel 风险等级阈值定义
type RiskLevel struct {
	Threshold     float64 `yaml:"threshold"`
	Level         string  `yaml:"level"`
	AutoApprove   bool    `yaml:"auto_approve"`
	RequireReview bool    `yaml:"require_review"`
	Block         bool    `yaml:"block"`
}

// EvaluationThresholds 准入评估阈值
type EvaluationThresholds struct {
	AutoApprove  float64 `yaml:"auto_approve"`  // ≥85分自动通过
	ManualReview float64 `yaml:"manual_review"` // 60-84分需人工审核
	Block        float64 `yaml:"block"`         // <60分禁止准入
}

// CacheConfig 缓存配置
type CacheConfig struct {
	Enabled        bool          `yaml:"enabled"`         // 是否启用缓存
	MaxSize        int           `yaml:"max_size"`        // 最大缓存条目数（0=无限制）
	Expiration     time.Duration `yaml:"expiration"`      // 缓存过期时间
	EvictionPolicy string        `yaml:"eviction_policy"` // 淘汰策略：lru / fifo / lfu
}

// DefaultCacheConfig 返回默认缓存配置
func DefaultCacheConfig() CacheConfig {
	return CacheConfig{
		Enabled:        true,
		MaxSize:        1000,
		Expiration:     24 * time.Hour,
		EvictionPolicy: "lru",
	}
}

// Rule 单条规则定义
type Rule struct {
	ID              string    `yaml:"id"`
	Name            string    `yaml:"name"`
	Description     string    `yaml:"description"` // 规则描述
	Layer           string    `yaml:"layer"`       // P0 / P1 / P2
	Weight          float64   `yaml:"weight"`      // 权重分（P1层使用）
	Detection       Detection `yaml:"detection"`
	Whitelist       []string  `yaml:"whitelist_patterns"`
	WhitelistCtx    []string  `yaml:"whitelist_context_patterns"`
	WhitelistDeny   []string  `yaml:"whitelist_deny_patterns"`
	OnFail          OnFail    `yaml:"on_fail"`
	Compensation    bool      `yaml:"compensation"`
	ScoreDeduction  float64   `yaml:"score_deduction"`  // 无补偿时扣分
	BlockConditions []string  `yaml:"block_conditions"` // 一票否决条件列表
	DeductScore     float64   `yaml:"deduct_score"`     // 扣分值
	Severity        string    `yaml:"severity"`         // critical/high/medium/low
	Remediation     string    `yaml:"remediation"`      // 整改要求（P2层使用）
}

// Detection 检测方式配置
type Detection struct {
	Type          string   `yaml:"type"`          // pattern / function / semantic
	Function      string   `yaml:"function"`      // 函数名（type=function时）
	Patterns      []string `yaml:"patterns"`      // 正则列表（type=pattern时）
	ThresholdLow  float64  `yaml:"threshold_low"` // semantic用
	ThresholdHigh float64  `yaml:"threshold_high"`
}

// OnFail 失败处理配置
type OnFail struct {
	Action              string  `yaml:"action"`                // block / deduct
	Reason              string  `yaml:"reason"`                // 阻断原因
	DefaultDeduction    float64 `yaml:"default_deduction"`     // 有补偿时的扣分
	NoCompensationBlock bool    `yaml:"no_compensation_block"` // 无补偿是否阻断
}

// CapabilityFusionConfig 能力融合配置
type CapabilityFusionConfig struct {
	Enabled             bool             `yaml:"enabled"`
	ScoreBase           float64          `yaml:"score_base"`
	ScoreFusion         ScoreFusion      `yaml:"score_fusion"`
	MatchBonus          float64          `yaml:"match_bonus"`
	OverreachMultiplier float64          `yaml:"overreach_multiplier"`
	UnderdeclarePenalty float64          `yaml:"underdeclare_penalty"`
	BlockOnOverreach    []string         `yaml:"block_on_overreach"`
	Thresholds          FusionThresholds `yaml:"thresholds"`
	Capabilities        []CapabilityItem `yaml:"capabilities"`
}

type ScoreFusion struct {
	BaseWeight       float64 `yaml:"base_weight"`
	CapabilityWeight float64 `yaml:"capability_weight"`
}

type FusionThresholds struct {
	Critical float64 `yaml:"critical"`
	High     float64 `yaml:"high"`
	Medium   float64 `yaml:"medium"`
}

type CapabilityItem struct {
	ID               string   `yaml:"id"`
	DisplayName      string   `yaml:"display_name"`
	RiskCategory     string   `yaml:"risk_category"`
	Weight           float64  `yaml:"weight"`
	DeclaredKeywords []string `yaml:"declared_keywords"`
	ObservedKeywords []string `yaml:"observed_keywords"`
	NoiseKeywords    []string `yaml:"noise_keywords"`
	FindingKeywords  []string `yaml:"finding_keywords"`
}

func DefaultCapabilityFusionConfig() CapabilityFusionConfig {
	return CapabilityFusionConfig{
		Enabled:             true,
		ScoreBase:           100,
		ScoreFusion:         ScoreFusion{BaseWeight: 0.65, CapabilityWeight: 0.35},
		MatchBonus:          4,
		OverreachMultiplier: 18,
		UnderdeclarePenalty: 9,
		BlockOnOverreach:    []string{"code_exec", "secret_access"},
		Thresholds: FusionThresholds{
			Critical: 80,
			High:     60,
			Medium:   35,
		},
		Capabilities: []CapabilityItem{
			{ID: "file_read", DisplayName: "文件读取", RiskCategory: "数据访问", Weight: 1.0, DeclaredKeywords: []string{"read", "读取", "文件读取"}, ObservedKeywords: []string{"os.readfile", "readfile(", "open("}, NoiseKeywords: []string{"readme", "reader"}, FindingKeywords: []string{"读取", "read"}},
			{ID: "file_write", DisplayName: "文件写入", RiskCategory: "数据改写", Weight: 1.2, DeclaredKeywords: []string{"write", "写入", "文件写入"}, ObservedKeywords: []string{"os.writefile", "os.create(", "writefile("}, NoiseKeywords: []string{"writer", "rewrite"}, FindingKeywords: []string{"写入", "write"}},
			{ID: "net_outbound", DisplayName: "网络外联", RiskCategory: "数据外发", Weight: 1.8, DeclaredKeywords: []string{"network", "网络", "http", "api"}, ObservedKeywords: []string{"http.get", "http.post", "fetch(", "requests.", "net.dial"}, NoiseKeywords: []string{"httpserver", "api_docs"}, FindingKeywords: []string{"数据外发", "network", "http"}},
			{ID: "code_exec", DisplayName: "代码执行", RiskCategory: "执行控制", Weight: 2.4, DeclaredKeywords: []string{"exec", "执行", "命令", "command"}, ObservedKeywords: []string{"exec.command", "os.system", "subprocess", "child_process", "eval("}, NoiseKeywords: []string{"example", "test_helper"}, FindingKeywords: []string{"exec", "代码执行", "命令", "沙箱"}},
			{ID: "secret_access", DisplayName: "敏感凭据访问", RiskCategory: "敏感信息处理", Weight: 2.6, DeclaredKeywords: []string{"secret", "凭据", "密钥", "token"}, ObservedKeywords: []string{"token", "secret", "password", ".ssh"}, NoiseKeywords: []string{"secret_name", "tokenizer"}, FindingKeywords: []string{"凭证", "secret", "token", "context"}},
		},
	}
}

func DefaultEvaluationThresholds() EvaluationThresholds {
	return EvaluationThresholds{
		AutoApprove:  85,
		ManualReview: 60,
		Block:        0,
	}
}

func (c *Config) applyDefaults() {
	thresholds := DefaultEvaluationThresholds()
	if c.Thresholds.AutoApprove <= 0 {
		c.Thresholds.AutoApprove = thresholds.AutoApprove
	}
	if c.Thresholds.ManualReview <= 0 {
		c.Thresholds.ManualReview = thresholds.ManualReview
	}
	if c.Thresholds.Block <= 0 {
		c.Thresholds.Block = thresholds.Block
	}

	cacheDefaults := DefaultCacheConfig()
	if c.Cache.Expiration <= 0 {
		c.Cache.Expiration = cacheDefaults.Expiration
	}
	if c.Cache.MaxSize <= 0 {
		c.Cache.MaxSize = cacheDefaults.MaxSize
	}
	if c.Cache.EvictionPolicy == "" {
		c.Cache.EvictionPolicy = cacheDefaults.EvictionPolicy
	}

	def := DefaultCapabilityFusionConfig()
	if !c.CapabilityFusion.Enabled {
		c.CapabilityFusion.Enabled = def.Enabled
	}
	if c.CapabilityFusion.ScoreBase <= 0 {
		c.CapabilityFusion.ScoreBase = def.ScoreBase
	}
	if c.CapabilityFusion.ScoreFusion.BaseWeight < 0 {
		c.CapabilityFusion.ScoreFusion.BaseWeight = def.ScoreFusion.BaseWeight
	}
	if c.CapabilityFusion.ScoreFusion.CapabilityWeight < 0 {
		c.CapabilityFusion.ScoreFusion.CapabilityWeight = def.ScoreFusion.CapabilityWeight
	}
	if c.CapabilityFusion.ScoreFusion.BaseWeight+c.CapabilityFusion.ScoreFusion.CapabilityWeight <= 0 {
		c.CapabilityFusion.ScoreFusion = def.ScoreFusion
	}
	if c.CapabilityFusion.MatchBonus <= 0 {
		c.CapabilityFusion.MatchBonus = def.MatchBonus
	}
	if c.CapabilityFusion.OverreachMultiplier <= 0 {
		c.CapabilityFusion.OverreachMultiplier = def.OverreachMultiplier
	}
	if c.CapabilityFusion.UnderdeclarePenalty <= 0 {
		c.CapabilityFusion.UnderdeclarePenalty = def.UnderdeclarePenalty
	}
	if len(c.CapabilityFusion.BlockOnOverreach) == 0 {
		c.CapabilityFusion.BlockOnOverreach = def.BlockOnOverreach
	}
	if c.CapabilityFusion.Thresholds.Critical <= 0 {
		c.CapabilityFusion.Thresholds.Critical = def.Thresholds.Critical
	}
	if c.CapabilityFusion.Thresholds.High <= 0 {
		c.CapabilityFusion.Thresholds.High = def.Thresholds.High
	}
	if c.CapabilityFusion.Thresholds.Medium <= 0 {
		c.CapabilityFusion.Thresholds.Medium = def.Thresholds.Medium
	}
	if len(c.CapabilityFusion.Capabilities) == 0 {
		c.CapabilityFusion.Capabilities = def.Capabilities
		return
	}
	for i := range c.CapabilityFusion.Capabilities {
		if c.CapabilityFusion.Capabilities[i].DisplayName == "" {
			c.CapabilityFusion.Capabilities[i].DisplayName = c.CapabilityFusion.Capabilities[i].ID
		}
		if c.CapabilityFusion.Capabilities[i].RiskCategory == "" {
			c.CapabilityFusion.Capabilities[i].RiskCategory = "能力行为一致性"
		}
	}
}

// Load 从指定路径加载配置文件
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置验证失败: %w", err)
	}
	return &cfg, nil
}

// Validate 验证配置有效性
func (c *Config) Validate() error {
	if c.Thresholds.AutoApprove <= 0 || c.Thresholds.AutoApprove > 100 {
		return fmt.Errorf("阈值 AutoApprove 必须介于 0-100 之间，当前值: %.1f", c.Thresholds.AutoApprove)
	}
	if c.Thresholds.ManualReview <= 0 || c.Thresholds.ManualReview > 100 {
		return fmt.Errorf("阈值 ManualReview 必须介于 0-100 之间，当前值: %.1f", c.Thresholds.ManualReview)
	}
	if c.Thresholds.AutoApprove < c.Thresholds.ManualReview {
		return fmt.Errorf("阈值 AutoApprove (%.1f) 必须 >= ManualReview (%.1f)", c.Thresholds.AutoApprove, c.Thresholds.ManualReview)
	}

	p1WeightTotal := 0.0
	for _, rule := range c.P1Rules {
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("P1规则 %s 验证失败: %w", rule.ID, err)
		}
		p1WeightTotal += rule.Weight
	}

	for _, rule := range c.P0Rules {
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("P0规则 %s 验证失败: %w", rule.ID, err)
		}
		if rule.Layer != "P0" {
			return fmt.Errorf("P0规则 %s 的 Layer 应为 P0，实际为 %s", rule.ID, rule.Layer)
		}
	}

	for _, rule := range c.P2Rules {
		if err := validateRule(rule); err != nil {
			return fmt.Errorf("P2规则 %s 验证失败: %w", rule.ID, err)
		}
		if rule.Layer != "P2" {
			return fmt.Errorf("P2规则 %s 的 Layer 应为 P2，实际为 %s", rule.ID, rule.Layer)
		}
	}

	if len(c.P1Rules) > 0 && (p1WeightTotal < 80 || p1WeightTotal > 120) {
		return fmt.Errorf("P1层权重总分应约为100，当前为 %.1f（偏差 %.1f%%）", p1WeightTotal, (100-p1WeightTotal)*-1)
	}

	for _, pattern := range getAllPatterns(c.P0Rules, c.P1Rules, c.P2Rules) {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("无效的正则表达式: %s - %v", pattern, err)
		}
	}

	return nil
}

func validateRule(rule Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("规则ID不能为空")
	}
	if rule.Name == "" {
		return fmt.Errorf("规则 %s 名称不能为空", rule.ID)
	}
	if rule.Layer != "P0" && rule.Layer != "P1" && rule.Layer != "P2" {
		return fmt.Errorf("规则 %s Layer 必须为 P0/P1/P2 之一，实际为 %s", rule.ID, rule.Layer)
	}
	if rule.Layer == "P1" && rule.Weight <= 0 {
		return fmt.Errorf("P1规则 %s 权重必须大于0", rule.ID)
	}
	if rule.Detection.Type == "" {
		return fmt.Errorf("规则 %s 检测类型不能为空", rule.ID)
	}
	if rule.Detection.Type != "pattern" && rule.Detection.Type != "function" && rule.Detection.Type != "semantic" && rule.Detection.Type != "ast" {
		return fmt.Errorf("规则 %s 检测类型必须为 pattern/function/semantic/ast 之一，实际为 %s", rule.ID, rule.Detection.Type)
	}
	return nil
}

func getAllPatterns(rules ...[]Rule) []string {
	var patterns []string
	for _, ruleset := range rules {
		for _, rule := range ruleset {
			patterns = append(patterns, rule.Detection.Patterns...)
			patterns = append(patterns, rule.Whitelist...)
			patterns = append(patterns, rule.WhitelistCtx...)
			patterns = append(patterns, rule.WhitelistDeny...)
		}
	}
	return patterns
}
