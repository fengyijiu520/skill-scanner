package llm

import (
"bytes"
"context"
"encoding/json"
"fmt"
"net/http"
)

type deepseekClient struct {
apiKey string
}

// DeepSeek API request structure
type deepseekChatRequest struct {
Model       string              `json:"model"`
Messages    []deepseekChatMessage `json:"messages"`
Temperature float64             `json:"temperature"`
}

type deepseekChatMessage struct {
Role    string `json:"role"`
Content string `json:"content"`
}

// DeepSeek API response structure
type deepseekChatResponse struct {
Choices []struct {
Message struct {
Content string `json:"content"`
} `json:"message"`
} `json:"choices"`
Error struct {
Message string `json:"message"`
} `json:"error"`
}

func (c *deepseekClient) AnalyzeCode(ctx context.Context, name, description, codeSummary string) (*AnalysisResult, error) {
systemPrompt := `你是一位顶级的代码安全专家。请严格分析以下代码，并以JSON格式输出分析结果。
你的分析必须包含：
1. stated_intent: 代码声称的功能 (string)
2. actual_behavior: 代码的实际行为 (string)
3. intent_consistency: 意图一致性得分 (0-100的整数)
4. risks: 风险列表 (array of objects)，每项包含：
   - title: 风险标题
   - severity: 风险等级 (high/medium/low)
   - description: 风险描述
   - evidence: 代码证据 (string)
请确保你的回复仅包含一个有效的JSON对象，不要有任何其他文字。`
userPrompt := fmt.Sprintf("技能名称：%s\n技能描述：%s\n\n源代码：\n%s", 
name, description, codeSummary)

// 构造请求
reqBody := deepseekChatRequest{
Model: "deepseek-chat",
Messages: []deepseekChatMessage{
{Role: "system", Content: systemPrompt},
{Role: "user", Content: userPrompt},
},
Temperature: 0.1,
}

jsonData, err := json.Marshal(reqBody)
if err != nil {
return nil, fmt.Errorf("序列化请求失败: %w", err)
}

// 创建HTTP请求
req, err := http.NewRequestWithContext(ctx, "POST", 
"https://api.deepseek.com/chat/completions",
bytes.NewBuffer(jsonData))
if err != nil {
return nil, fmt.Errorf("创建请求失败: %w", err)
}
req.Header.Set("Content-Type", "application/json")
req.Header.Set("Authorization", "Bearer "+c.apiKey)

// 发送请求
client := &http.Client{}
resp, err := client.Do(req)
if err != nil {
return nil, fmt.Errorf("调用 DeepSeek API 失败: %w", err)
}
defer resp.Body.Close()

// 解析响应
var result deepseekChatResponse
if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
return nil, fmt.Errorf("解析响应失败: %w", err)
}

if result.Error.Message != "" {
return nil, fmt.Errorf("DeepSeek API 错误: %s", result.Error.Message)
}

if len(result.Choices) == 0 {
return nil, fmt.Errorf("DeepSeek API 返回空结果")
}

content := result.Choices[0].Message.Content
content = extractJSON(content)

var analysisResult AnalysisResult
if err := json.Unmarshal([]byte(content), &analysisResult); err != nil {
return nil, fmt.Errorf("解析 LLM 响应失败: %w", err)
}

return &analysisResult, nil
}
