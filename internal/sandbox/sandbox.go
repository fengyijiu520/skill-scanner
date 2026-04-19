package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
)

// SandboxConfig 沙箱运行配置
type SandboxConfig struct {
	Timeout     time.Duration // 运行超时
	CPUQuota    int64         // CPU 配额，单位微秒/100ms（50000 = 0.5核）
	MemoryLimit int64         // 内存限制，单位字节
	EnableNet   bool          // 是否允许网络
}

// SandboxResult 沙箱执行结果
type SandboxResult struct {
	Logs           string         // 合并的标准输出和错误输出
	ExitCode       int64          // 容器退出码
	TimedOut       bool           // 是否超时
	SyscallSummary map[string]int // 系统调用统计
	NetworkEvents  []NetworkEvent // 网络事件列表
	C2Indicators   []C2Indicator  // C2通信指标
	RiskLevel      string         // low/medium/high/blocked
	RiskReasons    []string       // 风险原因
}

// NetworkEvent 网络事件
type NetworkEvent struct {
	Type      string // connect/dns/request
	Target    string // 目标地址
	Port      string // 端口
	Timestamp string // 时间戳
}

// C2Indicator C2通信指标
type C2Indicator struct {
	Type        string // suspicious_port/metricpreter/c2_domain
	Description string // 描述
	Target      string // 相关目标
	Severity    string // high/medium/low
}

// DefaultConfig 默认配置（禁用网络、0.5核、128MB、10秒超时）
func DefaultConfig() SandboxConfig {
	return SandboxConfig{
		Timeout:     10 * time.Second,
		CPUQuota:    50000,             // 0.5 核（周期 100ms 内最多使用 50ms CPU）
		MemoryLimit: 128 * 1024 * 1024, // 128 MB
		EnableNet:   false,
	}
}

// RunSandbox 在隔离容器中运行技能代码，返回结构化分析结果
func RunSandbox(ctx context.Context, codeDir string, lang string) (*SandboxResult, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("初始化 Docker 客户端失败: %w", err)
	}
	defer cli.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := cli.Ping(pingCtx); err != nil {
		return nil, fmt.Errorf("Docker 服务不可用: %w", err)
	}

	image, cmd, err := selectImageAndCommand(codeDir, lang)
	if err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	cfg.Timeout = 30 * time.Second

	containerConfig := &container.Config{
		Image:      image,
		Cmd:        cmd,
		WorkingDir: "/app",
		Tty:        false,
	}

	hostConfig := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeBind,
				Source:   codeDir,
				Target:   "/app",
				ReadOnly: false,
			},
		},
		Resources: container.Resources{
			CPUQuota:  cfg.CPUQuota,
			CPUPeriod: 100000,
			Memory:    cfg.MemoryLimit,
		},
		AutoRemove: false,
	}

	if cfg.EnableNet {
		hostConfig.NetworkMode = "bridge"
	} else {
		hostConfig.NetworkMode = "none"
	}

	resp, err := cli.ContainerCreate(ctx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return nil, fmt.Errorf("创建容器失败: %w", err)
	}
	containerID := resp.ID

	defer func() {
		cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanCancel()
		_ = cli.ContainerRemove(cleanCtx, containerID, types.ContainerRemoveOptions{Force: true})
	}()

	var (
		auditCleanup    func()
		syscallSummary  = make(map[string]int)
		networkEvents   []NetworkEvent
		c2Indicators    []C2Indicator
		auditLogContent string
	)

	if _, err := exec.LookPath("auditctl"); err == nil {
		inspect, err := cli.ContainerInspect(ctx, containerID)
		if err == nil && inspect.State != nil && inspect.State.Pid > 0 {
			pid := inspect.State.Pid
			cmdExec := exec.Command("auditctl", "-D")
			cmdExec.Run()
			cmdExec = exec.Command("auditctl", "-a", "exit,always", "-F", fmt.Sprintf("pid=%d", pid))
			if err := cmdExec.Run(); err == nil {
				auditCleanup = func() {
					cmd := exec.Command("auditctl", "-d", "exit,always", "-F", fmt.Sprintf("pid=%d", pid))
					cmd.Run()
				}
				go func() {
					cmd := exec.Command("ausearch", "-p", fmt.Sprintf("%d", pid), "--start", "recent", "-i")
					var out bytes.Buffer
					cmd.Stdout = &out
					cmd.Run()
					auditLogContent = out.String()
				}()
			}
		}
	}

	if err := cli.ContainerStart(ctx, containerID, types.ContainerStartOptions{}); err != nil {
		return nil, fmt.Errorf("启动容器失败: %w", err)
	}

	waitCh, errCh := cli.ContainerWait(ctx, containerID, container.WaitConditionNotRunning)
	timedOut := false

	select {
	case <-time.After(cfg.Timeout):
		log.Printf("沙箱运行超时 (%v)，强制终止容器 %s", cfg.Timeout, containerID[:12])
		killCtx, killCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer killCancel()
		_ = cli.ContainerKill(killCtx, containerID, "SIGKILL")
		<-waitCh
		timedOut = true
	case err := <-errCh:
		if err != nil {
			return nil, fmt.Errorf("容器等待错误: %w", err)
		}
	case <-waitCh:
	}

	if auditCleanup != nil {
		auditCleanup()
	}

	logs, err := getContainerLogs(ctx, cli, containerID)
	if err != nil {
		return nil, fmt.Errorf("获取容器日志失败: %w", err)
	}

	result := &SandboxResult{
		Logs:           logs,
		TimedOut:       timedOut,
		SyscallSummary: syscallSummary,
		NetworkEvents:  networkEvents,
		C2Indicators:   c2Indicators,
		RiskLevel:      "low",
		RiskReasons:    []string{},
	}

	if timedOut {
		result.RiskLevel = "medium"
		result.RiskReasons = append(result.RiskReasons, "执行超时")
	}

	result.analyzeSyscalls(auditLogContent)
	result.analyzeNetworkEvents()
	result.analyzeC2Indicators()
	result.analyzeLogsForRisk()

	return result, nil
}

func (r *SandboxResult) analyzeSyscalls(logContent string) {
	if logContent == "" {
		return
	}
	syscallCounts := make(map[string]int)
	sensitiveSyscalls := map[string]bool{
		"execve":   true,
		"execveat": true,
		"ptrace":   true,
		"mount":    true,
		"umount":   true,
		"chroot":   true,
		"unshare":  true,
		"capset":   true,
		"connect":  true,
		"sendto":   true,
	}
	sensitivePaths := []string{
		"/etc/passwd", "/etc/shadow", "/root/.ssh", "/home/",
		"/proc/kcore", "/dev/kmem", "/dev/mem",
	}

	lines := strings.Split(logContent, "\n")
	for _, line := range lines {
		for syscall := range sensitiveSyscalls {
			if strings.Contains(line, syscall) {
				syscallCounts[syscall]++
				r.SyscallSummary[syscall]++
			}
		}
		for _, path := range sensitivePaths {
			if strings.Contains(line, path) {
				r.RiskLevel = "high"
				r.RiskReasons = append(r.RiskReasons, fmt.Sprintf("访问敏感路径: %s", path))
			}
		}
	}
}

func (r *SandboxResult) analyzeNetworkEvents() {
	if len(r.NetworkEvents) == 0 {
		return
	}
	for _, event := range r.NetworkEvents {
		if event.Port == "4444" || event.Port == "5555" || event.Port == "6666" || event.Port == "1337" {
			r.C2Indicators = append(r.C2Indicators, C2Indicator{
				Type:        "suspicious_port",
				Description: fmt.Sprintf("连接异常端口 %s", event.Port),
				Target:      event.Target,
				Severity:    "high",
			})
			r.RiskLevel = "blocked"
			r.RiskReasons = append(r.RiskReasons, fmt.Sprintf("检测到可疑端口连接: %s", event.Port))
		}
	}
}

func (r *SandboxResult) analyzeC2Indicators() {
	logLower := strings.ToLower(r.Logs)
	c2Patterns := []struct {
		pattern  string
		desc     string
		severity string
	}{
		{`stratum\+tcp://`, "加密货币挖矿协议", "high"},
		{`pool\.mine`, "挖矿池连接", "high"},
		{`meterpreter`, "Metasploit meterpreter", "high"},
		{`beacon\.`, "C2 beacon特征", "high"},
		{`c2\.malware`, "已知恶意C2域名", "high"},
		{`:4444`, "Metasploit默认端口", "high"},
		{`:5555`, "可疑端口", "medium"},
		{`:6666`, "可疑端口", "medium"},
		{`:1337`, "可疑端口", "medium"},
	}

	for _, p := range c2Patterns {
		if strings.Contains(logLower, p.pattern) {
			r.C2Indicators = append(r.C2Indicators, C2Indicator{
				Type:        "c2_signature",
				Description: p.desc,
				Target:      p.pattern,
				Severity:    p.severity,
			})
			if p.severity == "high" {
				r.RiskLevel = "blocked"
				r.RiskReasons = append(r.RiskReasons, p.desc)
			}
		}
	}
}

func (r *SandboxResult) analyzeLogsForRisk() {
	if r.RiskLevel == "blocked" {
		return
	}
	logLower := strings.ToLower(r.Logs)
	riskPatterns := []struct {
		pattern  string
		reason   string
		severity string
	}{
		{`rm\s+-rf\s+/`, "检测到破坏性删除命令", "high"},
		{`chmod\s+777`, "检测到过度宽松的权限", "medium"},
		{`curl.*eval`, "检测到远程代码执行尝试", "high"},
		{`bash\s+-i.*>/dev/tcp`, "检测到反向Shell", "high"},
		{`nc\s+-e\s+/bin/sh`, "检测到Netcat后门", "high"},
	}

	for _, p := range riskPatterns {
		if matched, _ := regexp.MatchString(p.pattern, logLower); matched {
			if p.severity == "high" {
				r.RiskLevel = "high"
				r.RiskReasons = append(r.RiskReasons, p.reason)
			} else if p.severity == "medium" && r.RiskLevel != "high" {
				r.RiskLevel = "medium"
				r.RiskReasons = append(r.RiskReasons, p.reason)
			}
		}
	}
}

// RunSandboxLegacy 保留旧接口，返回 (string, error) 格式的日志
// 建议使用 RunSandbox 获取结构化分析结果
func RunSandboxLegacy(ctx context.Context, codeDir string, lang string) (string, error) {
	result, err := RunSandbox(ctx, codeDir, lang)
	if err != nil {
		return "", err
	}
	return result.Logs, nil
}

// 辅助函数：获取容器日志
func getContainerLogs(ctx context.Context, cli *client.Client, containerID string) (string, error) {
	logs, err := cli.ContainerLogs(ctx, containerID, types.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return "", err
	}
	defer logs.Close()

	var stdoutBuf, stderrBuf bytes.Buffer
	_, err = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, logs)
	if err != nil {
		return "", err
	}

	combined := stdoutBuf.String()
	if stderrBuf.Len() > 0 {
		combined += "\n[stderr]\n" + stderrBuf.String()
	}
	return combined, nil
}

// IsSandboxAvailable 检查 Docker 环境是否可用
func IsSandboxAvailable() bool {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return false
	}
	defer cli.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = cli.Ping(ctx)
	return err == nil
}

// selectImageAndCommand 根据语言及代码目录内容返回镜像和启动命令
func selectImageAndCommand(codeDir string, lang string) (image string, cmd []string, err error) {
	image = "skill-sandbox:latest"

	switch lang {
	case "go":
		mainFile := findFile(codeDir, "main.go")
		if mainFile == "" {
			cmd = []string{"go", "run", "."}
		} else {
			cmd = []string{"go", "run", mainFile}
		}

	case "python":
		entry := findFile(codeDir, "main.py", "app.py", "run.py")
		if entry == "" {
			matches, _ := filepath.Glob(filepath.Join(codeDir, "*.py"))
			if len(matches) > 0 {
				entry = filepath.Base(matches[0])
			}
		}
		if entry == "" {
			return "", nil, fmt.Errorf("未找到 Python 入口文件")
		}
		cmd = []string{"python3", entry}

	case "javascript", "typescript":
		// 修复：添加 --ignore-scripts 禁止执行 postinstall 恶意脚本
		installCmd := "npm install --silent --ignore-scripts 2>/dev/null || true; "
		entry := findFile(codeDir, "index.js", "main.js", "app.js", "index.ts", "main.ts")
		if entry == "" {
			entry = "index.js"
		}
		cmd = []string{"sh", "-c", installCmd + "node " + entry}

	default:
		return "", nil, fmt.Errorf("不支持的语言: %s", lang)
	}
	return
}

// findFile 在目录中查找第一个存在的文件（按顺序），返回相对于目录的路径
func findFile(dir string, names ...string) string {
	for _, name := range names {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return name
		}
	}
	return ""
}

// DetectLanguage 检测代码目录主要语言（供外部调用）
func DetectLanguage(codeDir string) string {
	if _, err := os.Stat(filepath.Join(codeDir, "go.mod")); err == nil {
		return "go"
	}
	if _, err := os.Stat(filepath.Join(codeDir, "package.json")); err == nil {
		// 检查是否包含 TypeScript 特征
		if _, err := os.Stat(filepath.Join(codeDir, "tsconfig.json")); err == nil {
			return "typescript"
		}
		return "javascript"
	}
	if _, err := os.Stat(filepath.Join(codeDir, "requirements.txt")); err == nil {
		return "python"
	}
	if matches, _ := filepath.Glob(filepath.Join(codeDir, "*.py")); len(matches) > 0 {
		return "python"
	}
	if matches, _ := filepath.Glob(filepath.Join(codeDir, "*.go")); len(matches) > 0 {
		return "go"
	}
	if matches, _ := filepath.Glob(filepath.Join(codeDir, "*.js")); len(matches) > 0 {
		return "javascript"
	}
	return ""
}

// HasMaliciousIndicators 分析日志和代码中的恶意行为特征
// 同时检查代码内容和运行输出，避免恶意代码隐藏输出
func HasMaliciousIndicators(codeContent string, logs string) bool {
	// 合并代码和日志，一起检查
	checkContent := strings.ToLower(codeContent + "\n" + logs)
	keywords := []string{
		"/etc/passwd", "/etc/shadow", "/root/.ssh", "/home/",
		"rm -rf", "chmod 777", "curl ", "wget ", "nc ", "bash -i",
		"sudo ", "su ", "passwd", "ssh-", "id_rsa", "eval(", "exec(",
		"__import__('os')", "subprocess.", "os.system", "child_process",
	}
	for _, kw := range keywords {
		if strings.Contains(checkContent, kw) {
			return true
		}
	}
	return false
}
