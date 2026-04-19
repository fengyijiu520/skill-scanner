// Package templates holds all HTML template strings for the skill scanner web UI.
package templates

// LoginHTML is the login page template.
const LoginHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 400px; }
        h1 { text-align: center; color: #333; margin-bottom: 30px; font-size: 28px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        input { width: 100%; padding: 12px 16px; border: 2px solid #e1e1e1; border-radius: 8px; font-size: 16px; transition: border-color 0.3s; }
        input:focus { outline: none; border-color: #667eea; }
        .error { background: #fee; color: #c00; padding: 12px; border-radius: 6px; margin-bottom: 20px; text-align: center; }
        button { width: 100%; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 18px; font-weight: 600; cursor: pointer; transition: transform 0.2s; margin-bottom: 10px; }
        button:hover { transform: translateY(-2px); }
        .link-btn { background: none; color: #667eea; font-size: 14px; }
        .info { text-align: center; margin-top: 20px; color: #888; font-size: 14px; }
        .engine-status { position: fixed; bottom: 20px; right: 20px; background: rgba(255,255,255,0.9); padding: 6px 14px; border-radius: 30px; font-size: 13px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .engine-badge { display: inline-block; background: #667eea; color: white; padding: 2px 10px; border-radius: 12px; margin-left: 6px; }
        .engine-error { color: #c00; margin-left: 6px; cursor: help; border-bottom: 1px dashed #c00; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 技能扫描器</h1>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">用户名</label>
                <input type="text" id="username" name="username" placeholder="请输入用户名" required>
            </div>
            <div class="form-group">
                <label for="password">密码</label>
                <input type="password" id="password" name="password" placeholder="请输入密码" required>
            </div>
            <button type="submit">登 录</button>
        </form>
        <form method="GET" action="/change-password">
            <button type="submit" class="link-btn">修改密码</button>
        </form>
        <div class="info">默认账号: admin / admin123</div>
    </div>
    {{if .ModelStatus}}
    <div class="engine-status">
        <span>🧠 引擎状态</span>
        {{if .ModelError}}
        <span class="engine-error" title="{{.ModelError}}">⚠️ 未就绪</span>
        {{else}}
        <span class="engine-badge">{{.ModelStatus}}</span>
        {{end}}
    </div>
    {{end}}
</body>
</html>
`

// ChangePasswordHTML is the change password page template.
const ChangePasswordHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>修改密码 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); width: 100%; max-width: 400px; }
        h1 { text-align: center; color: #333; margin-bottom: 30px; font-size: 24px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; }
        input { width: 100%; padding: 12px 16px; border: 2px solid #e1e1e1; border-radius: 8px; font-size: 16px; transition: border-color 0.3s; }
        input:focus { outline: none; border-color: #667eea; }
        .error { background: #fee; color: #c00; padding: 12px; border-radius: 6px; margin-bottom: 20px; text-align: center; }
        .success { background: #efe; color: #060; padding: 12px; border-radius: 6px; margin-bottom: 20px; text-align: center; }
        button { width: 100%; padding: 14px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: transform 0.2s; }
        button:hover { transform: translateY(-2px); }
        .back-btn { display: block; text-align: center; margin-top: 15px; color: #667eea; text-decoration: none; }
        .engine-status { position: fixed; bottom: 20px; right: 20px; background: rgba(255,255,255,0.9); padding: 6px 14px; border-radius: 30px; font-size: 13px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .engine-badge { display: inline-block; background: #667eea; color: white; padding: 2px 10px; border-radius: 12px; margin-left: 6px; }
        .engine-error { color: #c00; margin-left: 6px; cursor: help; border-bottom: 1px dashed #c00; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔑 修改密码</h1>
        {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
        {{if .Success}}<div class="success">{{.Success}}</div>{{end}}
        <form method="POST" action="/change-password">
            <div class="form-group">
                <label for="old_password">当前密码</label>
                <input type="password" id="old_password" name="old_password" placeholder="请输入当前密码" required>
            </div>
            <div class="form-group">
                <label for="new_password">新密码</label>
                <input type="password" id="new_password" name="new_password" placeholder="请输入新密码" required>
            </div>
            <div class="form-group">
                <label for="confirm_password">确认新密码</label>
                <input type="password" id="confirm_password" name="confirm_password" placeholder="请再次输入新密码" required>
            </div>
            <button type="submit">确认修改</button>
        </form>
        <a href="/dashboard" class="back-btn">返回仪表盘</a>
    </div>
    {{if .ModelStatus}}
    <div class="engine-status">
        <span>🧠 引擎状态</span>
        {{if .ModelError}}
        <span class="engine-error" title="{{.ModelError}}">⚠️ 未就绪</span>
        {{else}}
        <span class="engine-badge">{{.ModelStatus}}</span>
        {{end}}
    </div>
    {{end}}
</body>
</html>
`

// DashboardHTML is the main dashboard template.
const DashboardHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>仪表盘 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-btn .arrow { font-size: 10px; }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .container { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        .welcome { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 30px; }
        .welcome h2 { color: #333; margin-bottom: 10px; }
        .welcome p { color: #666; line-height: 1.6; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; }
        .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); transition: transform 0.2s, box-shadow: 0.2s; text-align: center; }
        .card:hover { transform: translateY(-5px); box-shadow: 0 8px 25px rgba(0,0,0,0.1); }
        .card h3 { color: #333; margin-bottom: 12px; font-size: 18px; }
        .card p { color: #666; line-height: 1.6; font-size: 14px; margin-bottom: 20px; }
        .card .icon { font-size: 48px; margin-bottom: 14px; }
        .card-btn { display: inline-block; padding: 12px 28px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; text-decoration: none; transition: transform 0.2s; }
        .card-btn:hover { transform: translateY(-2px); }
        .section-title { color: #333; font-size: 20px; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #667eea; margin-top: 40px; }
        .report-list { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }
        .report-item { padding: 16px 24px; border-bottom: 1px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 15px; }
        .report-item:last-child { border-bottom: none; }
        .report-item .info { flex: 1; }
        .report-item .filename { color: #333; font-weight: 500; }
        .report-item .meta { color: #888; font-size: 13px; margin-top: 4px; }
        .report-item .badges { display: flex; gap: 8px; margin-top: 6px; flex-wrap: wrap; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge.high { background: #fee; color: #c00; }
        .badge.medium { background: #ffc; color: #a60; }
        .badge.low { background: #efe; color: #060; }
        .badge.ok { background: #eef; color: #06c; }
        .download-btn { padding: 6px 14px; background: #667eea; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; text-decoration: none; white-space: nowrap; }
        .download-btn:hover { background: #5569d9; }
        .empty { text-align: center; padding: 40px; color: #888; }
        .engine-tag { background: rgba(255,255,255,0.15); padding: 6px 16px; border-radius: 30px; font-size: 13px; display: flex; align-items: center; gap: 6px; margin-right: 15px; }
        .engine-tag.error { background: rgba(220,53,69,0.2); color: #ffc9c9; cursor: help; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;">
            <h1>🎯 技能扫描器</h1>
            {{if .ModelStatus}}
            <div class="engine-tag {{if .ModelError}}error{{end}}" {{if .ModelError}}title="{{.ModelError}}"{{end}}>
                <span>{{if .ModelError}}⚠️{{else}}🧠{{end}}</span>
                <span>{{.ModelStatus}}</span>
            </div>
            {{end}}
        </div>
        <div class="header-nav">
            <a href="/dashboard" class="active">🎯 首页</a>
            <a href="/scan">🔍 扫描</a>
            <a href="/reports">📊 报告</a>
            
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" onclick="toggleDropdown()">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="welcome">
            <h2>欢迎使用技能扫描器</h2>
            <p>上传技能文件或文件夹，检测敏感信息泄露和危险函数调用，生成 Word 风险报告。</p>
        </div>
        <div class="cards">
            <div class="card">
                <div class="icon">🔍</div>
                <h3>技能扫描</h3>
                <p>拖拽或点击上传技能文件（夹），自动扫描并生成风险报告。</p>
                <a href="/scan" class="card-btn">开始扫描</a>
            </div>
            <div class="card">
                <div class="icon">📊</div>
                <h3>风险报告</h3>
                <p>查看历史扫描报告，{{if .IsAdmin}}管理员可查看所有报告{{else}}可查看您及同团队成员的报告{{end}}。</p>
                <a href="/reports" class="card-btn">查看报告</a>
            </div>
        </div>

        <h3 class="section-title">📋 最近报告</h3>
        <div class="report-list">
            {{if .Reports}}
                {{range .Reports}}
                <div class="report-item">
                    <div class="info">
                        <div class="filename">{{.FileName}}</div>
                        <div class="meta">{{.Username}} · {{.CreatedAt}}</div>
                        <div class="badges">
                            {{if .NoRisk}}<span class="badge ok">✅ 无风险</span>{{end}}
                            {{if .HighRisk}}<span class="badge high">🔴 高 {{.HighRisk}}</span>{{end}}
                            {{if .MediumRisk}}<span class="badge medium">🟡 中 {{.MediumRisk}}</span>{{end}}
                            {{if .LowRisk}}<span class="badge low">🟢 低 {{.LowRisk}}</span>{{end}}
                            <span style="color:#888;font-size:12px;margin-left:4px;">共 {{.FindingCount}} 项</span>
                        </div>
                    </div>
                    <a href="/reports/{{.ID}}" class="download-btn">查看详情</a>
                </div>
                {{end}}
            {{else}}
                <div class="empty">暂无报告，请先进行技能扫描</div>
            {{end}}
        </div>
    </div>
    <script>
        function toggleDropdown() {
            var menu = document.getElementById('userDropdown');
            menu.classList.toggle('show');
        }
        document.addEventListener('click', function(e) {
            var dropdown = document.querySelector('.user-dropdown');
            if (!dropdown.contains(e.target)) {
                document.getElementById('userDropdown').classList.remove('show');
            }
        });
    </script>
</body>
</html>
`

// ReportsHTML is the reports listing page template.
const ReportsHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>风险报告 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-btn .arrow { font-size: 10px; }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .nav-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; }
        .nav-btn:hover { background: rgba(255,255,255,0.2); }
        .container { max-width: 1000px; margin: 40px auto; padding: 0 20px; }
        .panel { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; }
        .panel-header { padding: 20px 24px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .panel-header h2 { color: #333; font-size: 18px; }
        .admin-hint { background: #f0f7ff; color: #667eea; font-size: 13px; padding: 6px 12px; border-radius: 6px; }
        .team-hint { background: #f0fff0; color: #060; font-size: 13px; padding: 6px 12px; border-radius: 6px; }
        .report-item { padding: 16px 24px; border-bottom: 1px; border-bottom: 1px solid #eee; display: flex; align-items: center; gap: 15px; }
        .report-item:last-child { border-bottom: none; }
        .report-item .info { flex: 1; }
        .report-item .filename { color: #333; font-weight: 500; }
        .report-item .meta { color: #888; font-size: 13px; margin-top: 4px; }
        .report-item .badges { display: flex; gap: 8px; margin-top: 6px; flex-wrap: wrap; }
        .badge { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge.high { background: #fee; color: #c00; }
        .badge.medium { background: #ffc; color: #a60; }
        .badge.low { background: #efe; color: #060; }
        .badge.ok { background: #eef; color: #06c; }
        .download-btn { padding: 6px 14px; background: #667eea; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; text-decoration: none; white-space: nowrap; }
        .download-btn:hover { background: #5569d9; }
        .empty { text-align: center; padding: 60px; color: #888; }
        .engine-tag { background: rgba(255,255,255,0.15); padding: 6px 16px; border-radius: 30px; font-size: 13px; display: flex; align-items: center; gap: 6px; margin-right: 15px; }
        .engine-tag.error { background: rgba(220,53,69,0.2); color: #ffc9c9; cursor: help; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;">
            <h1>📊 风险报告</h1>
            {{if .ModelStatus}}
            <div class="engine-tag {{if .ModelError}}error{{end}}" {{if .ModelError}}title="{{.ModelError}}"{{end}}>
                <span>{{if .ModelError}}⚠️{{else}}🧠{{end}}</span>
                <span>{{.ModelStatus}}</span>
            </div>
            {{end}}
        </div>
        <div class="header-nav">
                        <a href="/dashboard">🎯 首页</a>
                        <a href="/scan">🔍 扫描</a>
                        <a href="/reports" class="active">📊 报告</a>
                        
                </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" onclick="toggleDropdown()">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="panel">
            <div class="panel-header">
                <h2>报告列表</h2>
                {{if .IsAdmin}}<span class="admin-hint">👑 管理员视图（显示所有报告）</span>{{else}}<span class="team-hint">显示您及同团队成员的报告</span>{{end}}
            </div>
            {{if .Reports}}
                {{range .Reports}}
                <div class="report-item">
                    <div class="info">
                        <div class="filename"><a href="/reports/{{.ID}}" style="color:#333;text-decoration:none;">{{.FileName}}</a></div>
                        <div class="meta">{{.Username}} · {{.CreatedAt}}</div>
                        <div class="badges">
                            {{if .NoRisk}}<span class="badge ok">✅ 无风险</span>{{end}}
                            {{if .HighRisk}}<span class="badge high">🔴 高 {{.HighRisk}}</span>{{end}}
                            {{if .MediumRisk}}<span class="badge medium">🟡 中 {{.MediumRisk}}</span>{{end}}
                            {{if .LowRisk}}<span class="badge low">🟢 低 {{.LowRisk}}</span>{{end}}
                            <span style="color:#888;font-size:12px;margin-left:4px;">共 {{.FindingCount}} 项</span>
                        </div>
                    </div>
                    <a href="/reports/{{.ID}}" class="download-btn">查看详情</a>
                </div>
                {{end}}
            {{else}}
                <div class="empty">
                    <div style="font-size:40px;margin-bottom:10px;">📭</div>
                    暂无报告，请先进行技能扫描
                </div>
            {{end}}
        </div>
    </div>
    <script>
        function toggleDropdown() {
            document.getElementById('userDropdown').classList.toggle('show');
        }
        document.addEventListener('click', function(e) {
            var dropdown = document.querySelector('.user-dropdown');
            if (dropdown && !dropdown.contains(e.target)) {
                document.getElementById('userDropdown').classList.remove('show');
            }
        });
    </script>
</body>
</html>
`

const ReportDetailHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>报告详情 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; }
        .header-nav { display: flex; align-items: center; gap: 6px; }
        .header-nav a { color: rgba(255,255,255,0.85); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; }
        .header-nav a.active, .header-nav a:hover { background: rgba(255,255,255,0.25); color: white; }
        .container { max-width: 1200px; margin: 28px auto; padding: 0 16px; }
        .card { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 18px; overflow: hidden; }
        .card-h { padding: 16px 20px; border-bottom: 1px solid #eee; font-weight: 600; color: #333; display: flex; justify-content: space-between; align-items: center; }
        .card-b { padding: 16px 20px; }
        .meta-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
        .meta-item { background: #f9fafc; border: 1px solid #edf0f5; border-radius: 8px; padding: 10px; }
        .meta-label { color: #666; font-size: 12px; margin-bottom: 6px; }
        .meta-value { color: #222; font-size: 14px; word-break: break-all; }
        .download-btn { display: inline-block; padding: 8px 12px; background: #667eea; color: white; text-decoration: none; border-radius: 6px; font-size: 13px; }
        .chip-wrap { display: flex; flex-wrap: wrap; gap: 8px; }
        .chip { background: #eef2ff; color: #3a4ab8; border-radius: 999px; padding: 4px 10px; font-size: 12px; }
        .chip.warn { background: #fff4e5; color: #a16400; }
        .chip.danger { background: #ffe8e8; color: #b42318; }
        .finding { border: 1px solid #edf0f5; border-radius: 10px; padding: 12px; margin-bottom: 10px; }
        .finding:last-child { margin-bottom: 0; }
        .finding .title { font-weight: 600; color: #222; margin-bottom: 6px; }
        .finding .desc { color: #555; font-size: 13px; line-height: 1.6; margin-bottom: 6px; }
        .finding .meta { color: #777; font-size: 12px; }
        .severity { display: inline-block; font-size: 12px; border-radius: 4px; padding: 2px 8px; margin-right: 8px; }
        .severity.high { background: #ffe8e8; color: #b42318; }
        .severity.medium { background: #fff4e5; color: #a16400; }
        .severity.low { background: #e9f7ef; color: #0f6d35; }
        pre { background: #fafafa; border: 1px solid #eee; border-radius: 8px; padding: 10px; font-size: 12px; overflow-x: auto; color: #333; margin-top: 8px; }
        .empty { color: #888; padding: 8px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>报告详情</h1>
        <div class="header-nav">
            <a href="/dashboard">首页</a>
            <a href="/scan">扫描</a>
            <a href="/reports" class="active">报告</a>
        </div>
    </div>
    <div class="container">
        <div class="card">
            <div class="card-h">
                <span>{{.Report.FileName}}</span>
                <a href="/reports/download/{{.Report.ID}}" class="download-btn">下载 DOCX</a>
            </div>
            <div class="card-b">
                <div class="meta-grid">
                    <div class="meta-item"><div class="meta-label">报告ID</div><div class="meta-value">{{.Report.ID}}</div></div>
                    <div class="meta-item"><div class="meta-label">创建人</div><div class="meta-value">{{.Report.Username}}</div></div>
                    <div class="meta-item"><div class="meta-label">创建时间</div><div class="meta-value">{{.CreatedAt}}</div></div>
                    <div class="meta-item"><div class="meta-label">风险统计</div><div class="meta-value">高 {{.Report.HighRisk}} / 中 {{.Report.MediumRisk}} / 低 {{.Report.LowRisk}}</div></div>
                    <div class="meta-item"><div class="meta-label">发现项</div><div class="meta-value">{{.Report.FindingCount}}</div></div>
                    <div class="meta-item"><div class="meta-label">能力融合得分</div><div class="meta-value">{{printf "%.1f" .CapabilityScore}}</div></div>
                    <div class="meta-item"><div class="meta-label">规则基础得分</div><div class="meta-value">{{printf "%.1f" .BaseScore}}</div></div>
                    <div class="meta-item"><div class="meta-label">融合权重</div><div class="meta-value">base {{printf "%.2f" .BaseWeight}} / cap {{printf "%.2f" .CapWeight}}</div></div>
                    <div class="meta-item"><div class="meta-label">综合得分</div><div class="meta-value">{{printf "%.1f" .Report.Score}}</div></div>
                    <div class="meta-item"><div class="meta-label">风险等级</div><div class="meta-value">{{.Report.RiskLevel}}</div></div>
                    <div class="meta-item"><div class="meta-label">阻断状态</div><div class="meta-value">{{if .Report.P0Blocked}}已阻断{{else}}未阻断{{end}}</div></div>
                    <div class="meta-item"><div class="meta-label">白名单抑制告警</div><div class="meta-value">{{.Report.WhitelistSuppressed}}</div></div>
                    <div class="meta-item"><div class="meta-label">意图一致性</div><div class="meta-value">{{if gt .Report.LLMIntentConfidence 0}}{{.Report.LLMIntentConfidence}} / 100{{else}}无{{end}}</div></div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-h">LLM 意图重建</div>
            <div class="card-b">
                <div style="margin-bottom:10px;"><strong>声明意图</strong></div>
                <div class="chip-wrap">{{if .Report.LLMStatedIntent}}<span class="chip">{{.Report.LLMStatedIntent}}</span>{{else}}<span class="empty">无</span>{{end}}</div>
                <div style="margin:12px 0 10px;"><strong>实际行为</strong></div>
                <div class="chip-wrap">{{if .Report.LLMActualBehavior}}<span class="chip warn">{{.Report.LLMActualBehavior}}</span>{{else}}<span class="empty">无</span>{{end}}</div>
            </div>
        </div>

        <div class="card">
            <div class="card-h">R2 能力融合</div>
            <div class="card-b">
                <div style="margin-bottom:10px;"><strong>声明能力</strong></div>
                <div class="chip-wrap">{{if .DeclaredCaps}}{{range .DeclaredCaps}}<span class="chip">{{.}}</span>{{end}}{{else}}<span class="empty">无</span>{{end}}</div>
                <div style="margin:12px 0 10px;"><strong>观测能力</strong></div>
                <div class="chip-wrap">{{if .ObservedCaps}}{{range .ObservedCaps}}<span class="chip">{{.}}</span>{{end}}{{else}}<span class="empty">无</span>{{end}}</div>
                <div style="margin:12px 0 10px;"><strong>匹配能力</strong></div>
                <div class="chip-wrap">{{if .MatchedCaps}}{{range .MatchedCaps}}<span class="chip">{{.}}</span>{{end}}{{else}}<span class="empty">无</span>{{end}}</div>
                <div style="margin:12px 0 10px;"><strong>超声明能力</strong></div>
                <div class="chip-wrap">{{if .OverreachCaps}}{{range .OverreachCaps}}<span class="chip danger">{{.}}</span>{{end}}{{else}}<span class="empty">无</span>{{end}}</div>
                <div style="margin:12px 0 10px;"><strong>漏声明能力</strong></div>
                <div class="chip-wrap">{{if .UnderdeclareCaps}}{{range .UnderdeclareCaps}}<span class="chip warn">{{.}}</span>{{end}}{{else}}<span class="empty">无</span>{{end}}</div>
                <div style="margin:12px 0 10px;"><strong>阻断原因</strong></div>
                <div class="chip-wrap">{{if .Report.P0Reasons}}{{range .Report.P0Reasons}}<span class="chip danger">{{.}}</span>{{end}}{{else}}<span class="empty">无</span>{{end}}</div>
                <div style="margin:12px 0 10px;"><strong>白名单抑制（按规则）</strong></div>
                <div class="chip-wrap">{{if .WhitelistByRule}}{{range .WhitelistByRule}}<span class="chip">{{.RuleID}}: {{.Count}}</span>{{end}}{{else}}<span class="empty">无</span>{{end}}</div>
            </div>
        </div>

        <div class="card">
            <div class="card-h">发现项明细</div>
            <div class="card-b">
                {{if .Findings}}
                {{range .Findings}}
                <div class="finding">
                    <div class="title"><span class="severity {{if eq .Severity "高风险"}}high{{else if eq .Severity "中风险"}}medium{{else}}low{{end}}">{{.Severity}}</span>{{.Title}}</div>
                    <div class="desc">{{.Description}}</div>
                    <div class="meta">规则: {{.RuleID}} | 引擎: {{.PluginName}} | 位置: {{.Location}}</div>
                    {{if .CodeSnippet}}<pre>{{.CodeSnippet}}</pre>{{end}}
                </div>
                {{end}}
                {{else}}
                <div class="empty">当前报告未包含可展示的发现项详情。</div>
                {{end}}
            </div>
        </div>
    </div>
</body>
</html>
`

// ScanHTML is the skill scanning page template (fixed folder upload).
const ScanHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>技能扫描 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .container { max-width: 800px; margin: 40px auto; padding: 0 20px; }
        .panel { background: white; padding: 40px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); }
        .panel h2 { color: #333; margin-bottom: 10px; }
        .panel > p { color: #666; margin-bottom: 30px; line-height: 1.6; }
        .upload-mode { display: flex; gap: 15px; margin-bottom: 20px; }
        .mode-btn { flex: 1; padding: 20px; border: 2px solid #e1e1e1; border-radius: 10px; cursor: pointer; text-align: center; transition: all 0.2s; background: white; }
        .mode-btn:hover { border-color: #667eea; }
        .mode-btn.active { border-color: #667eea; background: rgba(102,126,234,0.05); }
        .mode-btn .icon { font-size: 36px; margin-bottom: 8px; }
        .mode-btn .title { font-weight: 600; color: #333; margin-bottom: 4px; }
        .mode-btn .desc { font-size: 13px; color: #888; }
        .upload-area { border: 3px dashed #ddd; border-radius: 12px; padding: 50px 40px; text-align: center; transition: all 0.3s; cursor: pointer; margin-bottom: 20px; }
        .upload-area:hover, .upload-area.dragover { border-color: #667eea; background: rgba(102,126,234,0.05); }
        .upload-area .icon { font-size: 50px; margin-bottom: 15px; }
        .upload-area h3 { color: #333; margin-bottom: 8px; }
        .upload-area p { color: #888; margin-bottom: 0; font-size: 14px; }
        .upload-area .hint { font-size: 12px; color: #aaa; margin-top: 8px; }
        .upload-area input { display: none; }
        .file-list { background: #f5f6fa; padding: 14px 18px; border-radius: 8px; margin-bottom: 15px; display: none; max-height: 200px; overflow-y: auto; }
        .file-list.show { display: block; }
        .file-item { display: flex; align-items: center; padding: 6px 0; border-bottom: 1px solid #e0e0e0; }
        .file-item:last-child { border-bottom: none; }
        .file-item .name { flex: 1; color: #333; font-size: 14px; word-break: break-all; }
        .file-item .size { color: #888; font-size: 12px; margin-left: 10px; }
        .file-summary { margin-bottom: 12px; color: #333; font-weight: 500; }
        .submit-btn { width: 100%; padding: 16px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 18px; font-weight: 600; cursor: pointer; transition: transform 0.2s; display: none; }
        .submit-btn:hover { transform: translateY(-2px); }
        .submit-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .loading { display: none; text-align: center; padding: 40px; }
        .loading .spinner { border: 4px solid #f3f3f3; border-top: 4px solid #667eea; border-radius: 50%; width: 50px; height: 50px; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .tips { background: #f0f7ff; border-left: 4px solid #667eea; padding: 16px 20px; border-radius: 0 8px 8px 0; margin-top: 30px; }
        .tips h4 { color: #333; margin-bottom: 10px; }
        .tips ul { color: #666; padding-left: 20px; line-height: 1.8; }
        .engine-tag { background: rgba(255,255,255,0.15); padding: 6px 16px; border-radius: 30px; font-size: 13px; display: flex; align-items: center; gap: 6px; margin-right: 15px; }
        .engine-tag.error { background: rgba(220,53,69,0.2); color: #ffc9c9; cursor: help; }
        .field-group { margin-bottom: 20px; }
        .field-group label { display: block; margin-bottom: 6px; color: #555; font-weight: 500; }
        .field-group input, .field-group textarea { width: 100%; padding: 12px; border: 2px solid #e1e1e1; border-radius: 8px; font-size: 14px; }
        .field-group textarea { resize: vertical; min-height: 80px; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;">
            <h1>🔍 技能扫描</h1>
            {{if .ModelStatus}}
            <div class="engine-tag {{if .ModelError}}error{{end}}" {{if .ModelError}}title="{{.ModelError}}"{{end}}>
                <span>{{if .ModelError}}⚠️{{else}}🧠{{end}}</span>
                <span>{{.ModelStatus}}</span>
            </div>
            {{end}}
            {{if .SandboxAvailable}}
            <div class="engine-tag">
                <span>📦</span>
                <span>动态沙箱已启用</span>
            </div>
            {{else}}
            <div class="engine-tag error">
                <span>⚠️</span>
                <span>动态沙箱未启用</span>
            </div>
            {{end}}
        </div>
        <div class="header-nav">
            <a href="/dashboard">🎯 首页</a>
            <a href="/scan" class="active">🔍 扫描</a>
            <a href="/reports">📊 报告</a>
            
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" onclick="toggleDropdown()">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="panel">
            <h2>上传技能文件</h2>
            <p>支持上传单个文件或整个文件夹，系统会自动扫描代码中的敏感信息和危险调用。</p>

            <div class="field-group">
                <label>技能描述（可选）</label>
                <textarea id="description" placeholder="请输入技能的功能描述，帮助系统更准确的分析风险"></textarea>
            </div>
            <div class="field-group">
                <label>权限声明（可选，逗号分隔）</label>
                <input id="permissions" placeholder="例如: 文件读取,网络访问">
            </div>

            <div class="upload-area" id="uploadArea">
                <div class="icon">📁</div>
                <h3>拖拽文件到这里，或点击上传</h3>
                <p>支持上传文件夹或多个文件</p>
                <p class="hint">支持 Go/Python/JavaScript/TypeScript 代码扫描</p>
                <input type="file" id="fileInput" multiple webkitdirectory directory>
            </div>
            <div class="file-list" id="fileList">
                <div class="file-summary" id="fileSummary">已选择 0 个文件</div>
            </div>
            <button class="submit-btn" id="submitBtn">开始扫描</button>
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p>正在扫描中，请稍候...</p>
            </div>

            <div class="tips">
                <h4>扫描说明</h4>
                <ul>
                    <li>支持静态代码分析：检测敏感密钥、危险函数调用、恶意代码模式</li>
                    <li>支持动态沙箱分析：在隔离环境中运行技能，检测运行时的恶意行为</li>
                    <li>扫描完成后会自动生成 Word 格式的风险报告，可下载留存</li>
                </ul>
            </div>
        </div>
    </div>
    <script>
                function toggleDropdown() {
                        document.getElementById('userDropdown').classList.toggle('show');
                }
                document.addEventListener('click', function(e) {
                        var dropdown = document.querySelector('.user-dropdown');
                        if (dropdown && !dropdown.contains(e.target)) {
                                document.getElementById('userDropdown').classList.remove('show');
                        }
                });

                // 上传逻辑
                const uploadArea = document.getElementById('uploadArea');
                const fileInput = document.getElementById('fileInput');
                const fileList = document.getElementById('fileList');
                const fileSummary = document.getElementById('fileSummary');
                const submitBtn = document.getElementById('submitBtn');
                const loading = document.getElementById('loading');

                let selectedFiles = [];
				// 确保按钮初始隐藏
				submitBtn.style.display = 'none';

                uploadArea.addEventListener('click', () => fileInput.click());

                uploadArea.addEventListener('dragover', (e) => {
                        e.preventDefault();
                        uploadArea.classList.add('dragover');
                });

                uploadArea.addEventListener('dragleave', () => {
                        uploadArea.classList.remove('dragover');
                });

                uploadArea.addEventListener('drop', (e) => {
                        e.preventDefault();
                        uploadArea.classList.remove('dragover');
                        handleFiles(e.dataTransfer.files);
                });

                fileInput.addEventListener('change', (e) => {
                        handleFiles(e.target.files);
                });

                function handleFiles(files) {
					selectedFiles = Array.from(files);
					fileList.innerHTML = '';
					let summary = document.createElement('div');
					summary.className = 'file-summary';
					summary.textContent = '已选择 ' + files.length + ' 个文件';
					fileList.appendChild(summary);
					for (const file of files) {
						const item = document.createElement('div');
						item.className = 'file-item';
						item.innerHTML = '<span class="name">' + (file.webkitRelativePath || file.name) + '</span>' +
										 '<span class="size">' + formatFileSize(file.size) + '</span>';
						fileList.appendChild(item);
					}
					fileList.classList.add('show');
					// 强制显示按钮（覆盖 CSS 隐藏）
					submitBtn.style.display = 'block';
					console.log('按钮已强制显示');
				}

                function formatFileSize(bytes) {
                        if (bytes === 0) return '0 Bytes';
                        const k = 1024;
                        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
                        const i = Math.floor(Math.log(bytes) / Math.log(k));
                        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
                }

                async function pollScanJob(jobId) {
                        const maxAttempts = 240;
                        let attempts = 0;
                        while (attempts < maxAttempts) {
                                attempts += 1;
                                const res = await fetch('/api/scan/jobs/' + encodeURIComponent(jobId));
                                const data = await res.json();
                                if (!res.ok) {
                                        throw new Error(data.error || '查询任务状态失败');
                                }
                                if (data.status === 'success') {
                                        return data;
                                }
                                if (data.status === 'failed') {
                                        throw new Error(data.error || '扫描任务执行失败');
                                }
                                await new Promise(function(resolve) { setTimeout(resolve, 1000); });
                        }
                        throw new Error('扫描超时，请稍后到报告页查看结果');
                }

                submitBtn.addEventListener('click', async function() {
                        if (selectedFiles.length === 0) return;
                        submitBtn.disabled = true;
                        loading.style.display = 'block';
                        uploadArea.style.display = 'none';
                        fileList.style.display = 'none';

                        const formData = new FormData();
                        for (const file of selectedFiles) {
                                formData.append('files', file, file.webkitRelativePath || file.name);
                        }
                        formData.append('description', document.getElementById('description').value);
                        formData.append('permissions', document.getElementById('permissions').value);

                        try {
                                const createRes = await fetch('/api/scan/jobs', {
                                        method: 'POST',
                                        body: formData
                                });
                                const createData = await createRes.json();
                                if (!createRes.ok) {
                                        throw new Error(createData.error || '创建扫描任务失败');
                                }

                                const jobData = await pollScanJob(createData.job_id);
                                const target = jobData.report_id ? ('/reports/' + encodeURIComponent(jobData.report_id)) : '/reports';
                                window.location.href = target;
                        } catch (e) {
                                alert('扫描失败: ' + e.message);
                                loading.style.display = 'none';
                                uploadArea.style.display = 'block';
                                fileList.style.display = 'block';
                                submitBtn.disabled = false;
                        }
                });
        </script>
</body>
</html>
`

// LoginLogHTML is the login log viewer page (admin only).
const LoginLogHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>登录日志 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .container { max-width: 1000px; margin: 40px auto; padding: 0 20px; }
        .panel { background: white; border-radius: 12px; border: 1px solid #eee; }
        .panel-header { padding: 20px 24px; border-bottom: 1px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; }
        .panel-header h2 { color: #333; font-size: 18px; }
        .readonly-note { background: #f0f7ff; color: #667eea; font-size: 13px; padding: 6px 12px; border-radius: 6px; }
        .log-table { width: 100%; border-collapse: collapse; }
        .log-table th, .log-table td { padding: 14px 24px; text-align: left; border-bottom: 1px solid #eee; }
        .log-table th { background: #f9f9f9; color: #666; font-size: 13px; font-weight: 600; }
        .log-table td { color: #333; font-size: 14px; }
        .log-table tr:last-child td { border-bottom: none; }
        .result-tag { padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .result-tag.success { background: #efe; color: #060; }
        .result-tag.fail { background: #fee; color: #c00; }
        .empty { text-align: center; padding: 60px; color: #888; }
        .ip { color: #888; font-size: 13px; }
        .engine-tag { background: rgba(255,255,255,0.15); padding: 6px 16px; border-radius: 30px; font-size: 13px; display: flex; align-items: center; gap: 6px; margin-right: 15px; }
        .engine-tag.error { background: rgba(220,53,69,0.2); color: #ffc9c9; cursor: help; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;">
            <h1>📋 登录日志</h1>
            {{if .ModelStatus}}
            <div class="engine-tag {{if .ModelError}}error{{end}}" {{if .ModelError}}title="{{.ModelError}}"{{end}}>
                <span>{{if .ModelError}}⚠️{{else}}🧠{{end}}</span>
                <span>{{.ModelStatus}}</span>
            </div>
            {{end}}
        </div>
        <div class="header-nav">
            <a href="/dashboard">🎯 首页</a>
            <a href="/scan">🔍 扫描</a>
            <a href="/reports">📊 报告</a>
            
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" onclick="toggleDropdown()">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="panel">
            <div class="panel-header">
                <h2>登录记录</h2>
                <span class="readonly-note">🔒 此记录不可删除，仅管理员可见</span>
            </div>
            {{if .Logs}}
            <table class="log-table">
                <thead>
                    <tr>
                        <th>用户名</th>
                        <th>时间</th>
                        <th>结果</th>
                        <th>IP 地址</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Logs}}
                    <tr>
                        <td>{{.Username}}</td>
                        <td>{{.Timestamp}}</td>
                        <td><span class="result-tag {{.ResultClass}}">{{.Result}}</span>
                        </td>
                        <td><span class="ip">{{.IP}}</span></td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
            {{else}}
                <div class="empty">
                    <div style="font-size:40px;margin-bottom:10px;">📭</div>
                    暂无登录记录
                </div>
            {{end}}
        </div>
    </div>
    <script>
        function toggleDropdown() {
            document.getElementById('userDropdown').classList.toggle('show');
        }
        document.addEventListener('click', function(e) {
            var dropdown = document.querySelector('.user-dropdown');
            if (dropdown && !dropdown.contains(e.target)) {
                document.getElementById('userDropdown').classList.remove('show');
            }
        });
    </script>
</body>
</html>
`

// PersonalHTML is the personal center page template.
const PersonalHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>个人中心 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav a.active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .container { max-width: 800px; margin: 40px auto; padding: 0 20px; }
        .card { background: white; padding: 30px; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); margin-bottom: 20px; }
        .card h2 { color: #333; margin-bottom: 20px; font-size: 18px; }
        .card h2 .icon { margin-right: 8px; }
        .info-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
        .info-item { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }
        .info-item .value { font-size: 24px; font-weight: 600; color: #333; }
        .info-item .label { font-size: 13px; color: #666; margin-top: 4px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 8px; color: #555; font-weight: 500; font-size: 14px; }
        .form-group input, .form-group select { width: 100%; padding: 12px 16px; border: 2px solid #e1e1e1; border-radius: 8px; font-size: 16px; transition: border-color 0.3s; }
        .form-group input:focus, .form-group select:focus { outline: none; border-color: #667eea; }
        .form-group .hint { font-size: 13px; color: #888; margin-top: 6px; }
        .form-group .configured { font-size: 13px; color: #060; background: #efe; padding: 6px 12px; border-radius: 6px; margin-top: 8px; display: inline-block; }
        .error { background: #fee; color: #c00; padding: 12px; border-radius: 6px; margin-bottom: 20px; display: none; }
        .success { background: #efe; color: #060; padding: 12px; border-radius: 6px; margin-bottom: 20px; display: none; }
        button { padding: 12px 28px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; font-size: 15px; font-weight: 600; cursor: pointer; transition: transform 0.2s; }
        button:hover { transform: translateY(-2px); }
        button:disabled { opacity: 0.7; cursor: not-allowed; }
        .section-title { color: #333; font-size: 16px; margin: 20px 0 16px; padding-bottom: 10px; border-bottom: 2px solid #eee; }
        .section-title .icon { margin-right: 6px; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;">
            <h1>👤 个人中心</h1>
        </div>
        <div class="header-nav">
            <a href="/dashboard">🎯 首页</a>
            <a href="/scan">🔍 扫描</a>
            <a href="/reports">📊 报告</a>
            
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" onclick="toggleDropdown()">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    <a href="/personal">👤 个人中心</a>
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        <div class="card">
            <h2><span class="icon">📋</span>账户信息</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="value">{{.Username}}</div>
                    <div class="label">用户名</div>
                </div>
                <div class="info-item">
                    <div class="value">{{.Team}}</div>
                    <div class="label">团队</div>
                </div>
                <div class="info-item">
                    <div class="value">{{.ReportCount}}</div>
                    <div class="label">扫描报告</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2><span class="icon">🤖</span>LLM 深度分析配置</h2>
            <p style="color: #666; font-size: 14px; margin-bottom: 20px;">配置大模型 API 密钥，启用代码深度意图分析能力，帮助检测隐蔽的安全风险。</p>
            <div id="errorMsg" class="error"></div>
            <div id="successMsg" class="success"></div>

            <div class="form-group">
                <label for="provider">选择模型</label>
                <select id="provider">
                    <option value="deepseek" {{if and .LLMConfig (not .LLMConfig.MiniMaxGroupID)}}selected{{end}}>DeepSeek</option>
                    <option value="minimax" {{if .LLMConfig.MiniMaxGroupID}}selected{{end}}>MiniMax</option>
                </select>
            </div>

            <div class="form-group">
                <label for="deepseek_key">DeepSeek API Key</label>
                <input type="password" id="deepseek_key" placeholder="输入你的 DeepSeek API Key">
                {{if and .LLMConfig .LLMConfig.APIKey (eq .LLMConfig.Provider "deepseek")}}
                <div class="configured">✅ 已配置，当前密钥已脱敏存储</div>
                {{end}}
                <div class="hint">如果你使用 DeepSeek 大模型，请在此填写 API Key。</div>
            </div>

            <div class="form-group">
                <label for="minimax_group">MiniMax Group ID</label>
                <input type="text" id="minimax_group" placeholder="输入你的 MiniMax Group ID" value="{{if .LLMConfig}}{{.LLMConfig.MiniMaxGroupID}}{{end}}">
                {{if and .LLMConfig .LLMConfig.MiniMaxGroupID}}
                <div class="configured">✅ 已配置</div>
                {{end}}
                <div class="hint">MiniMax 用户需要提供 Group ID。</div>
            </div>

            <div class="form-group">
                <label for="minimax_key">MiniMax API Key</label>
                <input type="password" id="minimax_key" placeholder="输入你的 MiniMax API Key">
                {{if and .LLMConfig .LLMConfig.APIKey (eq .LLMConfig.Provider "minimax")}}
                <div class="configured">✅ 已配置，当前密钥已脱敏存储</div>
                {{end}}
                <div class="hint">如果你使用 MiniMax 大模型，请在此填写 API Key。</div>
            </div>

            <button id="saveBtn">保存配置</button>
        </div>
    </div>
    <script>
        function toggleDropdown() {
            document.getElementById('userDropdown').classList.toggle('show');
        }
        document.addEventListener('click', function(event) {
            var dropdown = document.querySelector('.user-dropdown');
            if (dropdown && !dropdown.contains(event.target)) {
                document.getElementById('userDropdown').classList.remove('show');
            }
        });

        document.getElementById('saveBtn').addEventListener('click', async function() {
            var btn = this;
            var errorMsg = document.getElementById('errorMsg');
            var successMsg = document.getElementById('successMsg');
            errorMsg.style.display = 'none';
            successMsg.style.display = 'none';
            btn.disabled = true;
            btn.textContent = '保存中...';
            try {
                var provider = document.getElementById('provider').value;
                var deepseekKey = document.getElementById('deepseek_key').value.trim();
                var minimaxGroup = document.getElementById('minimax_group').value.trim();
                var minimaxKey = document.getElementById('minimax_key').value.trim();
                
                var config = {
                    enabled: true,
                    provider: provider,
                    api_key: provider === 'deepseek' ? deepseekKey : minimaxKey,
                    minimax_group_id: minimaxGroup
                };
                var res = await fetch('/api/user/llm', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(config)
                });
                var data = await res.json();
                if (!res.ok) {
                    throw new Error(data.error || data.message || '保存失败');
                }
                successMsg.textContent = data.message || '配置已保存';
                successMsg.style.display = 'block';
                setTimeout(function() { window.location.reload(); }, 1500);
            } catch (e) {
                errorMsg.textContent = e.message;
                errorMsg.style.display = 'block';
                btn.disabled = false;
                btn.textContent = '保存配置';
            }
        });
    </script>
</body>
</html>
`

// AdminUsersHTML is the admin user management page template.
const AdminUsersHTML = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>用户管理 - 技能扫描器</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f6fa; min-height: 100vh; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px 40px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header h1 { font-size: 24px; }
        .header-nav { display: flex; align-items: center; gap: 4px; margin-right: 24px; }
        .header-nav a { color: rgba(255,255,255,0.8); text-decoration: none; font-size: 13px; padding: 4px 12px; border-radius: 4px; transition: background 0.2s; }
        .header-nav a:hover { background: rgba(255,255,255,0.2); color: white; }
        .header-nav .active { background: rgba(255,255,255,0.25); color: white; }
        .header-right { display: flex; align-items: center; gap: 10px; }
        .user-dropdown { position: relative; }
        .dropdown-btn { background: rgba(255,255,255,0.2); color: white; border: 1px solid rgba(255,255,255,0.4); padding: 8px 20px; border-radius: 6px; cursor: pointer; font-size: 14px; text-decoration: none; transition: background 0.3s; display: flex; align-items: center; gap: 6px; }
        .dropdown-btn:hover { background: rgba(255,255,255,0.3); }
        .dropdown-menu { display: none; position: absolute; top: 100%; right: 0; margin-top: 6px; background: white; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.15); min-width: 180px; z-index: 100; overflow: hidden; }
        .dropdown-menu.show { display: block; }
        .dropdown-menu a { display: block; padding: 10px 18px; color: #333; text-decoration: none; font-size: 14px; transition: background 0.2s; }
        .dropdown-menu a:hover { background: #f5f6fa; }
        .dropdown-menu a.danger { color: #c00; }
        .dropdown-menu .divider { height: 1px; background: #eee; margin: 4px 0; }
        .container { max-width: 900px; margin: 40px auto; padding: 0 20px; }
        .msg { padding: 12px 24px; border-radius: 8px; margin-bottom: 16px; }
        .msg.error { background: #fee; color: #c00; }
        .msg.success { background: #efe; color: #060; }
        .panel { background: white; border-radius: 12px; box-shadow: 0 2px 10px rgba(0,0,0,0.05); overflow: hidden; margin-bottom: 20px; }
        .panel-header { padding: 20px 24px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
        .panel-header h2 { color: #333; font-size: 18px; }
        .form-row { display: grid; grid-template-columns: 1fr 1fr 1fr auto; gap: 12px; align-items: end; padding: 24px; }
        .form-group { display: flex; flex-direction: column; }
        .form-group label { color: #555; font-size: 14px; margin-bottom: 6px; font-weight: 500; }
        .form-group input { padding: 10px 14px; border: 2px solid #e1e1e1; border-radius: 8px; font-size: 14px; }
        .form-group input:focus { outline: none; border-color: #667eea; }
        .submit-btn { padding: 10px 24px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 14px; font-weight: 600; white-space: nowrap; }
        .submit-btn:hover { transform: translateY(-1px); }
        .user-table { width: 100%; border-collapse: collapse; }
        .user-table th, .user-table td { padding: 14px 24px; text-align: left; border-bottom: 1px solid #eee; }
        .user-table th { background: #f9f9f9; color: #666; font-size: 13px; font-weight: 600; }
        .user-table td { color: #333; }
        .user-table tr:last-child td { border-bottom: none; }
        .admin-tag { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .team-tag { background: #eef; color: #06c; padding: 2px 8px; border-radius: 4px; font-size: 12px; }
        .delete-btn { color: #c00; background: none; border: 1px solid #c00; padding: 5px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; }
        .delete-btn:hover { background: #fee; }
        .engine-tag { background: rgba(255,255,255,0.15); padding: 6px 16px; border-radius: 30px; font-size: 13px; display: flex; align-items: center; gap: 6px; margin-right: 15px; }
        .engine-tag.error { background: rgba(220,53,69,0.2); color: #ffc9c9; cursor: help; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; align-items: center; gap: 20px;">
            <h1>👥 用户管理</h1>
            {{if .ModelStatus}}
            <div class="engine-tag {{if .ModelError}}error{{end}}" {{if .ModelError}}title="{{.ModelError}}"{{end}}>
                <span>{{if .ModelError}}⚠️{{else}}🧠{{end}}</span>
                <span>{{.ModelStatus}}</span>
            </div>
            {{end}}
        </div>
        <div class="header-nav">
            <a href="/dashboard">🎯 首页</a>
            <a href="/scan">🔍 扫描</a>
            <a href="/reports">📊 报告</a>
            
        </div>
        <div class="header-right">
            <div class="user-dropdown">
                <button class="dropdown-btn" onclick="toggleDropdown()">
                    👤 {{.Username}} <span class="arrow">▾</span>
                </button>
                <div class="dropdown-menu" id="userDropdown">
                    {{if .HasPersonal}}<a href="/personal">👤 个人中心</a>{{end}}
                    {{if .HasUserMgmt}}<a href="/admin/users">👥 用户管理</a>{{end}}
                    {{if .HasLogPerm}}<a href="/admin/login-log">📋 登录日志</a>{{end}}
                    <div class="divider"></div>
                    <a href="/change-password">🔑 修改密码</a>
                    <a href="/logout" class="danger">🚪 退出</a>
                </div>
            </div>
        </div>
    </div>
    <div class="container">
        {{if .Error}}<div class="msg error">{{.Error}}</div>{{end}}
        {{if .Success}}<div class="msg success">{{.Success}}</div>{{end}}

        <div class="panel">
            <div class="panel-header">
                <h2>添加用户</h2>
            </div>
            <form method="POST" action="/admin/users">
                <input type="hidden" name="action" value="add">
                <div class="form-row">
                    <div class="form-group">
                        <label>用户名</label>
                        <input type="text" name="username" placeholder="请输入用户名" required>
                    </div>
                    <div class="form-group">
                        <label>密码</label>
                        <input type="password" name="password" placeholder="请输入密码" required>
                    </div>
                    <div class="form-group">
                        <label>团队名称</label>
                        <input type="text" name="team" placeholder="可选，如无则用户无团队">
                    </div>
                    <button type="submit" class="submit-btn">添加用户</button>
                </div>
            </form>
        </div>

        <div class="panel">
            <div class="panel-header">
                <h2>用户列表</h2>
            </div>
            <table class="user-table">
                <thead>
                    <tr>
                        <th>用户名</th>
                        <th>团队</th>
                        <th>创建时间</th>
                        <th>操作</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Users}}
                    <tr>
                        <td>{{.Username}}{{if .IsAdmin}} <span class="admin-tag">管理员</span>{{end}}</td>
                        <td>{{.Team}}</td>
                        <td>{{.CreatedAt}}</td>
                        <td>{{.DeleteForm}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
    </div>
    <script>
        function toggleDropdown() {
            document.getElementById('userDropdown').classList.toggle('show');
        }
        document.addEventListener('click', function(e) {
            var dropdown = document.querySelector('.user-dropdown');
            if (dropdown && !dropdown.contains(e.target)) {
                document.getElementById('userDropdown').classList.remove('show');
            }
        });
    </script>
</body>
</html>
`
