package handler

import (
	"encoding/json"
	"html/template"
	"net/http"

	"skill-scanner/web/templates"
)

// Template names passed to html/template.
const (
	tmplLogin        = "login"
	tmplChangePwd    = "change-password"
	tmplDashboard    = "dashboard"
	tmplScan         = "scan"
	tmplReports      = "reports"
	tmplReportDetail = "report-detail"
	tmplPersonal     = "personal"
	tmplAdminUsers   = "admin-users"
	tmplLoginLog     = "login-log"
)

// templates holds all parsed HTML templates.
var tmplCache = map[string]*template.Template{}

func init() {
	for name, html := range map[string]string{
		tmplLogin:        templates.LoginHTML,
		tmplChangePwd:    templates.ChangePasswordHTML,
		tmplDashboard:    templates.DashboardHTML,
		tmplScan:         templates.ScanHTML,
		tmplReports:      templates.ReportsHTML,
		tmplReportDetail: templates.ReportDetailHTML,
		tmplPersonal:     templates.PersonalHTML,
		tmplAdminUsers:   templates.AdminUsersHTML,
		tmplLoginLog:     templates.LoginLogHTML,
	} {
		tmplCache[name] = template.Must(template.New(name).Parse(html))
	}
}

// render executes the named template with the given data.
func render(w http.ResponseWriter, name string, data interface{}) {
	if err := tmplCache[name].Execute(w, data); err != nil {
		// Log error but don't crash - write a user-friendly message
		http.Error(w, "页面渲染失败，请稍后重试", http.StatusInternalServerError)
	}
}

// sendJSON writes a JSON response with the given status code and data.
func sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
