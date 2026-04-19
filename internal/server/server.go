package server

import (
	"fmt"
	"net/http"

	"skill-scanner/internal/handler"
	"skill-scanner/internal/storage"
)

func New(store *storage.Store) http.Handler {
	mux := http.NewServeMux()

	// Public routes.
	mux.HandleFunc("/login", handler.Login(store))
	mux.HandleFunc("/change-password", handler.ChangePassword(store))
	mux.HandleFunc("/logout", handler.Logout())

	// Protected routes. (all require authentication).
	mux.HandleFunc("/dashboard", handler.RequireAuth(handler.Dashboard(store)))
	mux.HandleFunc("/scan", handler.RequireAuth(handler.Scan(store)))
	mux.HandleFunc("/api/scan", handler.RequireAuth(handler.Scan(store))) // 兼容旧接口
	mux.HandleFunc("/api/scan/jobs", handler.RequireAuth(handler.CreateScanJob(store)))
	mux.HandleFunc("/api/scan/jobs/", handler.RequireAuth(handler.GetScanJobStatus(store)))
	mux.HandleFunc("/reports", handler.RequireAuth(handler.ListReports(store)))
	mux.HandleFunc("/reports/download/", handler.RequireAuth(handler.DownloadReport(store)))
	mux.HandleFunc("/reports/", handler.RequireAuth(handler.ReportDetail(store)))
	mux.HandleFunc("/personal", handler.RequireAuth(handler.Personal(store)))
	mux.HandleFunc("/admin/users", handler.RequireAuth(handler.AdminUsers(store)))
	mux.HandleFunc("/admin/login-log", handler.RequireAuth(handler.LoginLog(store)))

	mux.HandleFunc("/api/user/llm", handler.RequireAuth(handler.UserLLMHandler(store)))

	return mux
}

func Start(addr string, store *storage.Store) error {
	fmt.Printf("🌐 Web 服务已启动: http://%s\n", addr)
	return http.ListenAndServe(addr, New(store))
}
