package handler

import (
	"encoding/json"
	"net/http"
	"strings"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

// GetUserLLMConfig 返回当前用户的 LLM 配置（API Key 不返回真实值）
func GetUserLLMConfig(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		config := store.GetUserLLMConfig(sess.Username)
		resp := map[string]interface{}{
			"enabled":  false,
			"provider": "",
			"has_key":  false,
		}
		if config != nil {
			resp["enabled"] = config.Enabled
			resp["provider"] = config.Provider
			resp["has_key"] = config.APIKey != ""
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// UpdateUserLLMConfig 更新当前用户的 LLM 配置
func UpdateUserLLMConfig(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			Enabled        bool   `json:"enabled"`
			Provider       string `json:"provider"`
			APIKey         string `json:"api_key"`
			MiniMaxGroupID string `json:"minimax_group_id"`
			DeleteKey      bool   `json:"delete_key"` // 是否删除已保存的 Key
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		config := store.GetUserLLMConfig(sess.Username)
		if config == nil {
			config = &models.LLMConfig{}
		}

		// 根据 provider 和 API Key 是否有效来决定是否启用
		if req.Provider == "deepseek" && req.APIKey != "" {
			config.Enabled = true
			config.Provider = "deepseek"
			config.APIKey = strings.TrimSpace(req.APIKey)
			config.MiniMaxGroupID = ""
		} else if req.Provider == "minimax" && req.APIKey != "" && req.MiniMaxGroupID != "" {
			config.Enabled = true
			config.Provider = "minimax"
			config.APIKey = strings.TrimSpace(req.APIKey)
			config.MiniMaxGroupID = strings.TrimSpace(req.MiniMaxGroupID)
		} else {
			// 如果没有有效的 API Key，禁用 LLM
			config.Enabled = false
		}

		if req.DeleteKey {
			config.APIKey = ""
			config.Enabled = false
		}

		if err := store.SaveUserLLMConfig(sess.Username, config); err != nil {
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}

		statusMsg := "已禁用"
		if config.Enabled {
			statusMsg = "已启用"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": statusMsg})
	}
}

// UserLLMHandler 处理 /api/user/llm 的 GET 和 POST 请求
func UserLLMHandler(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			GetUserLLMConfig(store)(w, r)
		case http.MethodPost:
			UpdateUserLLMConfig(store)(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}
