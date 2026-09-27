// provenanced 是本地软件构建产物来源证明与验证服务。
//
// 提供来源声明登记、声明链校验与发布策略判定的 HTTP API。
// 数据保存在本地目录，重启自动恢复。
package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"

	"github.com/guoyyit/supply-chain-provenance-go/provenance"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8080", "HTTP 监听地址")
	dir := flag.String("dir", "./data", "数据存储目录")
	flag.Parse()

	svc, err := provenance.Open(*dir)
	if err != nil {
		log.Fatalf("open service: %v", err)
	}
	defer svc.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/artifacts/{id}/statements", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Type    string            `json:"type"`
			Content map[string]string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: "+err.Error())
			return
		}
		if req.Type == "" {
			writeError(w, http.StatusBadRequest, "type is required")
			return
		}
		st, err := svc.RegisterStatement(r.PathValue("id"), req.Type, req.Content)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, st)
	})
	mux.HandleFunc("GET /v1/artifacts/{id}/statements", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, svc.Statements(r.PathValue("id")))
	})
	mux.HandleFunc("GET /v1/artifacts/{id}/verify", func(w http.ResponseWriter, r *http.Request) {
		if err := svc.Verify(r.PathValue("id")); err != nil {
			writeJSON(w, http.StatusConflict, map[string]any{"ok": false, "error": err})
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("PUT /v1/artifacts/{id}/policy", func(w http.ResponseWriter, r *http.Request) {
		var p provenance.Policy
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeError(w, http.StatusBadRequest, "invalid policy: "+err.Error())
			return
		}
		if err := svc.SetPolicy(r.PathValue("id"), p); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, p)
	})
	mux.HandleFunc("POST /v1/artifacts/{id}/evaluate", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, svc.Evaluate(r.PathValue("id")))
	})

	log.Printf("provenanced listening on %s, data dir %s", *addr, *dir)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatal(err)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
