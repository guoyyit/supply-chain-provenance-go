// Command provenanced serves a local build-artifact provenance and policy
// verification service over HTTP. All state lives under a single data
// directory and survives process restarts.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"

	"github.com/guoyyit/supply-chain-provenance-go/provenance"
)

func main() {
	addr := flag.String("addr", ":8080", "HTTP listen address")
	dir := flag.String("dir", "./data", "data directory")
	flag.Parse()

	svc, err := provenance.OpenService(*dir)
	if err != nil {
		log.Fatalf("open service: %v", err)
	}
	defer svc.Close()

	log.Printf("provenanced listening on %s, data dir %s", *addr, *dir)
	if err := http.ListenAndServe(*addr, newMux(svc)); err != nil {
		log.Fatal(err)
	}
}

// newMux wires the HTTP API onto a service instance.
func newMux(svc *provenance.Service) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/artifacts", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"artifacts": svc.Artifacts()})
	})
	mux.HandleFunc("POST /v1/artifacts/{id}/statements", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Type    provenance.StatementType `json:"type"`
			Subject string                   `json:"subject"`
			Content map[string]string        `json:"content"`
		}
		if err := decode(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		st, err := svc.RegisterStatement(r.PathValue("id"), req.Type, req.Subject, req.Content)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, st)
	})
	mux.HandleFunc("GET /v1/artifacts/{id}/statements", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"statements": svc.Statements(r.PathValue("id"))})
	})
	mux.HandleFunc("GET /v1/artifacts/{id}/verify", func(w http.ResponseWriter, r *http.Request) {
		if verr := svc.VerifyArtifact(r.PathValue("id")); verr != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"valid":  false,
				"reason": string(verr.Reason),
				"index":  verr.Index,
				"digest": string(verr.Digest),
				"detail": verr.Detail,
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"valid": true})
	})
	mux.HandleFunc("PUT /v1/policy", func(w http.ResponseWriter, r *http.Request) {
		var p provenance.Policy
		if err := decode(r, &p); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := svc.SetPolicy(p); err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, p)
	})
	mux.HandleFunc("GET /v1/policy", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, svc.Policy())
	})
	mux.HandleFunc("POST /v1/artifacts/{id}/evaluate", func(w http.ResponseWriter, r *http.Request) {
		result, err := svc.Evaluate(r.PathValue("id"))
		if err != nil {
			var verr *provenance.VerificationError
			if errors.As(err, &verr) {
				writeJSON(w, http.StatusConflict, map[string]any{
					"passed": false,
					"reason": string(verr.Reason),
					"index":  verr.Index,
					"detail": verr.Detail,
				})
				return
			}
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		status := http.StatusOK
		if !result.Passed {
			status = http.StatusUnprocessableEntity
		}
		writeJSON(w, status, result)
	})
	mux.HandleFunc("GET /v1/results", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"results": svc.Results()})
	})
	return mux
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
