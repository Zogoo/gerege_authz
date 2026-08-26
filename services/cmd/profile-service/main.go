// Command profile-service owns profile data. It is never reachable from
// outside the cluster: every call arrives from another workload in the mesh,
// and every one of them is authorized independently at this service's own
// sidecar.
//
// Note what is absent: there is no authorization logic here. The service does
// not check who is calling, what they may see, or whether the user consented.
// By the time a request arrives, ext-authz has already answered all three. That
// is the point of the architecture — authorization is not scattered across
// application code.
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/gerege/idp-mvp/internal/svc"
)

type profile struct {
	UserID  string `json:"userId"`
	Name    string `json:"name"`
	Email   string `json:"email"`
	Phone   string `json:"phone"`
	Address string `json:"address"`
}

var (
	mu    sync.RWMutex
	store = map[string]*profile{
		"alice": {UserID: "alice", Name: "Alice Andersen", Email: "alice@gerege.test",
			Phone: "+976 9911 0001", Address: "12 Peace Avenue, Ulaanbaatar"},
		"bob": {UserID: "bob", Name: "Bob Baker", Email: "bob@gerege.test",
			Phone: "+976 9911 0002", Address: "5 Seoul Street, Ulaanbaatar"},
	}
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/profile/", handleProfile)
	svc.Run("profile-service", svc.Env("ADDR", ":8080"), svc.Env("HEALTH_ADDR", ":8081"), mux)
}

func handleProfile(w http.ResponseWriter, r *http.Request) {
	userID, _ := svc.PathTail(r.URL.Path, "/api/profile")
	if userID == "" {
		svc.WriteError(w, http.StatusNotFound, "no user id in path")
		return
	}
	switch r.Method {
	case http.MethodGet:
		mu.RLock()
		p, ok := store[userID]
		mu.RUnlock()
		if !ok {
			svc.WriteError(w, http.StatusNotFound, "no such profile")
			return
		}
		svc.WriteJSON(w, http.StatusOK, p)
	case http.MethodPut:
		var in profile
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			svc.WriteError(w, http.StatusBadRequest, "malformed body")
			return
		}
		mu.Lock()
		p, ok := store[userID]
		if !ok {
			mu.Unlock()
			svc.WriteError(w, http.StatusNotFound, "no such profile")
			return
		}
		if strings.TrimSpace(in.Address) != "" {
			p.Address = in.Address
		}
		if strings.TrimSpace(in.Phone) != "" {
			p.Phone = in.Phone
		}
		cp := *p
		mu.Unlock()
		svc.WriteJSON(w, http.StatusOK, cp)
	default:
		svc.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
