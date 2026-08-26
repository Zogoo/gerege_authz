// Command device-service owns device state and ingests telemetry.
//
// Two distinct surfaces, deliberately on different path prefixes:
//
//	/internal/devices/...  reached only by smarthome-service, inside the mesh
//	/telemetry/...         reached by a device from outside, under its own identity
//
// The split is not cosmetic. It is what lets the route configuration require a
// registered calling workload on one surface and not on the other, and it is
// what makes Scenario 3c — replaying a valid user token straight at
// device-service — fail with `workload_not_registered` rather than succeeding.
package main

import (
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/gerege/idp-mvp/internal/logx"
	"github.com/gerege/idp-mvp/internal/svc"
)

type device struct {
	ID       string    `json:"id"`
	Home     string    `json:"home"`
	Kind     string    `json:"kind"`
	State    string    `json:"state"`
	Reading  string    `json:"reading,omitempty"`
	Updated  time.Time `json:"updated"`
	UpdateBy string    `json:"updatedBy,omitempty"`
}

var (
	mu      sync.RWMutex
	devices = map[string]*device{
		"thermostat-1": {ID: "thermostat-1", Home: "alice-home", Kind: "thermostat", State: "21°C", Updated: time.Now().UTC()},
		"lock-1":       {ID: "lock-1", Home: "alice-home", Kind: "lock", State: "locked", Updated: time.Now().UTC()},
		"sensor-1":     {ID: "sensor-1", Home: "alice-home", Kind: "sensor", State: "reporting", Updated: time.Now().UTC()},
	}
	telemetry []reading
)

type reading struct {
	Device      string    `json:"device"`
	Temperature float64   `json:"temperature"`
	Humidity    float64   `json:"humidity"`
	At          time.Time `json:"at"`
	Principal   string    `json:"principal"`
}

func main() {
	mux := http.NewServeMux()
	// The device list is scoped by home, so the authorization rule guarding it
	// can name a resource: `gerege/home:{homeId}#view`. A flat /internal/devices
	// would have nothing to check a permission against, and "list everything the
	// caller may see" is the application's job, not the authorizer's — it is
	// what LookupResources exists for (mvp_docs/04 §1).
	mux.HandleFunc("/internal/homes/", homeDevices)
	mux.HandleFunc("/internal/devices/", deviceAction)
	mux.HandleFunc("/telemetry/", ingest)
	svc.Run("device-service", svc.Env("ADDR", ":8080"), svc.Env("HEALTH_ADDR", ":8081"), mux)
}

// homeDevices serves GET /internal/homes/{homeId}/devices.
func homeDevices(w http.ResponseWriter, r *http.Request) {
	homeID, rest := svc.PathTail(r.URL.Path, "/internal/homes")
	if homeID == "" || rest != "devices" || r.Method != http.MethodGet {
		svc.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	mu.RLock()
	defer mu.RUnlock()
	out := make([]device, 0, len(devices))
	for _, d := range devices {
		if d.Home == homeID {
			out = append(out, *d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	svc.WriteJSON(w, http.StatusOK, out)
}

func deviceAction(w http.ResponseWriter, r *http.Request) {
	id, action := svc.PathTail(r.URL.Path, "/internal/devices")
	mu.Lock()
	d, ok := devices[id]
	mu.Unlock()
	if !ok {
		svc.WriteError(w, http.StatusNotFound, "no such device")
		return
	}
	actor := r.Header.Get("x-user-id")

	switch {
	case action == "" && r.Method == http.MethodGet:
		mu.RLock()
		cp := *d
		mu.RUnlock()
		svc.WriteJSON(w, http.StatusOK, cp)

	case action == "unlock" && r.Method == http.MethodPost:
		mu.Lock()
		d.State, d.Updated, d.UpdateBy = "unlocked", time.Now().UTC(), actor
		cp := *d
		mu.Unlock()
		logx.Info("device unlocked", "device", id, "principal", actor,
			"application", r.Header.Get("x-application"))
		svc.WriteJSON(w, http.StatusOK, cp)

	case action == "lock" && r.Method == http.MethodPost:
		mu.Lock()
		d.State, d.Updated, d.UpdateBy = "locked", time.Now().UTC(), actor
		cp := *d
		mu.Unlock()
		svc.WriteJSON(w, http.StatusOK, cp)

	case action == "state" && r.Method == http.MethodPost:
		var in struct {
			State string `json:"state"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.State == "" {
			svc.WriteError(w, http.StatusBadRequest, "state is required")
			return
		}
		mu.Lock()
		d.State, d.Updated, d.UpdateBy = in.State, time.Now().UTC(), actor
		cp := *d
		mu.Unlock()
		svc.WriteJSON(w, http.StatusOK, cp)

	default:
		svc.WriteError(w, http.StatusNotFound, "unsupported device action")
	}
}

// ingest accepts a reading from a device acting under its own identity. The
// authorizer has already checked `push_telemetry` on exactly this device, so a
// sensor cannot report on another device's behalf.
func ingest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		svc.WriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id, _ := svc.PathTail(r.URL.Path, "/telemetry")
	var in struct {
		Temperature float64 `json:"temperature"`
		Humidity    float64 `json:"humidity"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		svc.WriteError(w, http.StatusBadRequest, "malformed body")
		return
	}
	rd := reading{Device: id, Temperature: in.Temperature, Humidity: in.Humidity,
		At: time.Now().UTC(), Principal: r.Header.Get("x-user-id")}

	mu.Lock()
	telemetry = append(telemetry, rd)
	if len(telemetry) > 100 {
		telemetry = telemetry[len(telemetry)-100:]
	}
	if d, ok := devices[id]; ok {
		d.Reading = formatReading(in.Temperature, in.Humidity)
		d.Updated = rd.At
	}
	mu.Unlock()

	logx.Info("telemetry accepted", "device", id, "principal", rd.Principal)
	svc.WriteJSON(w, http.StatusAccepted, rd)
}

func formatReading(t, h float64) string {
	b, _ := json.Marshal(map[string]float64{"temperature": t, "humidity": h})
	return string(b)
}
