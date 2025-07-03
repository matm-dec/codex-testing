package api

import (
	"encoding/json"
	"net/http"
)

type LiveMac struct {
	MAC  string `json:"mac"`
	VLAN string `json:"vlan"`
}

func LiveMacs(w http.ResponseWriter, r *http.Request) {
	data := []LiveMac{{MAC: "aa:bb:cc:dd:ee:01", VLAN: "1"}}
	json.NewEncoder(w).Encode(data)
}

type AuditResult struct {
	Timestamp string `json:"timestamp"`
	Status    string `json:"status"`
}

func AuditReport(w http.ResponseWriter, r *http.Request) {
	data := []AuditResult{{Timestamp: "2024-01-01T00:00:00Z", Status: "clean"}}
	json.NewEncoder(w).Encode(data)
}
