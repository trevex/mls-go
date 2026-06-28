package sim

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestMetricsTextReport(t *testing.T) {
	m := newMetrics()
	m.Delivered = 42
	m.CtrlDropped = 3
	m.DataSent = 10
	m.DataDecryptable = 10
	m.cpu("Rekey", 500*time.Microsecond)
	m.cpu("Rekey", 300*time.Microsecond)

	report := m.Report()
	if !strings.Contains(report, "delivered") {
		t.Error("Report missing 'delivered'")
	}
	if !strings.Contains(report, "42") {
		t.Error("Report missing delivered count 42")
	}
	if !strings.Contains(report, "cpu/Rekey") {
		t.Error("Report missing cpu/Rekey entry")
	}
	// tabwriter should align columns — at least two spaces between columns
	for _, line := range strings.Split(report, "\n") {
		if strings.Contains(line, "delivered") && !strings.Contains(line, "  ") {
			t.Errorf("tabwriter alignment missing in line: %q", line)
		}
	}
}

func TestMetricsJSON(t *testing.T) {
	m := newMetrics()
	m.Delivered = 7
	m.cpu("HandleCommit", time.Millisecond)

	b, err := m.ReportJSON()
	if err != nil {
		t.Fatal("ReportJSON error:", err)
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(b, &obj); err != nil {
		t.Fatal("invalid JSON:", err)
	}
	// Check that Delivered appears in JSON
	if _, ok := obj["Delivered"]; !ok {
		t.Error("JSON missing 'Delivered' key")
	}
	if _, ok := obj["cpu"]; !ok {
		t.Error("JSON missing 'cpu' key")
	}
}

func TestMetricsDeterministic(t *testing.T) {
	build := func() *Metrics {
		m := newMetrics()
		m.Delivered = 100
		m.cpu("Rekey", time.Millisecond)
		m.cpu("HandleCommit", 2*time.Millisecond)
		m.cpu("Rekey", 500*time.Microsecond)
		return m
	}
	r1 := build().Report()
	r2 := build().Report()
	if r1 != r2 {
		t.Fatal("Report() is not deterministic for identical inputs")
	}
	b1, _ := build().ReportJSON()
	b2, _ := build().ReportJSON()
	if string(b1) != string(b2) {
		t.Fatal("ReportJSON() is not deterministic for identical inputs")
	}
}
