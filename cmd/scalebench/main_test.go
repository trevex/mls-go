package main

import (
	"strings"
	"testing"
)

func TestRunProducesCSVAndVerdict(t *testing.T) {
	out, err := run(config{
		M: 20, hosts: []int{1000, 10000}, vnis: []int{1000, 100000},
		rekeySeconds: 3600, moveSeconds: 600, fwdBudgetMBps: 100,
		suiteID: 0x0001,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "H,V,M,") {
		t.Fatal("expected CSV header in output")
	}
	if !strings.Contains(out, "VERDICT") {
		t.Fatal("expected a verdict line in output")
	}
}
