// metalsim is a CLI driver for the MetalNet dual-redundancy simulation.
//
// Usage:
//
//	metalsim [-scenario <name|all>] [-seed S] [-clients N] [-vnis M]
//	         [-rounds R] [-drop p] [-json] [-v]
//
// Exits nonzero if any invariant fails, making it safe as a CI gate.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/trevex/mls-go/sim"
)

func main() {
	scenarioFlag := flag.String("scenario", "all",
		`scenario name or "all"; built-in: nominal, drops, ds_down, partition_recover, both_rekey, negative_control`)
	clientsFlag := flag.Int("clients", 0, "override number of clients (0 = scenario default)")
	vnisFlag := flag.Int("vnis", 0, "override number of VNIs (0 = scenario default)")
	seedFlag := flag.Int64("seed", 1, "deterministic random seed")
	roundsFlag := flag.Uint64("rounds", 0, "override settle rounds (0 = scenario default)")
	dropFlag := flag.Float64("drop", -1, "per-delivery drop probability [0,1] (< 0 = scenario default)")
	jsonFlag := flag.Bool("json", false, "emit JSON output instead of text tables")
	verboseFlag := flag.Bool("v", false, "print full event trace after each scenario")
	flag.Parse()

	if *scenarioFlag == "all" {
		code := runAll(*clientsFlag, *vnisFlag, *seedFlag, *roundsFlag, *dropFlag, *jsonFlag, *verboseFlag)
		os.Exit(code)
	}

	sc, ok := sim.ByName(*scenarioFlag)
	if !ok {
		fmt.Fprintf(os.Stderr, "metalsim: unknown scenario %q\n", *scenarioFlag)
		fmt.Fprintf(os.Stderr, "  built-in: nominal, drops, ds_down, partition_recover, both_rekey, negative_control\n")
		os.Exit(2)
	}
	applyOverrides(&sc, *clientsFlag, *vnisFlag, *roundsFlag, *dropFlag)

	r := sim.Run(sc, *seedFlag)
	printOne(sc.Name, r, *jsonFlag, *verboseFlag)
	if !r.InvariantsHeld {
		os.Exit(1)
	}
}

// applyOverrides copies non-zero / non-sentinel flag values into sc.
func applyOverrides(sc *sim.Scenario, clients, vnis int, rounds uint64, drop float64) {
	if clients > 0 {
		sc.Clients = clients
	}
	if vnis > 0 {
		sc.VNIs = vnis
	}
	if rounds > 0 {
		sc.SettleRounds = rounds
	}
	if drop >= 0 {
		sc.Faults.DropProb = drop
	}
}

// printOne renders one scenario result to stdout.
func printOne(name string, r sim.Result, jsonOutput, verbose bool) {
	status := "PASS"
	if !r.InvariantsHeld {
		status = "FAIL"
	}
	fmt.Printf("=== scenario: %-22s [%s] ===\n", name, status)
	fmt.Printf("  divergence  (inv.1):  %d failures\n", len(r.Divergence))
	for _, d := range r.Divergence {
		fmt.Printf("    ! %s\n", d)
	}
	fmt.Printf("  packet-loss (inv.2):  %d events\n", len(r.PacketLoss))
	fmt.Printf("  membership  (inv.3):  %d failures\n", len(r.Membership))
	for _, m := range r.Membership {
		fmt.Printf("    ! %s\n", m)
	}
	fmt.Println()

	if jsonOutput {
		b, err := r.Metrics.ReportJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "metalsim: ReportJSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s\n", b)
	} else {
		fmt.Print(r.Metrics.Report())
	}

	if verbose && len(r.Trace) > 0 {
		fmt.Printf("\n--- trace (%d events) ---\n", len(r.Trace))
		for _, line := range r.Trace {
			fmt.Println(line)
		}
	}
	fmt.Println()
}

// scenarioRow is one row in the summary table / JSON array.
type scenarioRow struct {
	Scenario    string `json:"scenario"`
	Pass        bool   `json:"pass"`
	PacketLoss  int    `json:"packet_loss"`
	CommitMsgs  int    `json:"commit_msgs"`
	CommitBytes int    `json:"commit_bytes"`
	DataDecrypt int    `json:"data_decryptable"`
	MaxOverlap  int    `json:"max_overlap"`
	MaxSendLag  uint64 `json:"max_send_lag"`
}

// runAll executes every scenario from sim.All() and prints per-scenario details
// followed by a summary table. Returns 0 if every invariant held, 1 otherwise.
func runAll(clients, vnis int, seed int64, rounds uint64, drop float64, jsonOutput, verbose bool) int {
	scenarios := sim.All()
	rows := make([]scenarioRow, 0, len(scenarios))
	allPass := true

	for _, sc := range scenarios {
		applyOverrides(&sc, clients, vnis, rounds, drop)
		r := sim.Run(sc, seed)
		printOne(sc.Name, r, jsonOutput, verbose)
		rows = append(rows, scenarioRow{
			Scenario:    sc.Name,
			Pass:        r.InvariantsHeld,
			PacketLoss:  len(r.PacketLoss),
			CommitMsgs:  r.Metrics.CommitMsgs,
			CommitBytes: r.Metrics.CommitBytes,
			DataDecrypt: r.Metrics.DataDecryptable,
			MaxOverlap:  r.Metrics.MaxOverlap,
			MaxSendLag:  r.Metrics.MaxSendLag,
		})
		if !r.InvariantsHeld {
			allPass = false
		}
	}

	fmt.Println("=== summary (all scenarios, seed", seed, ") ===")
	if jsonOutput {
		b, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Printf("%s\n", b)
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "scenario\tstatus\tpkt-loss\tcommit-msgs\tcommit-bytes\tdata-decryptable\tmax-overlap\tmax-send-lag")
		for _, row := range rows {
			status := "PASS"
			if !row.Pass {
				status = "FAIL"
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\n",
				row.Scenario, status, row.PacketLoss, row.CommitMsgs, row.CommitBytes,
				row.DataDecrypt, row.MaxOverlap, row.MaxSendLag)
		}
		_ = w.Flush()
	}

	if allPass {
		return 0
	}
	return 1
}
