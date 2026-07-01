// scalebench measures MLS per-event byte constants and projects reflector and
// host control-plane load across a datacenter envelope (single reflector, S=1),
// with an analytical pairwise-IKEv2 overlay. It prints a CSV sweep and a
// one-line fit verdict.
//
// Usage:
//
//	scalebench [-m 20] [-suite 0x0001] [-rekey-s 3600] [-move-s 600]
//	           [-fwd-budget-mbps 100] [-hosts 1000,10000] [-vnis 1e3,1e4,1e5]
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/trevex/mls-go/bench"
	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/scaling"
)

type config struct {
	M             int
	hosts, vnis   []int
	rekeySeconds  float64
	moveSeconds   float64
	fwdBudgetMBps float64
	suiteID       uint16
}

// run measures the commit-byte constant for cfg.M and returns the CSV + verdict.
func run(cfg config) (string, error) {
	suite, ok := cipher.Lookup(cipher.CipherSuite(cfg.suiteID))
	if !ok {
		return "", fmt.Errorf("ciphersuite %#x not registered", cfg.suiteID)
	}
	bytesPerCommit, err := bench.MeasureCommitBytes(suite, cfg.M, bench.OpUpdate)
	if err != nil {
		return "", fmt.Errorf("measuring commit bytes: %w", err)
	}
	base := scaling.Params{
		M: cfg.M, S: 1,
		RRekey:               1.0 / cfg.rekeySeconds,
		LambdaMove:           1.0 / cfg.moveSeconds,
		BytesPerCommit:       bytesPerCommit,
		FwdBudgetBytesPerSec: cfg.fwdBudgetMBps * 1e6,
	}
	rows := scaling.Sweep(base, cfg.hosts, cfg.vnis)

	var b strings.Builder
	fmt.Fprintf(&b, "# suite=%#x M=%d bytes_per_commit=%d rekey=%.0fs move=%.0fs budget=%.0fMB/s S=1\n",
		cfg.suiteID, cfg.M, bytesPerCommit, cfg.rekeySeconds, cfg.moveSeconds, cfg.fwdBudgetMBps)
	b.WriteString(scaling.CSV(rows))
	if knee, found := scaling.Knee(rows); found {
		fmt.Fprintf(&b, "VERDICT: single reflector saturates at V=%d VNIs (budget %.0f MB/s) — trigger for deferred sharding\n",
			knee, cfg.fwdBudgetMBps)
	} else {
		b.WriteString("VERDICT: single reflector stays under budget across the swept envelope — MLS fits at S=1\n")
	}
	return b.String(), nil
}

func parseIntList(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		f, err := strconv.ParseFloat(part, 64) // accept 1e5 forms
		if err != nil {
			return nil, fmt.Errorf("bad integer %q: %w", part, err)
		}
		out = append(out, int(f))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("empty list")
	}
	return out, nil
}

func main() {
	m := flag.Int("m", 20, "mean members per VNI")
	suite := flag.String("suite", "0x0001", "ciphersuite id (0x0001 classical, 0xF001 X-Wing)")
	rekey := flag.Float64("rekey-s", 3600, "PCS rekey interval per VNI, seconds")
	move := flag.Float64("move-s", 600, "mean seconds between membership changes per VNI")
	budget := flag.Float64("fwd-budget-mbps", 100, "reflector forwarding budget, MB/s")
	hosts := flag.String("hosts", "1000,10000", "comma list of host counts")
	vnis := flag.String("vnis", "1e3,1e4,1e5", "comma list of VNI counts")
	flag.Parse()

	sid, err := strconv.ParseUint(strings.TrimPrefix(*suite, "0x"), 16, 16)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scalebench: bad -suite %q: %v\n", *suite, err)
		os.Exit(2)
	}
	hs, err := parseIntList(*hosts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scalebench: -hosts: %v\n", err)
		os.Exit(2)
	}
	vs, err := parseIntList(*vnis)
	if err != nil {
		fmt.Fprintf(os.Stderr, "scalebench: -vnis: %v\n", err)
		os.Exit(2)
	}
	out, err := run(config{
		M: *m, hosts: hs, vnis: vs,
		rekeySeconds: *rekey, moveSeconds: *move, fwdBudgetMBps: *budget,
		suiteID: uint16(sid),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "scalebench: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(out)
}
