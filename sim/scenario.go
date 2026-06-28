package sim

import (
	"fmt"

	"github.com/trevex/mls-mlkem-go/mls/cipher"
)

// Scenario is a built-in simulation profile (design spec §4).
type Scenario struct {
	Name         string
	Clients      int
	VNIs         int
	Suite        cipher.CipherSuite
	W            int // SA-overlap depth (default 4; de-risked min is 2)
	Faults       FaultConfig
	Partitions   []scriptedPartition
	DSDowns      []scriptedDSDown
	Churn        []ChurnOp
	SettleRounds uint64
	MBBDisabled  bool // negative control
}

type scriptedPartition struct {
	At, Until    uint64
	SideA, SideB []ActorID
}
type scriptedDSDown struct {
	At, Until uint64
	DS        ActorID
}

const defaultSuite = cipher.XWING_AES256GCM_SHA256_Ed25519

func base(name string, clients, vnis int) Scenario {
	return Scenario{Name: name, Clients: clients, VNIs: vnis, Suite: defaultSuite,
		W: 4, SettleRounds: 200,
		Faults: FaultConfig{Latency: 2, Jitter: 2}}
}

// Nominal: churn across M VNIs, no faults (baseline; expect zero forks).
func Nominal() Scenario {
	s := base("nominal", 5, 2)
	s.Churn = churnPlan(5, 2)
	return s
}

// Drops: steady 20% per-delivery drops + churn.
func Drops() Scenario {
	s := base("drops", 5, 2)
	s.Faults.DropProb = 0.2
	s.Churn = churnPlan(5, 2)
	return s
}

// DSDown: one reflector stops mid-run then restarts; clients ride the other.
func DSDown() Scenario {
	s := base("ds_down", 5, 2)
	s.Churn = churnPlan(5, 2)
	s.DSDowns = []scriptedDSDown{{At: 50, Until: 120, DS: ActorID(5)}} // first DS id = Clients
	return s
}

// PartitionRecover: a client subset is cut from one DS, then heals.
func PartitionRecover() Scenario {
	s := base("partition_recover", 6, 2)
	s.Churn = churnPlan(6, 2)
	s.Partitions = []scriptedPartition{{At: 40, Until: 140,
		SideA: []ActorID{0, 1}, SideB: []ActorID{6}}} // cut clients 0,1 from DS #0
	return s
}

// SplitBrain: DS↔DS partition + concurrent churn pressure ⇒ competing commits.
func SplitBrain() Scenario {
	s := base("split_brain", 6, 1)
	s.Churn = churnPlanDense(6, 1)
	s.Partitions = []scriptedPartition{{At: 30, Until: 160,
		SideA: []ActorID{6}, SideB: []ActorID{7}}} // sever the two DS from each other
	s.SettleRounds = 400
	return s
}

// All returns the suite in deterministic order.
func All() []Scenario {
	return []Scenario{Nominal(), Drops(), DSDown(), PartitionRecover(), SplitBrain()}
}

// ByName looks up a scenario for the CLI.
func ByName(name string) (Scenario, bool) {
	for _, s := range All() {
		if s.Name == name {
			return s, true
		}
	}
	return Scenario{}, false
}

// churnPlan builds a simple join-then-leave plan: each non-founder client joins
// each VNI at staggered times, then some leave before the end of the scenario.
func churnPlan(clients, vnis int) []ChurnOp {
	var ops []ChurnOp
	// clients 1..clients-1 join vnis at staggered times
	for c := 1; c < clients; c++ {
		for v := 0; v < vnis; v++ {
			ops = append(ops, ChurnOp{Join: true, Client: ActorID(c), VNI: uint32(v)})
		}
	}
	return ops
}

// churnPlanDense adds more joins per VNI to increase concurrent-committer pressure.
func churnPlanDense(clients, vnis int) []ChurnOp {
	var ops []ChurnOp
	for c := 1; c < clients; c++ {
		for v := 0; v < vnis; v++ {
			ops = append(ops, ChurnOp{Join: true, Client: ActorID(c), VNI: uint32(v)})
		}
	}
	// Also add a second wave of joins (re-join) to create more races.
	half := clients / 2
	for c := 1; c <= half; c++ {
		for v := 0; v < vnis; v++ {
			ops = append(ops, ChurnOp{Join: true, Client: ActorID(c), VNI: uint32(v)})
		}
	}
	return ops
}

// failureSummary formats a Result for test output.
func failureSummary(r Result) string {
	return fmt.Sprintf(
		"divergence=%v fork=%v liveness=%v membership=%v packetLoss=%d forks=%d",
		r.Divergence, r.Fork, r.Liveness, r.Membership, len(r.PacketLoss),
		r.Metrics.Forks,
	)
}
