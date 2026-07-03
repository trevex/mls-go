package sim

import (
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
)

// Scenario is a built-in simulation profile (dual-group pure redundancy, rev 5 §0).
type Scenario struct {
	Name            string
	Clients         int
	VNIs            int
	Suite           cipher.CipherSuite
	W               int // per-replica SA-overlap depth (make-before-break window)
	Faults          FaultConfig
	Partitions      []scriptedPartition
	DSDowns         []scriptedDSDown
	Churn           []ChurnOp
	SettleRounds    uint64
	MBBDisabled     bool // negative control: W=0 + no sender-lag
	SingleReplica   bool // negative control: model only ONE replica (no redundancy)
	SharedSPIReplay bool // negative control: senders use the single group SPI (shared anti-replay window)
	// EncryptHandshakes makes every VNI in this scenario frame member handshakes
	// as PrivateMessage (maps to ironcore HandshakePrivacy). Default false: the
	// other scenarios opt out to HandshakePlaintext explicitly (see client.go) —
	// a deliberate opt-out of ironcore's HandshakeEncrypted zero-value default —
	// so the plaintext-exposure invariant applies only to EncryptedChurn.
	EncryptHandshakes bool
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
		W: 4, SettleRounds: 300,
		Faults: FaultConfig{Latency: 2, Jitter: 2}}
}

// reflectorID returns reflector R_r's ActorID for a scenario (clients are
// 0..Clients-1; R_0 = Clients, R_1 = Clients+1).
func (s Scenario) reflectorID(r int) ActorID { return ActorID(s.Clients + r) }

// Nominal: churn across M VNIs, no faults. Both replicas converge independently.
func Nominal() Scenario {
	s := base("nominal", 5, 2)
	s.Churn = churnPlan(5, 2)
	return s
}

// Drops: steady 20% per-delivery drops + churn. Exercises log-replay catch-up and
// committer resend; both replicas must still converge with zero key-loss.
func Drops() Scenario {
	s := base("drops", 5, 2)
	s.Faults.DropProb = 0.2
	s.Churn = churnPlan(5, 2)
	return s
}

// DSDown: reflector R0 stops mid-run then restarts → replica 0 stalls. The
// redundancy headline: replica 1's SA carries all data (ZERO loss) while R0 is
// down; replica 0 catches up on R0's return.
//
// This scenario demonstrates graceful-freeze-with-no-loss: R0 going down causes
// replica-0 to cleanly stall (no new commits), data keeps decrypting on the
// still-valid replica-0 SAs (within the W window) and on replica-1.  For
// active cross-replica failover under a live partition see PartitionRecover.
func DSDown() Scenario {
	s := base("ds_down", 5, 2)
	s.Churn = churnPlan(5, 2)
	s.DSDowns = []scriptedDSDown{{At: 50, Until: 130, DS: s.reflectorID(0)}}
	return s
}

// PartitionRecover: a client subset is cut from reflector R0 → those clients fall
// behind on replica 0 and ride replica 1 (ZERO loss); they catch up replica 0 on
// heal.
func PartitionRecover() Scenario {
	s := base("partition_recover", 6, 2)
	s.Churn = churnPlan(6, 2)
	s.Partitions = []scriptedPartition{{At: 40, Until: 150,
		SideA: []ActorID{2, 3}, SideB: []ActorID{s.reflectorID(0)}}}
	return s
}

// BothRekey: concurrent periodic rekeys across both replicas of multiple VNIs +
// churn, no faults. Asserts zero key-loss via per-replica make-before-break while
// both groups rotate keys independently.
func BothRekey() Scenario {
	s := base("both_rekey", 5, 3)
	s.Churn = churnPlan(5, 3)
	return s
}

// EncryptedChurn drives membership churn with encrypted member handshakes and
// asserts the reflectors never observe plaintext membership changes.
func EncryptedChurn() Scenario {
	s := Nominal()
	s.Name = "encrypted_churn"
	s.EncryptHandshakes = true
	return s
}

// migrationPlan models VM migration across hosts: for each VNI, hosts 1 and 2
// initially hold a VM (join), then each VM migrates to a new host (the old host
// leaves, a spare host joins). The founder (client 0) is the committer and never
// migrates. Requires clients >= 5 (0 founder, 1-2 initial, 3-4 destinations).
func migrationPlan(vnis int) []ChurnOp {
	var ops []ChurnOp
	for v := 0; v < vnis; v++ {
		vv := uint32(v)
		// initial placement
		ops = append(ops, ChurnOp{Join: true, Client: 1, VNI: vv})
		ops = append(ops, ChurnOp{Join: true, Client: 2, VNI: vv})
	}
	for v := 0; v < vnis; v++ {
		vv := uint32(v)
		// migrate host1's VM -> host3, host2's VM -> host4 (leave src, join dst)
		ops = append(ops, ChurnOp{Join: false, Client: 1, VNI: vv})
		ops = append(ops, ChurnOp{Join: true, Client: 3, VNI: vv})
		ops = append(ops, ChurnOp{Join: false, Client: 2, VNI: vv})
		ops = append(ops, ChurnOp{Join: true, Client: 4, VNI: vv})
	}
	return ops
}

// MigrationChurn exercises leave + join membership churn modeling VM migration
// across hosts. Asserts the dual-redundancy invariants still hold under removes.
func MigrationChurn() Scenario {
	s := base("migration_churn", 5, 2)
	s.Churn = migrationPlan(2)
	return s
}

// NegativeControl is the data-plane negative control: ONE replica, W=0, no
// sender-lag. A rekey under churn MUST produce undecryptable packets (inv. 2
// fails), proving the zero-loss checker has teeth.
func NegativeControl() Scenario {
	s := base("negative_control", 5, 2)
	s.Faults.DropProb = 0.2
	s.Churn = churnPlan(5, 2)
	s.MBBDisabled = true
	s.SingleReplica = true
	return s
}

// SharedSPIReplayControl is the anti-replay negative control: multiple senders
// share one group SPI ⇒ one shared replay window ⇒ concurrent senders collide
// and the receiver drops legitimate packets as replays (ReplayDrops > 0).
func SharedSPIReplayControl() Scenario {
	s := base("shared_spi_replay", 5, 2)
	s.Churn = churnPlan(5, 2)
	s.SharedSPIReplay = true
	return s
}

// All returns the property-tested suite in deterministic order.
// migration_churn is intentionally excluded pending soak: it is the first
// leave/remove scenario and is validated by its own test (migration_test.go);
// promote it here in a follow-up once it has soaked.
func All() []Scenario {
	return []Scenario{Nominal(), Drops(), DSDown(), PartitionRecover(), BothRekey(), EncryptedChurn()}
}

// ByName looks up a scenario for the CLI.
func ByName(name string) (Scenario, bool) {
	for _, s := range append(All(), NegativeControl(), MigrationChurn(), SharedSPIReplayControl()) {
		if s.Name == name {
			return s, true
		}
	}
	return Scenario{}, false
}

// churnPlan builds a join plan: each non-founder client joins each VNI (both
// replicas) at staggered times.
func churnPlan(clients, vnis int) []ChurnOp {
	var ops []ChurnOp
	for c := 1; c < clients; c++ {
		for v := 0; v < vnis; v++ {
			ops = append(ops, ChurnOp{Join: true, Client: ActorID(c), VNI: uint32(v)})
		}
	}
	return ops
}

// failureSummary formats a Result for test output.
func failureSummary(r Result) string {
	return fmt.Sprintf(
		"divergence=%v membership=%v packetLoss=%d dataSent=%d dataDecryptable=%d",
		r.Divergence, r.Membership, len(r.PacketLoss),
		r.Metrics.DataSent, r.Metrics.DataDecryptable,
	)
}
