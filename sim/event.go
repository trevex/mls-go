package sim

import "crypto/sha256"

// ActorID identifies an actor in the simulation. Clients are 0..C-1; the two
// DS reflectors are C and C+1. -1 means "broadcast to all VNI subscribers".
type ActorID int

const Broadcast ActorID = -1

// MsgType enumerates the envelope payload kinds (design spec §3.1).
type MsgType int

const (
	MsgCommit     MsgType = iota // real MLS commit bytes (member or external)
	MsgWelcome                   // real MLS Welcome bytes (joiner)
	MsgHeartbeat                 // {epoch} liveness beacon (drives min-epoch sender-lag)
	MsgLogRequest                // catch-up request {fromEpoch}
	MsgLogReply                  // catch-up reply (carries commit records)
	MsgData                      // tenant ESP data packet {spi, epoch}
)

func (m MsgType) String() string {
	switch m {
	case MsgCommit:
		return "commit"
	case MsgWelcome:
		return "welcome"
	case MsgHeartbeat:
		return "heartbeat"
	case MsgLogRequest:
		return "logRequest"
	case MsgLogReply:
		return "logReply"
	case MsgData:
		return "data"
	default:
		return "unknown"
	}
}

// Envelope is one in-flight message (design spec §3.1).
type Envelope struct {
	VNI     uint32
	Type    MsgType
	Src     ActorID
	Dst     ActorID        // Broadcast or a specific actor
	Base    uint64         // base epoch a commit was produced FROM (commit), or data/heartbeat epoch
	Payload []byte         // real MLS/ironcore bytes (commit/welcome) or nil
	SPI     uint32         // for MsgData: the sender's send-SA SPI
	Records []CommitRecord // for MsgLogReply
	Joiner  string         // for MsgWelcome: identity the Welcome is addressed to
	Hash    string         // content hash for dedup (set by sender)
}

// CommitRecord is one entry in a DS per-VNI committed log (design spec §3.2).
type CommitRecord struct {
	Base  uint64
	Bytes []byte
	Hash  string
}

// EventKind tags an event's dispatch (design spec §2).
type EventKind int

const (
	KindDeliver EventKind = iota // deliver Env to Actor
	KindTimer                    // a scheduled timer fires on Actor
	KindFault                    // apply/lift a fault
	KindChurn                    // membership change
)

// TimerKind enumerates client/DS timers.
type TimerKind int

const (
	TimerRekey     TimerKind = iota // committer issues a PCS Update
	TimerHeartbeat                  // client emits a heartbeat
	TimerReconcile                  // committer reconciles desired vs current
	TimerData                       // a tenant data packet is generated
)

// faultKind distinguishes fault types (detail in fault.go).
type faultKind int

// FaultOp toggles a fault (design spec §3.4).
type FaultOp struct {
	Kind  faultKind
	On    bool
	DS    ActorID // for ds_down
	SideA []ActorID
	SideB []ActorID
}

// ChurnOp is a scheduled membership change (design spec §3.3).
type ChurnOp struct {
	Join   bool
	Client ActorID
	VNI    uint32
}

// Event is one scheduled action (design spec §2).
type Event struct {
	At    uint64
	Seq   uint64
	Kind  EventKind
	Actor ActorID
	Env   Envelope
	Timer TimerKind
	Fault FaultOp
	Churn ChurnOp
}

// contentHash is the dedup/identity hash of a message payload.
func contentHash(b []byte) string {
	h := sha256.Sum256(b)
	return string(h[:])
}
