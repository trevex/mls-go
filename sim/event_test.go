package sim

import "testing"

// TestContentHashStable verifies contentHash is deterministic and distinguishes
// distinct payloads.
func TestContentHashStable(t *testing.T) {
	a := []byte("hello simulation")
	b := []byte("world simulation")

	h1 := contentHash(a)
	h2 := contentHash(a)
	if h1 != h2 {
		t.Fatalf("contentHash not deterministic: %x vs %x", h1, h2)
	}

	h3 := contentHash(b)
	if h1 == h3 {
		t.Fatalf("contentHash collision on distinct payloads")
	}

	// empty payload has a well-defined hash
	h4 := contentHash(nil)
	h5 := contentHash([]byte{})
	if h4 != h5 {
		t.Fatalf("contentHash(nil) != contentHash([]byte{})")
	}
}

// TestEnvelopeKindString verifies MsgType.String() round-trips for trace readability.
func TestEnvelopeKindString(t *testing.T) {
	cases := []struct {
		m    MsgType
		want string
	}{
		{MsgCommit, "commit"},
		{MsgWelcome, "welcome"},
		{MsgGroupInfo, "groupInfo"},
		{MsgHeartbeat, "heartbeat"},
		{MsgLogRequest, "logRequest"},
		{MsgLogReply, "logReply"},
		{MsgData, "data"},
		{MsgType(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.m.String(); got != c.want {
			t.Errorf("MsgType(%d).String() = %q, want %q", c.m, got, c.want)
		}
	}
}
