package tree

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// treekem.json scenario 0 (suite 1), update_paths[0].update_path.
const scenario0UpdatePathHex = "20b3dfdc6de908f094fa9b6e13cdfb972cc7596f0788ed2128be628fdd5bdeec4d20c4c1595a92bc2fe9413a0eb6484a106159300bbd27d9f69c8287bff4c812685100012064f3832198d0541bb38e744801075164e81371c4952ad36e2a41c8fcac593f930200010c0001000200030004000500060000040001000203204ab91adcf7be9ea795042e1fd2d3c2021d3bdc7c0a767bb13b96f4b2b75b7188004040c42e9b322d874ac6f51b40fdad15f740ff99e85fa86c0c5da28dddcb9667403eb94e55bd34fd610be9308c86b3e881b1751649f15d34ede85689f59968116202407520875897dba7d6d7a545729ad08582e8372876b4f323f9ba75e0e0c66da8d84b14405220c8d8c0ec4526045cce5979e3cb3a2435322b20cb224073c1b00ef0deb336d50b30f7b94d151d792713a4814d0bc3219d627fe44c0f82258db4804ea79bda9c18027da4c9a4ef89cc703d70049104889432"

func TestUpdatePathRoundTrip(t *testing.T) {
	raw := mustHex(t, scenario0UpdatePathHex)
	var up UpdatePath
	if err := up.UnmarshalMLS(raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if up.LeafNode.LeafNodeSource != LeafNodeSourceCommit {
		t.Errorf("leaf source = %d, want commit(3)", up.LeafNode.LeafNodeSource)
	}
	if len(up.Nodes) != 1 { // 2-leaf tree: filtered direct path of sender 0 is [root]
		t.Fatalf("len(nodes) = %d, want 1", len(up.Nodes))
	}
	if len(up.Nodes[0].EncryptedPathSecret) != 1 { // resolution of copath child = [leaf 1]
		t.Fatalf("len(encrypted_path_secret) = %d, want 1", len(up.Nodes[0].EncryptedPathSecret))
	}
	out, err := up.MarshalMLS()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Equal(out, raw) {
		t.Fatalf("round-trip mismatch:\n got %x\nwant %x", out, raw)
	}
}
