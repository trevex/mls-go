# Ratchet Tree / TreeSync (Plan 4 of 8) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the RFC 9420 §7 ratchet-tree data model and its *static* validation: the `Credential`, `LeafNode` (+ `LeafNodeTBS` signing/verification), `ParentNode`, and `Node`/ratchet-tree array types with byte-accurate marshal/unmarshal; node **resolution** (§4.1.1/§7.7), **tree hash** (§7.8), **parent hash** (§7.9) and **parent-hash-valid** verification (§7.9.2); plus leaf-signature verification and signature-key/encryption-key uniqueness (§7.3). The work is gated by the official `tree-validation.json` KAT, which is the authoritative acceptance test.

**Architecture:** Everything lands in the existing `mls/tree` package (which already holds the node-index math in `math.go`). New types implement the established codec convention — an unexported `marshal(*syntax.Builder) error` method and a package-level `decodeX(*syntax.Cursor) (X, error)` function, with exported `MarshalMLS()`/`UnmarshalMLS()` wrappers (top-level `Unmarshal` enforces `Cursor.Empty()`). The ratchet tree itself is an opaque `RatchetTree` value (array of `*Node`, nil = blank) carrying its `cipher.Suite`; it exposes `Resolution`, `TreeHash`, `RootTreeHash`, `VerifyParentHashes`, and `VerifyLeafSignatures`. Tree mutation (applying Add/Update/Remove, the `tree-operations.json` KAT) is **deferred to Plan 4b** because it depends on `Proposal` types not defined until later plans.

**Tech Stack:** Go 1.26 standard library only (`fmt`, `bytes`, `crypto/ed25519` in tests). Builds on `mls/syntax` (Builder/Cursor + generic `WriteVectorV`/`ReadVectorV`/`WriteOptional`/`ReadOptional`), `mls/cipher` (`Suite.Hash`, `Suite.SignWithLabel`/`VerifyWithLabel`, `Lookup`, `CipherSuite`), `mls/tree` math (`NodeWidth`, `Root`, `Left`, `Right`, `Parent`, `Sibling`, plus the unexported `level`), and `mls/internal/katutil`.

**Spec reference:** RFC 9420 §5.3 (credentials), §4.1.1 (resolution), §7.1 (ParentNode), §7.2 (LeafNode/LeafNodeTBS), §7.3 (leaf-node validation), §7.8 (tree hashes), §7.9 / §7.9.1 / §7.9.2 (parent hashes), §12.4.3.1 (ratchet_tree extension wire form). KAT format: <https://github.com/mlswg/mls-implementations/blob/main/test-vectors.md>.

> **Go invocation convention:** Go is **not** on `PATH`. Every Go command runs through the nix devshell, e.g. `nix develop -c go test ./mls/tree/`, `nix develop -c go vet ./mls/...`, `nix develop -c gofmt -l mls/`. Use this form everywhere below.

---

## Design notes (read before implementing)

These are the non-obvious facts pinned directly from RFC 9420 (verbatim structs quoted in the relevant tasks). Get them exactly right or the KAT will not pass.

1. **Enum widths.** `CredentialType`, `ExtensionType`, `ProposalType`, `CipherSuite`, `ProtocolVersion` are all `uint16`. `LeafNodeSource` and `NodeType` are `uint8` (their enums top out at `(255)`). `HPKEPublicKey` and `SignaturePublicKey` are `opaque <V>` (varint-length byte vectors).

2. **`LeafNodeTBS` is the LeafNode body without the signature, plus group context for `update`/`commit`.** The signature is `SignWithLabel(sigkey, "LeafNodeTBS", LeafNodeTBS)`. For `key_package` source the TBS has **no** trailing group context; for `update` and `commit` it appends `opaque group_id<V>` then `uint32 leaf_index`. The selected middle field is `Lifetime` (key_package), empty `struct{}` (update), or `opaque parent_hash<V>` (commit).

3. **ratchet_tree wire form (`tree` field of the vector).** `optional<Node> ratchet_tree<V>` where `Node` is a `uint8 node_type` (leaf=1, parent=2) discriminating `LeafNode`/`ParentNode`. Nodes are listed in left-to-right in-order traversal (the same array order as `math.go`: leaf `L` at array index `2*L`, root at `2^d - 1`). The serialized vector **omits trailing blank nodes**; the receiver MUST reject a vector whose last element is blank, then extend to width `2^(d+1) - 1` by appending blanks. When re-serializing, truncate trailing blanks again.

4. **Resolution (§4.1.1).** Returns a list of **node indices**.
   - non-blank node → `[i]` followed by its unmerged leaves rendered as node indices `2*L` (parent nodes only; leaf nodes have none);
   - blank leaf → `[]`;
   - blank parent → `resolution(left) ++ resolution(right)`.

5. **Tree hash (§7.8).** `node_hash = Hash(TreeHashInput)`:
   ```
   enum { reserved(0), leaf(1), parent(2), (255) } NodeType;
   struct {
     NodeType node_type;
     select (TreeHashInput.node_type) {
       case leaf:   LeafNodeHashInput leaf_node;
       case parent: ParentNodeHashInput parent_node;
     };
   } TreeHashInput;
   struct { uint32 leaf_index; optional<LeafNode> leaf_node; } LeafNodeHashInput;
   struct { optional<ParentNode> parent_node; opaque left_hash<V>; opaque right_hash<V>; } ParentNodeHashInput;
   ```
   The optional is **absent** for a blank node, **present** otherwise. Computed recursively from the leaves up; `left_hash`/`right_hash` are the children's tree hashes.

6. **Parent hash (§7.9).** `parent_hash = Hash(ParentHashInput)`:
   ```
   struct {
     HPKEPublicKey encryption_key;          // P's encryption_key
     opaque parent_hash<V>;                 // P's *stored* parent_hash field ("" if P is root)
     opaque original_sibling_tree_hash<V>;  // tree hash of S (P's other child), in the "original tree"
   } ParentHashInput;
   ```
   For node `D` with parent `P` and sibling `S`: the value stored in `D.parent_hash` must equal `Hash(ParentHashInput)` built from `P`. **`ParentHashInput.parent_hash` is read directly from `P.parent_hash`** (not recomputed) — the RFC defines it as "the parent hash of the next node after P on the filtered direct path", i.e. exactly the field stored in `P`.
   The **original tree hash** of `S` is the ordinary §7.8 tree hash of the subtree at `S`, but in a tree "modified as follows: For each leaf L in P.unmerged_leaves, blank L and remove it from the unmerged_leaves sets of all parent nodes." Implement this as a single `treeHashExcept(i, excluded)` where `excluded = set(P.unmerged_leaves)`: leaves in `excluded` are treated as blank, and every `ParentNode.unmerged_leaves` is filtered to drop entries in `excluded`. With an empty `excluded`, `treeHashExcept` equals the plain tree hash.

7. **parent-hash-valid (§7.9.2), top-down.** For each non-blank parent `P` with children `C` and `S` (in some orientation), `D`'s parent hash is valid w.r.t. `P` iff:
   - `D` is in `resolution(C)`, and `D.parent_hash == Hash(ParentHashInput from P with sibling S)`, and
   - the intersection of `P.unmerged_leaves` with the subtree under `C` equals `resolution(C)` with `D` removed (as node-index sets `{2*L}`).
   A non-blank parent is valid iff **exactly one** orientation `(C,S)` yields such a `D`. (For clean trees with no unmerged leaves this reduces to: `resolution(C) == [D]` and `D.parent_hash` matches.) The leaf-side stored parent hash lives in `LeafNode.parent_hash` only when `leaf_node_source == commit`; leaves of other sources have no parent hash and never match.

8. **Leaf validation we implement here (§7.3).** Signature verify per leaf (using its own `leaf_node_source` to build the TBS, with `group_id` context for update/commit), and uniqueness of `signature_key` and `encryption_key` across all leaves. (Lifetime/required_capabilities/credential-type-support checks are out of scope for the static tree KAT and deferred.)

9. **`tree-validation.json` schema** (confirmed against the live vector file). Top-level JSON **array**; each element:
   | key | JSON type | meaning |
   |---|---|---|
   | `cipher_suite` | integer | suite id (1, 2, …) |
   | `group_id` | hex string | context for update/commit leaf signatures |
   | `tree` | hex string | TLS-serialized `optional<Node><V>` ratchet tree |
   | `tree_hashes` | array of hex strings | `tree_hashes[i]` = tree hash of node index `i` |
   | `resolutions` | array of arrays of int | `resolutions[i]` = node indices in resolution of node `i` |
   The arrays are indexed by **node index** and have length `NodeWidth(leafCount)` (i.e. the full extended width). Verification: parse `tree`; for every `i` check `Resolution(i) == resolutions[i]` and `TreeHash(i) == tree_hashes[i]`; verify all parent hashes "as when joining"; verify all leaf signatures using `group_id` as context.

---

## File Structure

| File | Change | Responsibility |
|---|---|---|
| `mls/tree/credential.go` | Create | `CredentialType`, `Certificate`, `Credential` + marshal/decode + wrappers. |
| `mls/tree/credential_test.go` | Create | `package tree` round-trip tests (basic + x509). |
| `mls/tree/leaf.go` | Create | `ProtocolVersion`, `ExtensionType`, `ProposalType`, `Capabilities`, `Lifetime`, `Extension`, `LeafNodeSource`, `LeafNode`, `LeafNodeTBS`, signature verify. |
| `mls/tree/leaf_test.go` | Create | `package tree` round-trip + sign/verify tests. |
| `mls/tree/parent.go` | Create | `ParentNode` + marshal/decode + wrappers. |
| `mls/tree/parent_test.go` | Create | `package tree` round-trip tests. |
| `mls/tree/node.go` | Create | `NodeType`, `Node`, `RatchetTree`, parse/marshal, extend-to-full. |
| `mls/tree/node_test.go` | Create | `package tree` round-trip + extend/truncate tests. |
| `mls/tree/treesync.go` | Create | `Resolution`, `TreeHash`/`treeHashExcept`/`RootTreeHash`. |
| `mls/tree/treesync_test.go` | Create | `package tree` resolution + tree-hash unit tests. |
| `mls/tree/validation.go` | Create | parent-hash compute + `VerifyParentHashes` + `VerifyLeafSignatures`. |
| `mls/tree/validation_test.go` | Create | `package tree` parent-hash/sig unit tests. |
| `mls/tree/treevalidation_kat_test.go` | Create | `package tree_test` — `tree-validation.json` KAT (authoritative gate). |
| `mls/testdata/tree-validation.json` | Vendor (curl) | Official KAT vectors. |

> Unit test files are `package tree` (internal) so they can exercise the unexported `marshal`/`decodeX`/`tbs`/`treeHashExcept` helpers. The KAT file is `package tree_test` (external), alongside the existing `kat_test.go`. Go allows both packages in one directory.

---

## Task 1: Credential

**Files:** Create `mls/tree/credential.go`, `mls/tree/credential_test.go`.

- [ ] **Step 1: Write the failing test.** Create `mls/tree/credential_test.go`:

```go
package tree

import (
	"bytes"
	"testing"
)

func TestCredentialBasicRoundTrip(t *testing.T) {
	in := Credential{CredentialType: CredentialTypeBasic, Identity: []byte("alice@example.com")}
	enc, err := in.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	var out Credential
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if out.CredentialType != CredentialTypeBasic || !bytes.Equal(out.Identity, in.Identity) {
		t.Fatalf("round-trip mismatch: %+v vs %+v", out, in)
	}
}

func TestCredentialX509RoundTrip(t *testing.T) {
	in := Credential{
		CredentialType: CredentialTypeX509,
		Certificates:   []Certificate{{CertData: []byte("der0")}, {CertData: []byte("der1")}},
	}
	enc, err := in.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	var out Credential
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if out.CredentialType != CredentialTypeX509 || len(out.Certificates) != 2 ||
		!bytes.Equal(out.Certificates[0].CertData, []byte("der0")) ||
		!bytes.Equal(out.Certificates[1].CertData, []byte("der1")) {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestCredentialRejectsTrailingBytes(t *testing.T) {
	in := Credential{CredentialType: CredentialTypeBasic, Identity: []byte("x")}
	enc, _ := in.MarshalMLS()
	var out Credential
	if err := out.UnmarshalMLS(append(enc, 0x00)); err == nil {
		t.Fatal("expected trailing-byte error")
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/tree/` → FAIL (`undefined: Credential`).

- [ ] **Step 3: Implement `mls/tree/credential.go`:**

```go
package tree

import (
	"fmt"

	"github.com/trevex/mls-go/mls/syntax"
)

// CredentialType is the 2-byte MLS credential type (RFC 9420 §5.3).
type CredentialType uint16

const (
	CredentialTypeBasic CredentialType = 1
	CredentialTypeX509  CredentialType = 2
)

// Certificate wraps a single DER-encoded X.509 certificate (RFC 9420 §5.3).
type Certificate struct {
	CertData []byte // opaque cert_data<V>
}

// Credential authenticates a member's identity and signing key (RFC 9420 §5.3).
// Exactly one of Identity / Certificates is populated, per CredentialType.
type Credential struct {
	CredentialType CredentialType
	Identity       []byte        // basic: opaque identity<V>
	Certificates   []Certificate // x509: Certificate certificates<V>
}

func (c Credential) marshal(b *syntax.Builder) error {
	b.WriteUint16(uint16(c.CredentialType))
	switch c.CredentialType {
	case CredentialTypeBasic:
		return b.WriteOpaqueV(c.Identity)
	case CredentialTypeX509:
		return syntax.WriteVectorV(b, c.Certificates, func(b *syntax.Builder, cert Certificate) error {
			return b.WriteOpaqueV(cert.CertData)
		})
	default:
		return fmt.Errorf("tree: unsupported credential type %d", c.CredentialType)
	}
}

func decodeCredential(c *syntax.Cursor) (Credential, error) {
	var cred Credential
	ct, err := c.ReadUint16()
	if err != nil {
		return cred, err
	}
	cred.CredentialType = CredentialType(ct)
	switch cred.CredentialType {
	case CredentialTypeBasic:
		if cred.Identity, err = c.ReadOpaqueV(); err != nil {
			return cred, err
		}
	case CredentialTypeX509:
		cred.Certificates, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (Certificate, error) {
			data, err := c.ReadOpaqueV()
			return Certificate{CertData: data}, err
		})
		if err != nil {
			return cred, err
		}
	default:
		return cred, fmt.Errorf("tree: unsupported credential type %d", cred.CredentialType)
	}
	return cred, nil
}

// MarshalMLS encodes the Credential to its MLS wire form.
func (c Credential) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := c.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a Credential, rejecting trailing bytes.
func (c *Credential) UnmarshalMLS(data []byte) error {
	cur := syntax.NewCursor(data)
	v, err := decodeCredential(cur)
	if err != nil {
		return err
	}
	if !cur.Empty() {
		return fmt.Errorf("tree: trailing bytes after Credential")
	}
	*c = v
	return nil
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/tree/` → PASS. Then `nix develop -c go vet ./mls/...` and `nix develop -c gofmt -l mls/` clean.

- [ ] **Step 5: Commit.**

```bash
git add mls/tree/credential.go mls/tree/credential_test.go
git commit -m "feat(tree): Credential (basic/x509) marshal/unmarshal"
```

---

## Task 2: LeafNode and its sub-structures

**Files:** Create `mls/tree/leaf.go`, `mls/tree/leaf_test.go`.

RFC 9420 §7.2 verbatim:

```
enum { reserved(0), key_package(1), update(2), commit(3), (255) } LeafNodeSource;
struct { ProtocolVersion versions<V>; CipherSuite cipher_suites<V>; ExtensionType extensions<V>;
         ProposalType proposals<V>; CredentialType credentials<V>; } Capabilities;
struct { uint64 not_before; uint64 not_after; } Lifetime;
struct { ExtensionType extension_type; opaque extension_data<V>; } Extension;
struct {
  HPKEPublicKey encryption_key; SignaturePublicKey signature_key;
  Credential credential; Capabilities capabilities;
  LeafNodeSource leaf_node_source;
  select (LeafNode.leaf_node_source) {
    case key_package: Lifetime lifetime;
    case update:      struct{};
    case commit:      opaque parent_hash<V>;
  };
  Extension extensions<V>;
  opaque signature<V>;   /* SignWithLabel(., "LeafNodeTBS", LeafNodeTBS) */
} LeafNode;
```

`LeafNodeTBS` is identical down through `extensions<V>`, then for `update`/`commit` appends `opaque group_id<V>` and `uint32 leaf_index` (key_package appends nothing).

- [ ] **Step 1: Write the failing test.** Create `mls/tree/leaf_test.go`:

```go
package tree

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
)

func sampleCapabilities() Capabilities {
	return Capabilities{
		Versions:     []ProtocolVersion{ProtocolVersionMLS10},
		CipherSuites: []cipher.CipherSuite{cipher.X25519_AES128GCM_SHA256_Ed25519},
		Extensions:   []ExtensionType{},
		Proposals:    []ProposalType{},
		Credentials:  []CredentialType{CredentialTypeBasic},
	}
}

func TestLeafNodeKeyPackageRoundTrip(t *testing.T) {
	in := LeafNode{
		EncryptionKey:  []byte("enc-pub"),
		SignatureKey:   []byte("sig-pub"),
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("a")},
		Capabilities:   sampleCapabilities(),
		LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime:       &Lifetime{NotBefore: 1, NotAfter: 2},
		Extensions:     []Extension{{ExtensionType: 5, ExtensionData: []byte("x")}},
		Signature:      []byte("sig"),
	}
	enc, err := in.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	var out LeafNode
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if out.LeafNodeSource != LeafNodeSourceKeyPackage || out.Lifetime == nil ||
		out.Lifetime.NotAfter != 2 || !bytes.Equal(out.EncryptionKey, in.EncryptionKey) ||
		len(out.Extensions) != 1 || !bytes.Equal(out.Signature, in.Signature) {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestLeafNodeCommitRoundTrip(t *testing.T) {
	in := LeafNode{
		EncryptionKey:  []byte("e"),
		SignatureKey:   []byte("s"),
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("a")},
		Capabilities:   sampleCapabilities(),
		LeafNodeSource: LeafNodeSourceCommit,
		ParentHash:     []byte("ph"),
		Extensions:     []Extension{},
		Signature:      []byte("sig"),
	}
	enc, _ := in.MarshalMLS()
	var out LeafNode
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if out.LeafNodeSource != LeafNodeSourceCommit || !bytes.Equal(out.ParentHash, []byte("ph")) {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestLeafNodeSignVerify(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	pub, priv, _ := ed25519.GenerateKey(nil)
	groupID := []byte("group")
	leafIndex := uint32(3)

	leaf := LeafNode{
		EncryptionKey:  []byte("e"),
		SignatureKey:   []byte(pub),
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte("a")},
		Capabilities:   sampleCapabilities(),
		LeafNodeSource: LeafNodeSourceCommit,
		ParentHash:     []byte("ph"),
		Extensions:     []Extension{},
	}
	tbs, err := leaf.tbs(groupID, leafIndex)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := suite.SignWithLabel(priv, "LeafNodeTBS", tbs)
	if err != nil {
		t.Fatal(err)
	}
	leaf.Signature = sig

	ok, err := leaf.verifySignature(suite, groupID, leafIndex)
	if err != nil || !ok {
		t.Fatalf("verify failed: ok=%v err=%v", ok, err)
	}
	// Wrong group context must fail.
	if ok, _ := leaf.verifySignature(suite, []byte("other"), leafIndex); ok {
		t.Fatal("verify should fail with wrong group_id")
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/tree/` → FAIL (`undefined: LeafNode`).

- [ ] **Step 3: Implement `mls/tree/leaf.go`:**

```go
package tree

import (
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/syntax"
)

// ProtocolVersion is the 2-byte MLS protocol version (RFC 9420 §6).
type ProtocolVersion uint16

// ProtocolVersionMLS10 is mls10 (RFC 9420 §6).
const ProtocolVersionMLS10 ProtocolVersion = 1

// ExtensionType is the 2-byte MLS extension type (RFC 9420 §7.2).
type ExtensionType uint16

// ProposalType is the 2-byte MLS proposal type (RFC 9420 §12.1).
type ProposalType uint16

// LeafNodeSource indicates how a LeafNode entered the tree (RFC 9420 §7.2).
type LeafNodeSource uint8

const (
	LeafNodeSourceReserved   LeafNodeSource = 0
	LeafNodeSourceKeyPackage LeafNodeSource = 1
	LeafNodeSourceUpdate     LeafNodeSource = 2
	LeafNodeSourceCommit     LeafNodeSource = 3
)

// Capabilities advertises the features a client supports (RFC 9420 §7.2).
type Capabilities struct {
	Versions     []ProtocolVersion
	CipherSuites []cipher.CipherSuite
	Extensions   []ExtensionType
	Proposals    []ProposalType
	Credentials  []CredentialType
}

func (c Capabilities) marshal(b *syntax.Builder) error {
	if err := syntax.WriteVectorV(b, c.Versions, func(b *syntax.Builder, v ProtocolVersion) error {
		b.WriteUint16(uint16(v))
		return nil
	}); err != nil {
		return err
	}
	if err := syntax.WriteVectorV(b, c.CipherSuites, func(b *syntax.Builder, v cipher.CipherSuite) error {
		b.WriteUint16(uint16(v))
		return nil
	}); err != nil {
		return err
	}
	if err := syntax.WriteVectorV(b, c.Extensions, func(b *syntax.Builder, v ExtensionType) error {
		b.WriteUint16(uint16(v))
		return nil
	}); err != nil {
		return err
	}
	if err := syntax.WriteVectorV(b, c.Proposals, func(b *syntax.Builder, v ProposalType) error {
		b.WriteUint16(uint16(v))
		return nil
	}); err != nil {
		return err
	}
	return syntax.WriteVectorV(b, c.Credentials, func(b *syntax.Builder, v CredentialType) error {
		b.WriteUint16(uint16(v))
		return nil
	})
}

func decodeCapabilities(c *syntax.Cursor) (Capabilities, error) {
	var cap Capabilities
	var err error
	if cap.Versions, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (ProtocolVersion, error) {
		v, err := c.ReadUint16()
		return ProtocolVersion(v), err
	}); err != nil {
		return cap, err
	}
	if cap.CipherSuites, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (cipher.CipherSuite, error) {
		v, err := c.ReadUint16()
		return cipher.CipherSuite(v), err
	}); err != nil {
		return cap, err
	}
	if cap.Extensions, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (ExtensionType, error) {
		v, err := c.ReadUint16()
		return ExtensionType(v), err
	}); err != nil {
		return cap, err
	}
	if cap.Proposals, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (ProposalType, error) {
		v, err := c.ReadUint16()
		return ProposalType(v), err
	}); err != nil {
		return cap, err
	}
	if cap.Credentials, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (CredentialType, error) {
		v, err := c.ReadUint16()
		return CredentialType(v), err
	}); err != nil {
		return cap, err
	}
	return cap, nil
}

// Lifetime is the validity window for a key_package LeafNode (RFC 9420 §7.2).
type Lifetime struct {
	NotBefore uint64
	NotAfter  uint64
}

func (l Lifetime) marshal(b *syntax.Builder) {
	b.WriteUint64(l.NotBefore)
	b.WriteUint64(l.NotAfter)
}

func decodeLifetime(c *syntax.Cursor) (Lifetime, error) {
	var l Lifetime
	var err error
	if l.NotBefore, err = c.ReadUint64(); err != nil {
		return l, err
	}
	if l.NotAfter, err = c.ReadUint64(); err != nil {
		return l, err
	}
	return l, nil
}

// Extension is a single MLS extension (RFC 9420 §7.2).
type Extension struct {
	ExtensionType ExtensionType
	ExtensionData []byte
}

func (e Extension) marshal(b *syntax.Builder) error {
	b.WriteUint16(uint16(e.ExtensionType))
	return b.WriteOpaqueV(e.ExtensionData)
}

func decodeExtension(c *syntax.Cursor) (Extension, error) {
	et, err := c.ReadUint16()
	if err != nil {
		return Extension{}, err
	}
	data, err := c.ReadOpaqueV()
	if err != nil {
		return Extension{}, err
	}
	return Extension{ExtensionType: ExtensionType(et), ExtensionData: data}, nil
}

// LeafNode describes a member's appearance in the ratchet tree (RFC 9420 §7.2).
type LeafNode struct {
	EncryptionKey  []byte // HPKEPublicKey opaque<V>
	SignatureKey   []byte // SignaturePublicKey opaque<V>
	Credential     Credential
	Capabilities   Capabilities
	LeafNodeSource LeafNodeSource
	Lifetime       *Lifetime // present iff source==key_package
	ParentHash     []byte    // present iff source==commit
	Extensions     []Extension
	Signature      []byte // opaque<V>
}

// marshalContents writes the fields above the signature — the body shared by
// LeafNode and the leading part of LeafNodeTBS (RFC 9420 §7.2).
func (l LeafNode) marshalContents(b *syntax.Builder) error {
	if err := b.WriteOpaqueV(l.EncryptionKey); err != nil {
		return err
	}
	if err := b.WriteOpaqueV(l.SignatureKey); err != nil {
		return err
	}
	if err := l.Credential.marshal(b); err != nil {
		return err
	}
	if err := l.Capabilities.marshal(b); err != nil {
		return err
	}
	b.WriteUint8(uint8(l.LeafNodeSource))
	switch l.LeafNodeSource {
	case LeafNodeSourceKeyPackage:
		if l.Lifetime == nil {
			return fmt.Errorf("tree: key_package leaf node missing lifetime")
		}
		l.Lifetime.marshal(b)
	case LeafNodeSourceUpdate:
		// empty struct{}
	case LeafNodeSourceCommit:
		if err := b.WriteOpaqueV(l.ParentHash); err != nil {
			return err
		}
	default:
		return fmt.Errorf("tree: invalid leaf_node_source %d", l.LeafNodeSource)
	}
	return syntax.WriteVectorV(b, l.Extensions, func(b *syntax.Builder, e Extension) error {
		return e.marshal(b)
	})
}

func (l LeafNode) marshal(b *syntax.Builder) error {
	if err := l.marshalContents(b); err != nil {
		return err
	}
	return b.WriteOpaqueV(l.Signature)
}

func decodeLeafNode(c *syntax.Cursor) (LeafNode, error) {
	var l LeafNode
	var err error
	if l.EncryptionKey, err = c.ReadOpaqueV(); err != nil {
		return l, err
	}
	if l.SignatureKey, err = c.ReadOpaqueV(); err != nil {
		return l, err
	}
	if l.Credential, err = decodeCredential(c); err != nil {
		return l, err
	}
	if l.Capabilities, err = decodeCapabilities(c); err != nil {
		return l, err
	}
	src, err := c.ReadUint8()
	if err != nil {
		return l, err
	}
	l.LeafNodeSource = LeafNodeSource(src)
	switch l.LeafNodeSource {
	case LeafNodeSourceKeyPackage:
		lt, err := decodeLifetime(c)
		if err != nil {
			return l, err
		}
		l.Lifetime = &lt
	case LeafNodeSourceUpdate:
		// empty struct{}
	case LeafNodeSourceCommit:
		if l.ParentHash, err = c.ReadOpaqueV(); err != nil {
			return l, err
		}
	default:
		return l, fmt.Errorf("tree: invalid leaf_node_source %d", l.LeafNodeSource)
	}
	if l.Extensions, err = syntax.ReadVectorV(c, decodeExtension); err != nil {
		return l, err
	}
	if l.Signature, err = c.ReadOpaqueV(); err != nil {
		return l, err
	}
	return l, nil
}

// tbs builds the LeafNodeTBS bytes for signing/verification (RFC 9420 §7.2/§7.3).
// groupID and leafIndex are appended only for update/commit sources.
func (l LeafNode) tbs(groupID []byte, leafIndex uint32) ([]byte, error) {
	b := syntax.NewBuilder()
	if err := l.marshalContents(b); err != nil {
		return nil, err
	}
	switch l.LeafNodeSource {
	case LeafNodeSourceUpdate, LeafNodeSourceCommit:
		if err := b.WriteOpaqueV(groupID); err != nil {
			return nil, err
		}
		b.WriteUint32(leafIndex)
	}
	return b.Bytes(), nil
}

// verifySignature checks the leaf's signature under label "LeafNodeTBS".
func (l LeafNode) verifySignature(suite cipher.Suite, groupID []byte, leafIndex uint32) (bool, error) {
	tbs, err := l.tbs(groupID, leafIndex)
	if err != nil {
		return false, err
	}
	return suite.VerifyWithLabel(l.SignatureKey, "LeafNodeTBS", tbs, l.Signature), nil
}

// MarshalMLS encodes the LeafNode to its MLS wire form.
func (l LeafNode) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := l.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a LeafNode, rejecting trailing bytes.
func (l *LeafNode) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeLeafNode(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("tree: trailing bytes after LeafNode")
	}
	*l = v
	return nil
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/tree/` → PASS. `nix develop -c go vet ./mls/...` + `nix develop -c gofmt -l mls/` clean.

- [ ] **Step 5: Commit.**

```bash
git add mls/tree/leaf.go mls/tree/leaf_test.go
git commit -m "feat(tree): LeafNode, Capabilities, Lifetime, Extension + LeafNodeTBS sign/verify"
```

---

## Task 3: ParentNode

**Files:** Create `mls/tree/parent.go`, `mls/tree/parent_test.go`.

RFC 9420 §7.1 verbatim:
```
struct { HPKEPublicKey encryption_key; opaque parent_hash<V>; uint32 unmerged_leaves<V>; } ParentNode;
```
`unmerged_leaves` MUST be sorted increasing.

- [ ] **Step 1: Write the failing test.** Create `mls/tree/parent_test.go`:

```go
package tree

import (
	"bytes"
	"testing"
)

func TestParentNodeRoundTrip(t *testing.T) {
	in := ParentNode{
		EncryptionKey:  []byte("enc"),
		ParentHash:     []byte("ph"),
		UnmergedLeaves: []uint32{1, 4, 9},
	}
	enc, err := in.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	var out ParentNode
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.EncryptionKey, in.EncryptionKey) || !bytes.Equal(out.ParentHash, in.ParentHash) ||
		len(out.UnmergedLeaves) != 3 || out.UnmergedLeaves[2] != 9 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}

func TestParentNodeEmptyUnmerged(t *testing.T) {
	in := ParentNode{EncryptionKey: []byte("e"), ParentHash: nil, UnmergedLeaves: nil}
	enc, _ := in.MarshalMLS()
	var out ParentNode
	if err := out.UnmarshalMLS(enc); err != nil {
		t.Fatal(err)
	}
	if len(out.UnmergedLeaves) != 0 || len(out.ParentHash) != 0 {
		t.Fatalf("round-trip mismatch: %+v", out)
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/tree/` → FAIL (`undefined: ParentNode`).

- [ ] **Step 3: Implement `mls/tree/parent.go`:**

```go
package tree

import (
	"fmt"

	"github.com/trevex/mls-go/mls/syntax"
)

// ParentNode is an interior ratchet-tree node (RFC 9420 §7.1).
type ParentNode struct {
	EncryptionKey  []byte   // HPKEPublicKey opaque<V>
	ParentHash     []byte   // opaque<V>
	UnmergedLeaves []uint32 // uint32 unmerged_leaves<V>, sorted increasing
}

func (p ParentNode) marshal(b *syntax.Builder) error {
	if err := b.WriteOpaqueV(p.EncryptionKey); err != nil {
		return err
	}
	if err := b.WriteOpaqueV(p.ParentHash); err != nil {
		return err
	}
	return syntax.WriteVectorV(b, p.UnmergedLeaves, func(b *syntax.Builder, v uint32) error {
		b.WriteUint32(v)
		return nil
	})
}

func decodeParentNode(c *syntax.Cursor) (ParentNode, error) {
	var p ParentNode
	var err error
	if p.EncryptionKey, err = c.ReadOpaqueV(); err != nil {
		return p, err
	}
	if p.ParentHash, err = c.ReadOpaqueV(); err != nil {
		return p, err
	}
	if p.UnmergedLeaves, err = syntax.ReadVectorV(c, func(c *syntax.Cursor) (uint32, error) {
		return c.ReadUint32()
	}); err != nil {
		return p, err
	}
	return p, nil
}

// MarshalMLS encodes the ParentNode to its MLS wire form.
func (p ParentNode) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := p.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// UnmarshalMLS decodes a ParentNode, rejecting trailing bytes.
func (p *ParentNode) UnmarshalMLS(data []byte) error {
	c := syntax.NewCursor(data)
	v, err := decodeParentNode(c)
	if err != nil {
		return err
	}
	if !c.Empty() {
		return fmt.Errorf("tree: trailing bytes after ParentNode")
	}
	*p = v
	return nil
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/tree/` → PASS. Vet + gofmt clean.

- [ ] **Step 5: Commit.**

```bash
git add mls/tree/parent.go mls/tree/parent_test.go
git commit -m "feat(tree): ParentNode marshal/unmarshal"
```

---

## Task 4: Node and RatchetTree (parse / serialize / extend)

**Files:** Create `mls/tree/node.go`, `mls/tree/node_test.go`.

RFC 9420 §12.4.3.1 verbatim:
```
struct { NodeType node_type;
  select (Node.node_type) { case leaf: LeafNode leaf_node; case parent: ParentNode parent_node; };
} Node;
optional<Node> ratchet_tree<V>;
```
The sender MUST NOT include blank nodes after the last non-blank node; the receiver MUST check the last node is non-blank and extend to width `2^(d+1) - 1`.

- [ ] **Step 1: Write the failing test.** Create `mls/tree/node_test.go`:

```go
package tree

import (
	"bytes"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/syntax"
)

func testLeaf(id byte) *LeafNode {
	return &LeafNode{
		EncryptionKey:  []byte{id, 'e'},
		SignatureKey:   []byte{id, 's'},
		Credential:     Credential{CredentialType: CredentialTypeBasic, Identity: []byte{id}},
		Capabilities:   sampleCapabilities(),
		LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime:       &Lifetime{NotBefore: 0, NotAfter: 1},
		Extensions:     []Extension{},
		Signature:      []byte{id, 'g'},
	}
}

func TestRatchetTreeRoundTripAndExtend(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	// Two leaves, one parent => compact width 3. Serialize with a trailing
	// blank that MUST be dropped, then reparse.
	tr := &RatchetTree{
		suite: suite,
		nodes: []*Node{
			{Leaf: testLeaf('a')},
			{Parent: &ParentNode{EncryptionKey: []byte("p"), UnmergedLeaves: []uint32{1}}},
			{Leaf: testLeaf('b')},
		},
	}
	enc, err := tr.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseRatchetTree(suite, enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.Width() != 3 {
		t.Fatalf("width=%d want 3", got.Width())
	}
	re, _ := got.MarshalMLS()
	if !bytes.Equal(re, enc) {
		t.Fatalf("re-serialize mismatch")
	}
}

func TestParseRejectsTrailingBlank(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	// optional<Node><V> body: [present + leaf-node][absent]. The trailing
	// absent node makes this malformed per RFC 9420 §12.4.3.1. Build the body
	// with the real codec so the varint length prefix is correct for any size.
	inner := syntax.NewBuilder()
	inner.WriteUint8(0x01) // optional present
	if err := (Node{Leaf: testLeaf('a')}).marshal(inner); err != nil {
		t.Fatal(err)
	}
	inner.WriteUint8(0x00) // optional absent (trailing blank)
	outer := syntax.NewBuilder()
	if err := outer.WriteOpaqueV(inner.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRatchetTree(suite, outer.Bytes()); err == nil {
		t.Fatal("expected error for trailing blank node")
	}
}

func TestFullWidth(t *testing.T) {
	cases := map[uint32]uint32{1: 1, 2: 3, 3: 3, 4: 7, 5: 7, 7: 7, 8: 15, 11: 15}
	for in, want := range cases {
		if got := fullWidth(in); got != want {
			t.Fatalf("fullWidth(%d)=%d want %d", in, got, want)
		}
	}
}
```

> Note `Node` needs its own `MarshalMLS` for the test; include it in the implementation below.

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/tree/` → FAIL (`undefined: RatchetTree`).

- [ ] **Step 3: Implement `mls/tree/node.go`:**

```go
package tree

import (
	"fmt"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/syntax"
)

// NodeType discriminates a populated ratchet-tree node (RFC 9420 §7.8/§12.4.3.1).
type NodeType uint8

const (
	NodeTypeReserved NodeType = 0
	NodeTypeLeaf     NodeType = 1
	NodeTypeParent   NodeType = 2
)

// Node is a populated ratchet-tree node. Exactly one of Leaf / Parent is set.
type Node struct {
	Leaf   *LeafNode
	Parent *ParentNode
}

func (n Node) marshal(b *syntax.Builder) error {
	switch {
	case n.Leaf != nil:
		b.WriteUint8(uint8(NodeTypeLeaf))
		return n.Leaf.marshal(b)
	case n.Parent != nil:
		b.WriteUint8(uint8(NodeTypeParent))
		return n.Parent.marshal(b)
	default:
		return fmt.Errorf("tree: empty Node")
	}
}

func decodeNode(c *syntax.Cursor) (Node, error) {
	var n Node
	t, err := c.ReadUint8()
	if err != nil {
		return n, err
	}
	switch NodeType(t) {
	case NodeTypeLeaf:
		l, err := decodeLeafNode(c)
		if err != nil {
			return n, err
		}
		n.Leaf = &l
	case NodeTypeParent:
		p, err := decodeParentNode(c)
		if err != nil {
			return n, err
		}
		n.Parent = &p
	default:
		return n, fmt.Errorf("tree: invalid node type %d", t)
	}
	return n, nil
}

// MarshalMLS encodes a single populated Node (RFC 9420 §12.4.3.1).
func (n Node) MarshalMLS() ([]byte, error) {
	b := syntax.NewBuilder()
	if err := n.marshal(b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// RatchetTree is the public ratchet tree for an epoch (RFC 9420 §7). nodes has
// length NodeWidth(leafCount); a nil entry is a blank node.
type RatchetTree struct {
	suite cipher.Suite
	nodes []*Node
}

// fullWidth returns the smallest complete-tree node width (2^k - 1) >= n.
func fullWidth(n uint32) uint32 {
	w := uint32(1)
	for w < n {
		w = 2*w + 1
	}
	return w
}

// ParseRatchetTree decodes the ratchet_tree extension wire form (the KAT
// "tree" field): optional<Node><V>, extended to full width (RFC 9420 §12.4.3.1).
func ParseRatchetTree(suite cipher.Suite, data []byte) (*RatchetTree, error) {
	c := syntax.NewCursor(data)
	nodes, err := syntax.ReadVectorV(c, func(c *syntax.Cursor) (*Node, error) {
		return syntax.ReadOptional(c, decodeNode)
	})
	if err != nil {
		return nil, err
	}
	if !c.Empty() {
		return nil, fmt.Errorf("tree: trailing bytes after ratchet_tree")
	}
	if len(nodes) == 0 {
		return nil, fmt.Errorf("tree: empty ratchet_tree")
	}
	if nodes[len(nodes)-1] == nil {
		return nil, fmt.Errorf("tree: ratchet_tree must not end with a blank node")
	}
	for uint32(len(nodes)) < fullWidth(uint32(len(nodes))) {
		nodes = append(nodes, nil)
	}
	return &RatchetTree{suite: suite, nodes: nodes}, nil
}

// MarshalMLS serializes the tree to ratchet_tree wire form, truncating trailing
// blanks (RFC 9420 §12.4.3.1).
func (t *RatchetTree) MarshalMLS() ([]byte, error) {
	end := len(t.nodes)
	for end > 0 && t.nodes[end-1] == nil {
		end--
	}
	nodes := t.nodes[:end]
	b := syntax.NewBuilder()
	if err := syntax.WriteVectorV(b, nodes, func(b *syntax.Builder, n *Node) error {
		return syntax.WriteOptional(b, n, func(b *syntax.Builder, nn Node) error {
			return nn.marshal(b)
		})
	}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Width returns the number of array slots (NodeWidth of the tree).
func (t *RatchetTree) Width() uint32 { return uint32(len(t.nodes)) }

// leafCount returns the number of leaves: (width + 1) / 2.
func (t *RatchetTree) leafCount() uint32 { return (uint32(len(t.nodes)) + 1) / 2 }
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/tree/` → PASS. Vet + gofmt clean.

- [ ] **Step 5: Commit.**

```bash
git add mls/tree/node.go mls/tree/node_test.go
git commit -m "feat(tree): Node + RatchetTree parse/serialize with full-width extension"
```

---

## Task 5: Resolution

**Files:** Create `mls/tree/treesync.go`, `mls/tree/treesync_test.go`.

RFC 9420 §4.1.1: resolution of a node returns node indices. See Design note 4.

- [ ] **Step 1: Write the failing test.** Create `mls/tree/treesync_test.go`:

```go
package tree

import (
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
)

func eqU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Tree from RFC 9420 §4.1.1 Figure 10 (8 leaves, width 15). Node X = index 1
// (parent of leaves 0,1) is non-blank with unmerged leaf B (leaf index 1 ->
// node 2). Node Y = index 9 non-blank. Several blanks. We assert the documented
// resolutions: res(1)=[1,2], res(4)=[], res(12)=[], res(7)=[1,2,9,14].
func TestResolutionFigure10(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	blank := func(n int) []*Node { return make([]*Node, n) }
	nodes := blank(15)
	// Leaves present: A(0), B(2), D(6), E(8), F(10), H(14). Mark only what the
	// resolution depends on: X(1) and Y(9) non-blank parents; the rest blank.
	nodes[1] = &Node{Parent: &ParentNode{EncryptionKey: []byte("X"), UnmergedLeaves: []uint32{1}}} // unmerged leaf 1 -> node 2
	nodes[9] = &Node{Parent: &ParentNode{EncryptionKey: []byte("Y")}}
	nodes[14] = &Node{Leaf: testLeaf('H')}
	tr := &RatchetTree{suite: suite, nodes: nodes}

	if got := tr.Resolution(1); !eqU32(got, []uint32{1, 2}) {
		t.Fatalf("res(1)=%v want [1 2]", got)
	}
	if got := tr.Resolution(4); !eqU32(got, []uint32{}) {
		t.Fatalf("res(4)=%v want []", got)
	}
	if got := tr.Resolution(7); !eqU32(got, []uint32{1, 2, 9, 14}) {
		t.Fatalf("res(7)=%v want [1 2 9 14]", got)
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/tree/` → FAIL (`tr.Resolution undefined`).

- [ ] **Step 3: Implement resolution in `mls/tree/treesync.go`:**

```go
package tree

import "github.com/trevex/mls-go/mls/syntax"

// Resolution returns the resolution of node index i as a list of node indices
// (RFC 9420 §4.1.1).
func (t *RatchetTree) Resolution(i uint32) []uint32 {
	n := t.nodes[i]
	if n != nil {
		// Non-blank: the node itself, then its unmerged leaves as node indices.
		res := []uint32{i}
		if n.Parent != nil {
			for _, leaf := range n.Parent.UnmergedLeaves {
				res = append(res, 2*leaf)
			}
		}
		return res
	}
	// Blank node.
	left, ok := Left(i)
	if !ok {
		return []uint32{} // blank leaf
	}
	right, _ := Right(i, t.leafCount())
	res := append([]uint32{}, t.Resolution(left)...)
	return append(res, t.Resolution(right)...)
}
```

> The `syntax` import is unused for now; it is consumed by Task 6's tree-hash code added to this same file. If implementing strictly one task at a time, omit the import in Step 3 and add it in Task 6 Step 3 to keep the build clean.

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/tree/` → PASS. Vet + gofmt clean.

- [ ] **Step 5: Commit.**

```bash
git add mls/tree/treesync.go mls/tree/treesync_test.go
git commit -m "feat(tree): node resolution (RFC 9420 §4.1.1)"
```

---

## Task 6: Tree hash and original tree hash

**Files:** Edit `mls/tree/treesync.go`, `mls/tree/treesync_test.go`.

See Design notes 5 and 6 for the verbatim structs and the `treeHashExcept` design.

- [ ] **Step 1: Write the failing test.** Append to `mls/tree/treesync_test.go`:

```go
// A single-leaf tree (width 1). The root tree hash is the leaf tree hash:
// Hash( node_type=leaf(1) || leaf_index=0 || optional<LeafNode>=present || LeafNode ).
func TestTreeHashSingleLeaf(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	leaf := testLeaf('a')
	tr := &RatchetTree{suite: suite, nodes: []*Node{{Leaf: leaf}}}

	leafEnc, err := leaf.MarshalMLS()
	if err != nil {
		t.Fatal(err)
	}
	// Build the expected TreeHashInput by hand.
	var want []byte
	want = append(want, byte(NodeTypeLeaf))         // node_type
	want = append(want, 0, 0, 0, 0)                 // leaf_index = 0
	want = append(want, 0x01)                       // optional present
	want = append(want, leafEnc...)                 // LeafNode
	want = suite.Hash(want)

	got, err := tr.TreeHash(0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("tree hash mismatch\n got %x\nwant %x", got, want)
	}
}

// treeHashExcept with an empty excluded set must equal the plain tree hash.
func TestTreeHashExceptEmptyEqualsPlain(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	tr := &RatchetTree{suite: suite, nodes: []*Node{
		{Leaf: testLeaf('a')},
		{Parent: &ParentNode{EncryptionKey: []byte("p")}},
		{Leaf: testLeaf('b')},
	}}
	plain, err := tr.TreeHash(1)
	if err != nil {
		t.Fatal(err)
	}
	except, err := tr.treeHashExcept(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(except) {
		t.Fatal("treeHashExcept(nil) != TreeHash")
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/tree/` → FAIL (`tr.TreeHash undefined`).

- [ ] **Step 3: Implement in `mls/tree/treesync.go`** (ensure `import "github.com/trevex/mls-go/mls/syntax"` is present):

```go
// TreeHash returns the tree hash of the subtree rooted at node index i
// (RFC 9420 §7.8).
func (t *RatchetTree) TreeHash(i uint32) ([]byte, error) {
	return t.treeHashExcept(i, nil)
}

// RootTreeHash returns the tree hash of the whole tree (its root).
func (t *RatchetTree) RootTreeHash() ([]byte, error) {
	return t.TreeHash(Root(t.leafCount()))
}

// treeHashExcept computes the tree hash of the subtree rooted at i (RFC 9420
// §7.8). Every leaf whose index is in excluded is treated as blank, and every
// ParentNode.unmerged_leaves is filtered to drop entries in excluded — this is
// the "original tree hash" of §7.9. With excluded nil/empty it is the ordinary
// tree hash.
func (t *RatchetTree) treeHashExcept(i uint32, excluded map[uint32]bool) ([]byte, error) {
	b := syntax.NewBuilder()
	left, isParent := Left(i)
	if !isParent {
		// Leaf node.
		leafIndex := i / 2
		var leaf *LeafNode
		if n := t.nodes[i]; n != nil && n.Leaf != nil && !excluded[leafIndex] {
			leaf = n.Leaf
		}
		b.WriteUint8(uint8(NodeTypeLeaf))
		b.WriteUint32(leafIndex)
		if err := syntax.WriteOptional(b, leaf, func(b *syntax.Builder, l LeafNode) error {
			return l.marshal(b)
		}); err != nil {
			return nil, err
		}
		return t.suite.Hash(b.Bytes()), nil
	}
	// Parent node.
	right, _ := Right(i, t.leafCount())
	leftHash, err := t.treeHashExcept(left, excluded)
	if err != nil {
		return nil, err
	}
	rightHash, err := t.treeHashExcept(right, excluded)
	if err != nil {
		return nil, err
	}
	var parent *ParentNode
	if n := t.nodes[i]; n != nil && n.Parent != nil {
		p := *n.Parent
		if len(excluded) > 0 {
			p.UnmergedLeaves = filterLeaves(p.UnmergedLeaves, excluded)
		}
		parent = &p
	}
	b.WriteUint8(uint8(NodeTypeParent))
	if err := syntax.WriteOptional(b, parent, func(b *syntax.Builder, pn ParentNode) error {
		return pn.marshal(b)
	}); err != nil {
		return nil, err
	}
	if err := b.WriteOpaqueV(leftHash); err != nil {
		return nil, err
	}
	if err := b.WriteOpaqueV(rightHash); err != nil {
		return nil, err
	}
	return t.suite.Hash(b.Bytes()), nil
}

// filterLeaves returns leaves with every entry in excluded removed.
func filterLeaves(leaves []uint32, excluded map[uint32]bool) []uint32 {
	out := make([]uint32, 0, len(leaves))
	for _, l := range leaves {
		if !excluded[l] {
			out = append(out, l)
		}
	}
	return out
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/tree/` → PASS. Vet + gofmt clean.

- [ ] **Step 5: Commit.**

```bash
git add mls/tree/treesync.go mls/tree/treesync_test.go
git commit -m "feat(tree): tree hash + original tree hash (RFC 9420 §7.8/§7.9)"
```

---

## Task 7: Parent-hash verification and leaf-signature validation

**Files:** Create `mls/tree/validation.go`, `mls/tree/validation_test.go`.

See Design notes 6, 7, 8. `ParentHashInput = { encryption_key opaque<V>; parent_hash opaque<V>; original_sibling_tree_hash opaque<V> }`.

- [ ] **Step 1: Write the failing test.** Create `mls/tree/validation_test.go`:

```go
package tree

import (
	"crypto/ed25519"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
)

// Build a clean 2-leaf tree where the committer's leaf (index 0, node 0) and
// the parent (node 1) form a valid parent-hash chain, and both leaves are
// validly signed. This exercises VerifyParentHashes and VerifyLeafSignatures
// end-to-end without the KAT.
func TestVerifyParentHashesAndSignatures(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	groupID := []byte("g")

	// Parent node P at index 1, with no unmerged leaves and root parent_hash "".
	parent := &ParentNode{EncryptionKey: []byte("penc"), ParentHash: nil}

	// Sibling S of node 0 is node 2 (leaf 1). Committer leaf is node 0 (leaf 0),
	// child C of P on the committer's side; sibling S = node 2.
	// Committer leaf's parent_hash = Hash(ParentHashInput{P.enc, "", origSibTH}).
	tr := &RatchetTree{suite: suite, nodes: []*Node{nil, {Parent: parent}, nil}}

	// Build leaf 1 (the sibling subtree) first so its tree hash is fixed.
	pub1, priv1, _ := ed25519.GenerateKey(nil)
	leaf1 := &LeafNode{
		EncryptionKey: []byte("e1"), SignatureKey: []byte(pub1),
		Credential:   Credential{CredentialType: CredentialTypeBasic, Identity: []byte("1")},
		Capabilities: sampleCapabilities(), LeafNodeSource: LeafNodeSourceKeyPackage,
		Lifetime: &Lifetime{NotBefore: 0, NotAfter: 1}, Extensions: []Extension{},
	}
	tbs1, _ := leaf1.tbs(groupID, 1)
	leaf1.Signature, _ = suite.SignWithLabel(priv1, "LeafNodeTBS", tbs1)
	tr.nodes[2] = &Node{Leaf: leaf1}

	// Committer leaf 0, source=commit, parent_hash = parentHashOf(P=1, S=2).
	wantPH, err := tr.parentHashOf(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	pub0, priv0, _ := ed25519.GenerateKey(nil)
	leaf0 := &LeafNode{
		EncryptionKey: []byte("e0"), SignatureKey: []byte(pub0),
		Credential:   Credential{CredentialType: CredentialTypeBasic, Identity: []byte("0")},
		Capabilities: sampleCapabilities(), LeafNodeSource: LeafNodeSourceCommit,
		ParentHash: wantPH, Extensions: []Extension{},
	}
	tbs0, _ := leaf0.tbs(groupID, 0)
	leaf0.Signature, _ = suite.SignWithLabel(priv0, "LeafNodeTBS", tbs0)
	tr.nodes[0] = &Node{Leaf: leaf0}

	ok, err := tr.VerifyParentHashes()
	if err != nil || !ok {
		t.Fatalf("VerifyParentHashes ok=%v err=%v", ok, err)
	}
	if err := tr.VerifyLeafSignatures(groupID); err != nil {
		t.Fatalf("VerifyLeafSignatures: %v", err)
	}

	// Corrupt the committer's parent_hash -> verification must fail.
	bad := *tr
	badNodes := append([]*Node{}, tr.nodes...)
	badLeaf := *leaf0
	badLeaf.ParentHash = append([]byte{0xff}, wantPH...)
	badNodes[0] = &Node{Leaf: &badLeaf}
	bad.nodes = badNodes
	if ok, _ := bad.VerifyParentHashes(); ok {
		t.Fatal("expected parent-hash verification to fail after corruption")
	}
}

func TestVerifyLeafSignaturesRejectsDuplicateKeys(t *testing.T) {
	suite, _ := cipher.Lookup(cipher.X25519_AES128GCM_SHA256_Ed25519)
	groupID := []byte("g")
	pub, priv, _ := ed25519.GenerateKey(nil)
	mk := func(id byte) *Node {
		l := &LeafNode{
			EncryptionKey: []byte("same-enc"), SignatureKey: []byte(pub),
			Credential:   Credential{CredentialType: CredentialTypeBasic, Identity: []byte{id}},
			Capabilities: sampleCapabilities(), LeafNodeSource: LeafNodeSourceKeyPackage,
			Lifetime: &Lifetime{NotBefore: 0, NotAfter: 1}, Extensions: []Extension{},
		}
		tbs, _ := l.tbs(groupID, 0)
		l.Signature, _ = suite.SignWithLabel(priv, "LeafNodeTBS", tbs)
		return &Node{Leaf: l}
	}
	tr := &RatchetTree{suite: suite, nodes: []*Node{mk('a'), {Parent: &ParentNode{EncryptionKey: []byte("p")}}, mk('b')}}
	if err := tr.VerifyLeafSignatures(groupID); err == nil {
		t.Fatal("expected duplicate-key error")
	}
}
```

- [ ] **Step 2: Run to verify it fails.** `nix develop -c go test ./mls/tree/` → FAIL (`tr.parentHashOf undefined`).

- [ ] **Step 3: Implement `mls/tree/validation.go`:**

```go
package tree

import (
	"bytes"
	"fmt"

	"github.com/trevex/mls-go/mls/syntax"
)

// leafSet builds a set of leaf indices.
func leafSet(leaves []uint32) map[uint32]bool {
	m := make(map[uint32]bool, len(leaves))
	for _, l := range leaves {
		m[l] = true
	}
	return m
}

// parentHashOf computes the parent hash that a child of parent node pi should
// carry, given si is the copath sibling (RFC 9420 §7.9). The parent_hash field
// is read directly from P; original_sibling_tree_hash is the tree hash of S in
// the tree with P's unmerged leaves blanked.
func (t *RatchetTree) parentHashOf(pi, si uint32) ([]byte, error) {
	p := t.nodes[pi].Parent
	excluded := leafSet(p.UnmergedLeaves)
	origSibHash, err := t.treeHashExcept(si, excluded)
	if err != nil {
		return nil, err
	}
	b := syntax.NewBuilder()
	if err := b.WriteOpaqueV(p.EncryptionKey); err != nil {
		return nil, err
	}
	if err := b.WriteOpaqueV(p.ParentHash); err != nil {
		return nil, err
	}
	if err := b.WriteOpaqueV(origSibHash); err != nil {
		return nil, err
	}
	return t.suite.Hash(b.Bytes()), nil
}

// nodeParentHash returns the parent_hash stored in node i, and whether the node
// carries one (parent nodes always; leaf nodes only when source==commit).
func (t *RatchetTree) nodeParentHash(i uint32) ([]byte, bool) {
	n := t.nodes[i]
	if n == nil {
		return nil, false
	}
	if n.Leaf != nil {
		if n.Leaf.LeafNodeSource == LeafNodeSourceCommit {
			return n.Leaf.ParentHash, true
		}
		return nil, false
	}
	return n.Parent.ParentHash, true
}

// subtreeContains reports whether node is in the subtree rooted at root.
func subtreeContains(root, node uint32) bool {
	half := uint32(1)<<level(root) - 1
	return node >= root-half && node <= root+half
}

// hasParentHashMatch reports whether, treating ci as the direct-path child and
// si as the copath sibling of parent pi, some node D in resolution(ci) has a
// stored parent_hash equal to parentHashOf(pi, si) and satisfies the
// unmerged-leaves condition of RFC 9420 §7.9.2.
func (t *RatchetTree) hasParentHashMatch(pi, ci, si uint32) (bool, error) {
	want, err := t.parentHashOf(pi, si)
	if err != nil {
		return false, err
	}
	res := t.Resolution(ci)
	excluded := leafSet(t.nodes[pi].Parent.UnmergedLeaves)
	for _, d := range res {
		ph, ok := t.nodeParentHash(d)
		if !ok || !bytes.Equal(ph, want) {
			continue
		}
		// resolution(ci) with d removed must equal { 2*L : L in excluded, leaf
		// 2*L under subtree ci }.
		expected := make(map[uint32]bool)
		for l := range excluded {
			ni := 2 * l
			if subtreeContains(ci, ni) {
				expected[ni] = true
			}
		}
		actual := make(map[uint32]bool)
		for _, x := range res {
			if x != d {
				actual[x] = true
			}
		}
		if mapsEqual(actual, expected) {
			return true, nil
		}
	}
	return false, nil
}

func mapsEqual(a, b map[uint32]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// VerifyParentHashes checks that every non-blank parent node is parent-hash
// valid (RFC 9420 §7.9.2, top-down): exactly one orientation of its children
// must yield a matching descendant.
func (t *RatchetTree) VerifyParentHashes() (bool, error) {
	leaves := t.leafCount()
	for i := uint32(0); i < t.Width(); i++ {
		n := t.nodes[i]
		if n == nil || n.Parent == nil {
			continue
		}
		l, _ := Left(i)
		r, _ := Right(i, leaves)
		okL, err := t.hasParentHashMatch(i, l, r)
		if err != nil {
			return false, err
		}
		okR, err := t.hasParentHashMatch(i, r, l)
		if err != nil {
			return false, err
		}
		if okL == okR { // need exactly one orientation to match
			return false, nil
		}
	}
	return true, nil
}

// VerifyLeafSignatures verifies the signature on every non-blank leaf using
// groupID as context for update/commit leaves (RFC 9420 §7.3), and checks that
// signature_key and encryption_key are unique across all leaves.
func (t *RatchetTree) VerifyLeafSignatures(groupID []byte) error {
	sigKeys := make(map[string]bool)
	encKeys := make(map[string]bool)
	for i := uint32(0); i < t.Width(); i += 2 {
		n := t.nodes[i]
		if n == nil || n.Leaf == nil {
			continue
		}
		leafIndex := i / 2
		ok, err := n.Leaf.verifySignature(t.suite, groupID, leafIndex)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("tree: invalid signature on leaf %d", leafIndex)
		}
		sk := string(n.Leaf.SignatureKey)
		if sigKeys[sk] {
			return fmt.Errorf("tree: duplicate signature_key at leaf %d", leafIndex)
		}
		sigKeys[sk] = true
		ek := string(n.Leaf.EncryptionKey)
		if encKeys[ek] {
			return fmt.Errorf("tree: duplicate encryption_key at leaf %d", leafIndex)
		}
		encKeys[ek] = true
	}
	return nil
}
```

- [ ] **Step 4: Run to verify it passes.** `nix develop -c go test ./mls/tree/` → PASS. Vet + gofmt clean.

- [ ] **Step 5: Commit.**

```bash
git add mls/tree/validation.go mls/tree/validation_test.go
git commit -m "feat(tree): parent-hash verification + leaf signature/uniqueness validation"
```

---

## Task 8: `tree-validation.json` KAT (authoritative gate)

**Files:** Vendor `mls/testdata/tree-validation.json`, create `mls/tree/treevalidation_kat_test.go`.

This is the authoritative acceptance test. Iterate the implementation until it passes; **never weaken the test**.

- [ ] **Step 1: Vendor the official vectors.**

```bash
curl -fsSL -o mls/testdata/tree-validation.json \
  https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors/tree-validation.json
```

- [ ] **Step 2: Write the KAT harness.** Create `mls/tree/treevalidation_kat_test.go`:

```go
package tree_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/trevex/mls-go/mls/cipher"
	"github.com/trevex/mls-go/mls/internal/katutil"
	"github.com/trevex/mls-go/mls/tree"
)

type treeValidationCase struct {
	CipherSuite uint16             `json:"cipher_suite"`
	GroupID     katutil.HexBytes   `json:"group_id"`
	Tree        katutil.HexBytes   `json:"tree"`
	Resolutions [][]uint32         `json:"resolutions"`
	TreeHashes  []katutil.HexBytes `json:"tree_hashes"`
}

func eqU32(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTreeValidationKAT(t *testing.T) {
	var cases []treeValidationCase
	katutil.Load(t, "tree-validation.json", &cases)
	if len(cases) == 0 {
		t.Fatal("no tree-validation vectors loaded")
	}
	for idx, c := range cases {
		c := c
		t.Run(fmt.Sprintf("case=%d/suite=%d", idx, c.CipherSuite), func(t *testing.T) {
			suite, ok := cipher.Lookup(cipher.CipherSuite(c.CipherSuite))
			if !ok {
				t.Skipf("unsupported cipher suite %d", c.CipherSuite)
			}
			rt, err := tree.ParseRatchetTree(suite, c.Tree)
			if err != nil {
				t.Fatalf("parse tree: %v", err)
			}
			if int(rt.Width()) != len(c.Resolutions) {
				t.Fatalf("width %d != len(resolutions) %d", rt.Width(), len(c.Resolutions))
			}
			if int(rt.Width()) != len(c.TreeHashes) {
				t.Fatalf("width %d != len(tree_hashes) %d", rt.Width(), len(c.TreeHashes))
			}
			for i := uint32(0); i < rt.Width(); i++ {
				if got := rt.Resolution(i); !eqU32(got, c.Resolutions[i]) {
					t.Fatalf("resolution[%d]=%v want %v", i, got, c.Resolutions[i])
				}
				got, err := rt.TreeHash(i)
				if err != nil {
					t.Fatalf("tree hash[%d]: %v", i, err)
				}
				if !bytes.Equal(got, c.TreeHashes[i]) {
					t.Fatalf("tree_hash[%d]=%x want %x", i, got, []byte(c.TreeHashes[i]))
				}
			}
			ok2, err := rt.VerifyParentHashes()
			if err != nil {
				t.Fatalf("verify parent hashes: %v", err)
			}
			if !ok2 {
				t.Fatal("parent hash verification failed")
			}
			if err := rt.VerifyLeafSignatures(c.GroupID); err != nil {
				t.Fatalf("leaf signatures: %v", err)
			}
		})
	}
}
```

- [ ] **Step 3: Run.** `nix develop -c go test ./mls/tree/ -run TestTreeValidationKAT -v`. Vectors for cipher suites 1 and 2 must PASS; suites we do not register (3–7) are skipped. If a sub-case fails:
  - Resolution mismatch → re-check Design note 4 (unmerged leaves as node indices `2*L`; ordering left-then-right).
  - Tree-hash mismatch → re-check Design note 5 byte layout (`node_type` u8; leaf: `uint32 leaf_index` + `optional<LeafNode>`; parent: `optional<ParentNode>` + `left_hash<V>` + `right_hash<V>`); confirm blank ⇒ optional absent.
  - Parent-hash failure → re-check Design notes 6/7: `ParentHashInput.parent_hash` is P's **stored** field; `original_sibling_tree_hash` uses `treeHashExcept` with `P.unmerged_leaves`.
  - Signature failure → confirm the TBS appends `group_id` + `leaf_index` **only** for update/commit, and label is exactly `"LeafNodeTBS"`.
  Fix the implementation, not the test.

- [ ] **Step 4: Full module + hygiene.** `nix develop -c go test ./...` PASS; `nix develop -c go vet ./mls/...` and `nix develop -c gofmt -l mls/` clean.

- [ ] **Step 5: Commit.**

```bash
git add mls/testdata/tree-validation.json mls/tree/treevalidation_kat_test.go
git commit -m "test(tree): tree-validation.json KAT (resolution, tree hash, parent hash, leaf sigs)"
```

---

## Definition of Done (Plan 4)

- [ ] `nix develop -c go test ./...` passes, including `TestTreeValidationKAT` for all registered cipher suites (1, 2); unregistered suites are skipped, not failed.
- [ ] `nix develop -c go vet ./mls/...` and `nix develop -c gofmt -l mls/` are clean.
- [ ] `Credential` (basic/x509), `LeafNode`, `ParentNode`, and `Node`/`RatchetTree` round-trip via `MarshalMLS`/`UnmarshalMLS`; top-level decoders reject trailing bytes; `ParseRatchetTree` rejects a trailing blank node and extends to full width; `MarshalMLS` truncates trailing blanks (re-serialization is byte-identical to the vector `tree`).
- [ ] `Resolution`, `TreeHash`/`RootTreeHash`, `VerifyParentHashes`, and `VerifyLeafSignatures` match the KAT for every node index.
- [ ] `go.mod` remains dependency-free (stdlib only).
- [ ] `tree-operations.json` is explicitly deferred to Plan 4b (see below); no half-built mutation code is committed.

## Deferred to Plan 4b (tree mutations / `tree-operations.json`)

`tree-operations.json` verifies applying an Add/Update/Remove `Proposal` to a serialized tree and comparing the re-serialized result and its tree hash. This requires the `Proposal` wire types (`Add`, `Update`, `Remove`) and the tree-mutation algorithms (§7.4 blank-direct-path, leaf insertion/extension, `unmerged_leaves` maintenance on Add, §7.6) that are not defined until later plans. Plan 4b will add: `RatchetTree.AddLeaf`, `UpdateLeaf`, `RemoveLeaf`, direct-path blanking, leftmost-empty-leaf placement with tree growth, and the `tree-operations.json` KAT, reusing all marshal/tree-hash machinery built here.

## Notes for the next plan (Plan 5 = key schedule + secret tree + transcript hashes)

- Plan 5 builds the RFC 9420 §8 key schedule (`GroupContext`, `Extract`/`Expand`, `joiner_secret`/`welcome_secret`/`epoch_secret` and the derived secrets), the §9 secret tree (per-leaf handshake/application ratchets keyed off the tree's node indices — reuse `mls/tree` math and `Suite.DeriveTreeSecret`), and the §5.2 / §8.1 transcript hashes (`confirmed_transcript_hash`, `interim_transcript_hash`).
- `GroupContext` carries `tree_hash` — use `RatchetTree.RootTreeHash` from this plan to populate it.
- The `cipher.Suite` already exposes `ExpandWithLabel`, `DeriveSecret`, `DeriveTreeSecret`, `MAC`, and `Hash`; no new crypto primitives should be required. Keep the stdlib-only constraint and the `nix develop -c go ...` invocation convention.
