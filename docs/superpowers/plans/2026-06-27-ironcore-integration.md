# IronCore Integration Layer — VNI↔Group, exporter→ESP-SA derivation, credential adapters + atomic pending-update fix (Plan 10 of 11) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. **Depends on Plan 9** (`2026-06-27-active-operations.md`) — the active `mls/group` engine (`NewGroup`, `NewKeyPackage`, `Commit`, `ProcessCommit`, `JoinFromWelcome`, `ProposeUpdate`/`ProposeAdd`/`ProposeRemove`, `ProtectApplication`/`UnprotectApplication`, `Exporter`, the `ports.go` interfaces) must be merged first. Every derivation, label, byte-encoding, and convergence claim in the **Design notes** below was **empirically validated during planning** with throwaway `package group_test` / `package ironcore_test` tests (3-member X-Wing groups; the atomic pending-update swap incl. the superseded-update case; byte-identical `K_group`/`SPI` across members; pairwise-distinct per-sender salts; SA rotation across an epoch change; x509-credential group formation; PKI chain verify + SPIFFE URI-SAN extraction). **The throwaways were deleted; the working tree was left clean (only this plan file is new).**

**Goal:** Build the **`ironcore/` integration layer** (design spec §3 / §10) — a new top-level package depending on `mls/...` — that turns the domain-agnostic MLS engine into a per-VNI key-agreement service for IronCore underlay encryption. Five deliverables: **(0)** a prerequisite **MLS-core correctness fix** in `mls/group` — replace the non-atomic `InstallPendingUpdateKey` with **automatic, atomic pending-update tracking** so a member whose `Update` is committed by a *different* member converges with no manual key install, and a member whose `Update` is *superseded* by a competing commit can still decrypt that commit with its old key; **(1)** **VNI↔Group** mapping (`GroupID(vni)` + inverse, `VNIGroup` wrapper); **(2)** the core **exporter→ESP-SA derivation** (`DeriveSAKeys`) — per-epoch `K_group` from the MLS exporter, an epoch-encoded `SPI`, and the **critical per-sender GCM nonce salt** that gives every sender a disjoint AES-256-GCM nonce space; **(3)** **`CredentialValidator` adapters** — `PKIValidator` (x509 chain against a trust bundle) and `SPIFFEValidator` (SVID URI-SAN trust-domain check) plus an `Authorizer` authz hook; **(4)** a **multi-node VNI scenario gate** — N in-memory nodes form a VNI group under the PQ X-Wing suite `0xF001`, all derive byte-equal ESP SA keys, a node joins (membership change) → all rekey → still converged, and an ESP-payload round-trips. The scenario test **is** the integration gate.

**Architecture (design spec §3, "Approach C"):** Two layers in one repo. `mls/` is the auditable, domain-agnostic RFC 9420 engine (knows nothing about VNIs/ESP/metalbond). `ironcore/` is the thin integration layer that depends on `mls/group` + `mls/cipher` + `mls/tree` and owns the VNI↔GroupID mapping, the exporter→ESP-SA derivation, the GCM nonce-separation logic, and the SPIFFE+PKI credential adapters. **The single library change *outside* `ironcore/` is Task 0** — an MLS-core correctness fix that belongs in `mls/group` (it fixes how the engine tracks a proposer's pending leaf key across a commit, independent of IronCore). `ironcore/` adds **no new dependency edges into `mls/`** beyond the public API already exposed by Plan 9 (`Group.Exporter`, `Group.Epoch`, `Group.OwnLeaf`, `Group.GroupContext`, `cipher.Lookup`, `cipher.Suite.ExpandWithLabel`, `tree.Credential`, `group.CredentialValidator`). metalbond implements the `DeliveryService`/`Ordering` ports in *its own* repo; this plan does **not** touch them.

**Tech Stack:** Go 1.26 standard library only (hard constraint). `ironcore/` uses `bytes`, `encoding/binary`, `fmt`, `crypto/ecdsa`, `crypto/ed25519`, `crypto/elliptic`, `crypto/x509`, `net/url` (all stdlib; `crypto/x509` + `net/url` are explicitly permitted for the credential adapters). It builds on `mls/cipher` (`Lookup`, `Suite.ExpandWithLabel`, `CipherSuite`), `mls/group` (`Group`, `CredentialValidator`, `NewGroup`/`NewKeyPackage`/`Commit`/`ProcessCommit`/`JoinFromWelcome`/`Protect`/`Unprotect`, the proposal constructors), and `mls/tree` (`Credential`, `Certificate`, `CredentialTypeX509`). Task 0 stays inside `mls/group` and `mls/tree`, stdlib-only.

**Spec reference:** Design spec `docs/superpowers/specs/2026-06-26-mls-mlkem-go-design.md` §3 (two-layer arch), §4 (the four ports + `CredentialValidator`), §8 (identity: one x509 SVID end-to-end; pluggable validators; authz hook in metalnet), §10.1 (VNI↔GroupID), §10.3 (membership controller flow), §10.4 (exporter→ESP-SA + per-sender GCM nonce separation), §10.5 (scale). RFC 9420 §5.1.3/§5.2 (labeled derivation), §8/§8.5 (key schedule + `MLS-Exporter`), §12.1.2/§12.3/§12.4 (Update proposals, application order, Commit). RFC 9750 §5 (DS untrusted for confidentiality). RFC 4106 (AES-GCM-ESP: 4-byte salt + 8-byte IV → 12-byte nonce), RFC 4303 §2.1 (ESP SPI range; values 1..255 reserved).

> **Go invocation convention:** Go is **not** on `PATH`. Every Go command runs through the nix devshell, e.g. `nix develop -c go test ./ironcore/`. Use this form everywhere below. Expect a `warning: Git tree '…' is dirty` line and a `Entered Go dev shell: …` banner on stderr — both are harmless.

---

## Design notes (read before implementing)

Every claim below was reproduced during planning by throwaway tests that built a 3-member X-Wing (`0xF001`) group (Alice creates → Add(Bob) → Add(Carol), Bob/Carol join+process) and exercised the exact code shown. **These facts make or break the integration — get them exactly right.**

### N0. The atomic pending-update fix (Task 0) — the subtle one

**The bug being replaced.** Plan 9's `(*Group).ProposeUpdate()` returns the freshly-generated leaf private key to the caller, and `(*Group).InstallPendingUpdateKey(newLeafPriv)` *mutates `g.priv` immediately*. That is **non-atomic**: a proposer must decide, *before processing any commit*, whether to install. If it installs eagerly but a **competing commit** (one that does **not** include its `Update`) wins the epoch, the old leaf key is already destroyed and the proposer can no longer decrypt that commit's `UpdatePath` (which was encrypted to its **old** leaf key, because the tree still holds the old leaf). The proposer is stuck.

**The fix.** The `Group` tracks pending updates itself and performs the key swap **atomically inside `ProcessCommit`**, only when a *confirmed* commit actually applies the proposer's own `Update`. `g.priv` is **never** mutated by `ProposeUpdate`; it is preserved until `ProcessCommit` has verified the `confirmation_tag`, exactly like every other piece of epoch state in the existing atomic commit block.

**Keying decision (validated, non-obvious).** The spec phrasing is "store [the pending key] keyed by the proposal's ref". We key by the **new leaf HPKE public key** instead, for a concrete reason discovered during planning: `Proposal.Ref(suite)` hashes the **bare `Proposal` body**, whereas the ref that appears in the committed `Commit.Proposals` (`ProposalOrRef.Reference`) is `RefHash("MLS 1.0 Proposal Reference", AuthenticatedContent)` over the **full framed `AuthenticatedContent`** — which is not known until `FrameProposal` runs. So a ref computed at `ProposeUpdate` time would **not match** the committed ref, and matching by the committed ref would force `ProposeUpdate` to also frame. The new leaf `encryption_key` is (a) freshly random per `ProposeUpdate` (unique), (b) carried verbatim in the committed `Update.LeafNode.EncryptionKey`, and (c) only ever produced by us for our own leaf (Updates are signed by our signer). Keying the pending map by `string(leafPub)` therefore gives **identical atomicity** with a clean, framing-independent API. *Validated: a 3-member group where Bob proposes, Alice commits by-reference, and Bob processes with no manual install converges; and a competing-commit scenario where Carol commits path-only (not Bob's update) and Bob processes it with the old key, all converging.*

**Implementation shape (all in `mls/group`):**
- `group.go`: add field `pendingUpdates map[string][]byte // new-leaf-pubkey → new-leaf-priv; swapped in atomically by ProcessCommit; cleared every epoch`.
- `create.go` / `join.go`: initialize `pendingUpdates: map[string][]byte{}` in the `&Group{…}` literal.
- `propose.go`: change `ProposeUpdate` signature from `(Proposal, []byte, error)` to `(Proposal, error)`; store `g.pendingUpdates[string(leafPub)] = leafPriv` **without** touching `g.priv`; **delete** `InstallPendingUpdateKey`.
- `process.go`: before path processing, resolve whether this commit applies our own `Update` (`resolveOwnUpdatePriv`); if so build a **local** `workingPriv = tree.NewTreeKEMPrivate(g.ownLeaf, pendingPriv)` and use it for `ProcessUpdatePath` and for the `PrivateKeyAt(2*ownLeaf)` rebuild — **never** assigning to `g.priv` until the existing atomic commit block; clear `g.pendingUpdates` there.
- `commit_gen.go`: clear `g.pendingUpdates` in the committer's own atomic commit block (a committer always rekeys its own leaf via `GenerateUpdatePath`, so any of its own pending updates are moot once it commits).
- `active_test.go`: update T5 to drop `bobNewLeafPriv` and the `InstallPendingUpdateKey` call.

The `resolveOwnUpdatePriv` helper (verified):
```go
// resolveOwnUpdatePriv returns the pending leaf private key for an Update in cm
// authored by g's own leaf, or nil if this commit does not apply such an Update.
// It errors only if an own Update is committed but no pending key is tracked.
func (g *Group) resolveOwnUpdatePriv(cm Commit, cache map[string]cachedProposal, committerLeaf uint32) ([]byte, error) {
	for _, por := range cm.Proposals {
		var prop Proposal
		var sender uint32
		switch por.Type {
		case ProposalOrRefTypeProposal:
			if por.Proposal == nil {
				continue
			}
			prop, sender = *por.Proposal, committerLeaf
		case ProposalOrRefTypeReference:
			cp, ok := cache[string(por.Reference)]
			if !ok {
				continue // applyProposals will surface the missing-ref error
			}
			prop, sender = cp.proposal, cp.sender
		default:
			continue
		}
		if prop.Type != ProposalTypeUpdate || sender != g.ownLeaf || prop.Update == nil {
			continue
		}
		pub := prop.Update.LeafNode.EncryptionKey
		priv, ok := g.pendingUpdates[string(pub)]
		if !ok {
			return nil, fmt.Errorf("own Update committed but no pending leaf key tracked")
		}
		return priv, nil
	}
	return nil, nil
}
```
The `ProcessCommit` wiring (verified) — inserted **after** `applyProposals` returns and **before** the `cm.Path != nil` block:
```go
// Atomic pending-update swap: if this commit applies an Update authored by our
// own leaf, decrypt the UpdatePath with the pending leaf key (path secrets are
// encrypted to our NEW leaf pubkey after the Update is applied to the tree).
// g.priv is NOT mutated here — workingPriv is local until confirmation_tag
// verifies, so a superseded update leaves the old key usable.
ownUpdatePriv, err := g.resolveOwnUpdatePriv(cm, cache, committerLeaf)
if err != nil {
	return fmt.Errorf("group: ProcessCommit: %w", err)
}
workingPriv := g.priv
if ownUpdatePriv != nil {
	workingPriv = tree.NewTreeKEMPrivate(g.ownLeaf, ownUpdatePriv)
}
```
Then **two one-line substitutions** in the existing body: `ProcessUpdatePath(committerLeaf, cm.Path, g.priv, …)` → `… workingPriv …`, and `g.priv.PrivateKeyAt(2 * g.ownLeaf)` → `workingPriv.PrivateKeyAt(2 * g.ownLeaf)` (and the `else { newPriv = g.priv }` → `newPriv = workingPriv`). In the final atomic block add `g.pendingUpdates = map[string][]byte{}`. **Do not move the `g.priv = newPriv` line** — it stays where it is, after `confirmation_tag` verification.

### N1. VNI↔GroupID encoding (design spec §10.1) — verified

`GroupID` must be a **stable, collision-free** encoding the `mls/` core treats opaquely, with an inverse. Use a 6-byte ASCII tag + 4-byte big-endian VNI (10 bytes total). The tag namespaces VNI group-ids away from any other GroupID scheme and lets the inverse fail-closed on foreign ids.
```go
var groupIDTag = []byte("ICVNI1") // 6-byte versioned tag for VNI-derived GroupIDs

// GroupID returns the stable MLS GroupID for a VNI (design spec §10.1).
func GroupID(vni uint32) []byte {
	b := make([]byte, len(groupIDTag)+4)
	copy(b, groupIDTag)
	binary.BigEndian.PutUint32(b[len(groupIDTag):], vni)
	return b
}

// VNIOfGroupID is the inverse of GroupID. It fails on any non-VNI GroupID.
func VNIOfGroupID(gid []byte) (uint32, error) {
	if len(gid) != len(groupIDTag)+4 || !bytes.Equal(gid[:len(groupIDTag)], groupIDTag) {
		return 0, fmt.Errorf("ironcore: not a VNI GroupID: %x", gid)
	}
	return binary.BigEndian.Uint32(gid[len(groupIDTag):]), nil
}
```
*Validated: round-trips for `0`, `1`, `0x0A0B0C0D`, `^uint32(0)`; `VNIOfGroupID` rejects wrong-length and wrong-tag inputs.*

### N2. exporter→ESP-SA derivation (design spec §10.4) — the core deliverable, fully verified

Mirror the spec §10.4 derivation **verbatim**. All quantities are deterministic functions of `(VNI, epoch)` and the per-epoch exporter secret, so **every member of a VNI group computes byte-identical `K_group` and `SPI`**.

- **Context encoding** — `context = VNI ‖ epoch` = 4-byte big-endian VNI followed by 8-byte big-endian epoch (12 bytes):
  ```go
  func saContext(vni uint32, epoch uint64) []byte {
  	b := make([]byte, 12)
  	binary.BigEndian.PutUint32(b[0:4], vni)
  	binary.BigEndian.PutUint64(b[4:12], epoch)
  	return b
  }
  ```
- **`K_group`** — the per-epoch group key, **32 bytes** for AES-256-GCM (the X-Wing suite's AEAD):
  ```
  K_group = MLS-Exporter("ironcore-esp", VNI‖epoch, 32)
  ```
  via `g.Exporter("ironcore-esp", saContext(vni, epoch), 32)`. **Label note:** design spec §10.4 writes the label as **`"ironcore-esp"`** (hyphenated); the Plan-10 brief paraphrases it as `"ironcore esp"`. **Use the spec's verbatim `"ironcore-esp"`** — it is the source of truth and what every member must agree on; pin it as a `const`.
- **`SPI`** — `f(VNI, epoch)`, a 32-bit ESP SPI with the epoch's low byte embedded so receivers disambiguate overlapping (make-before-break) epochs, and forced out of the reserved `0..255` range (RFC 4303 §2.1):
  ```go
  func deriveSPI(suite cipher.Suite, kGroup []byte, vni uint32, epoch uint64) (uint32, error) {
  	raw, err := suite.ExpandWithLabel(kGroup, "esp-spi", saContext(vni, epoch), 4)
  	if err != nil {
  		return 0, fmt.Errorf("ironcore: derive SPI: %w", err)
  	}
  	spi := binary.BigEndian.Uint32(raw)
  	spi = (spi &^ 0xFF) | uint32(uint8(epoch)) // epoch low byte → disambiguates overlapping epochs
  	spi |= 0x80000000                          // keep SPI > 255 (RFC 4303 §2.1 reserved range)
  	return spi, nil
  }
  ```
  Deriving the SPI from `K_group` (rather than a public function) is safe — the SPI travels in cleartext ESP headers but is a one-way `ExpandWithLabel` output that reveals nothing about the key — and guarantees all members agree.
- **Per-sender GCM nonce salt — THE CRITICAL PART (design spec §10.4 "GCM nonce safety").** The design uses **one group key** in a connectionless, route-based model (WireGuard-style cryptokey routing). Under AES-GCM, **nonce reuse across two encryptions under the same key is catastrophic** (it leaks the XOR of plaintexts and the GHASH authentication key). With a shared `K_group`, two different senders could pick the same `(key, nonce)`. The fix: give **every sender a disjoint nonce space** via a per-sender 4-byte salt that occupies the high 4 bytes of the 12-byte AES-GCM-ESP nonce (RFC 4106: `nonce = salt(4) ‖ IV(8)`, IV from the per-SA ESP sequence number). Distinct salts ⇒ two senders **never** share a full 12-byte nonce, regardless of their sequence numbers.
  ```go
  func (sa SA) SenderSalt(leafIndex uint32) ([]byte, error) {
  	ctx := make([]byte, 4)
  	binary.BigEndian.PutUint32(ctx, leafIndex)
  	salt, err := sa.suite.ExpandWithLabel(sa.Key, "esp-sender", ctx, 4) // 4-byte RFC 4106 GCM-ESP salt
  	if err != nil {
  		return nil, fmt.Errorf("ironcore: derive sender salt: %w", err)
  	}
  	return salt, nil
  }
  ```
  A **sender** encrypts with `SenderSalt(itsOwnLeaf)`; a **receiver** decrypts a packet with `SenderSalt(sourceLeafIndex)` (the data plane maps the IPv6 source to the sender's leaf index). *Validated: salts for leaves `0,1,2` are pairwise distinct, and every member derives the same salt for a given sender.*
- **The `SA` struct** (matches the enhancement proposal's ESP model: AES-256-GCM, PQ suite):
  ```go
  // SA is one IronCore ESP security association derived from an MLS epoch
  // (design spec §10.4). It feeds the dpservice/metalnet XFRM data plane.
  type SA struct {
  	VNI     uint32 // the VNI this SA protects
  	Epoch   uint64 // the MLS epoch it was derived from
  	SPI     uint32 // ESP SPI (epoch-encoded; > 255)
  	Key     []byte // K_group: 32-byte AES-256-GCM group key
  	OwnLeaf uint32 // this member's leaf index
  	OwnSalt []byte // 4-byte GCM nonce salt for this member's own sender nonce space
  	suite   cipher.Suite
  }
  ```
- **`DeriveSAKeys`** — the entry point. Suite is recovered from the group context (no new `mls/group` accessor needed):
  ```go
  func DeriveSAKeys(g *group.Group, vni uint32) (SA, error) {
  	suite, ok := cipher.Lookup(g.GroupContext().CipherSuite)
  	if !ok {
  		return SA{}, fmt.Errorf("ironcore: unregistered cipher suite %#x", g.GroupContext().CipherSuite)
  	}
  	epoch := g.Epoch()
  	kGroup, err := g.Exporter(espExporterLabel, saContext(vni, epoch), saKeyLen)
  	if err != nil {
  		return SA{}, fmt.Errorf("ironcore: derive K_group: %w", err)
  	}
  	spi, err := deriveSPI(suite, kGroup, vni, epoch)
  	if err != nil {
  		return SA{}, err
  	}
  	sa := SA{VNI: vni, Epoch: epoch, SPI: spi, Key: kGroup, OwnLeaf: g.OwnLeaf(), suite: suite}
  	if sa.OwnSalt, err = sa.SenderSalt(g.OwnLeaf()); err != nil {
  		return SA{}, err
  	}
  	return sa, nil
  }
  ```
- **Make-before-break (design spec §10.4).** `K_group` and `SPI` both depend on `epoch`, so an epoch change yields a **new, distinct** SA. Forward secrecy means an old epoch's exporter secret is gone after advancing, so the **caller holds the previous `SA` value object across the overlap window** (derive epoch `n+1` *before* tearing down epoch `n`'s SA). *Validated: `K_group` and `SPI` differ between epoch `n` and `n+1`; the held epoch-`n` `SA` bytes remain valid.*

Constants:
```go
const (
	espExporterLabel = "ironcore-esp" // design spec §10.4 verbatim
	saKeyLen         = 32             // AES-256-GCM key length (the X-Wing suite AEAD)
	saSaltLen        = 4              // RFC 4106 AES-GCM-ESP salt length
)
```

### N3. VNIGroup wrapper (design spec §10.1) — thin

A thin handle pairing a VNI with its `*group.Group`; the home for `DeriveSA` and `GroupID`. Keep it minimal — the membership controller (designated-committer election, external-commit join) is **deferred** (see roadmap).
```go
type VNIGroup struct {
	vni uint32
	g   *group.Group
}

func NewVNIGroup(vni uint32, g *group.Group) *VNIGroup { return &VNIGroup{vni: vni, g: g} }
func (v *VNIGroup) VNI() uint32          { return v.vni }
func (v *VNIGroup) GroupID() []byte      { return GroupID(v.vni) }
func (v *VNIGroup) Group() *group.Group  { return v.g }
func (v *VNIGroup) Epoch() uint64        { return v.g.Epoch() }
func (v *VNIGroup) DeriveSA() (SA, error) { return DeriveSAKeys(v.g, v.vni) }
```

### N4. CredentialValidator adapters (design spec §8) — verified with `crypto/x509` + `net/url`

Both adapters implement the `group.CredentialValidator` port: `Validate(cred tree.Credential, sigPub []byte) (identity []byte, err error)`. Credentials are MLS-native **x509** (`tree.CredentialTypeX509`, `cred.Certificates[0]` = leaf DER, `[1:]` = intermediates). The **identity binding** that matters: the cert's public key, re-encoded in the MLS `SignaturePublicKey` form, **must equal** `sigPub` — this is what ties the x509 SVID to the MLS leaf's signing key (and, per spec §8, to the mTLS channel identity).

Shared helpers (verified):
```go
func parseChain(cred tree.Credential) (leaf *x509.Certificate, intermediates *x509.CertPool, err error) {
	if cred.CredentialType != tree.CredentialTypeX509 || len(cred.Certificates) == 0 {
		return nil, nil, fmt.Errorf("ironcore: credential is not a non-empty x509 credential")
	}
	leaf, err = x509.ParseCertificate(cred.Certificates[0].CertData)
	if err != nil {
		return nil, nil, fmt.Errorf("ironcore: parse leaf cert: %w", err)
	}
	intermediates = x509.NewCertPool()
	for i, c := range cred.Certificates[1:] {
		ic, err := x509.ParseCertificate(c.CertData)
		if err != nil {
			return nil, nil, fmt.Errorf("ironcore: parse intermediate[%d]: %w", i, err)
		}
		intermediates.AddCert(ic)
	}
	return leaf, intermediates, nil
}

// bindSignatureKey checks the cert public key equals the MLS SignaturePublicKey
// encoding of sigPub (Ed25519: raw 32 bytes; ECDSA-P256: uncompressed SEC1 point
// — the exact encodings cipher.Suite.SignaturePublicKey produces).
func bindSignatureKey(leaf *x509.Certificate, sigPub []byte) error {
	switch pk := leaf.PublicKey.(type) {
	case ed25519.PublicKey:
		if !bytes.Equal([]byte(pk), sigPub) {
			return fmt.Errorf("ironcore: cert public key does not match MLS signature key")
		}
	case *ecdsa.PublicKey:
		if !bytes.Equal(elliptic.Marshal(pk.Curve, pk.X, pk.Y), sigPub) { //nolint:staticcheck — matches cipher.Suite.SignaturePublicKey
			return fmt.Errorf("ironcore: cert public key does not match MLS signature key")
		}
	default:
		return fmt.Errorf("ironcore: unsupported certificate public key type %T", pk)
	}
	return nil
}
```
**`PKIValidator`** — chain to a trust bundle, return the subject DN as identity:
```go
type PKIValidator struct {
	Roots *x509.CertPool // trust bundle
}

func (v PKIValidator) Validate(cred tree.Credential, sigPub []byte) ([]byte, error) {
	leaf, intermediates, err := parseChain(cred)
	if err != nil {
		return nil, err
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         v.Roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, fmt.Errorf("ironcore: PKI chain verification failed: %w", err)
	}
	if err := bindSignatureKey(leaf, sigPub); err != nil {
		return nil, err
	}
	return []byte(leaf.Subject.String()), nil
}
```
**`SPIFFEValidator`** — extract the single `spiffe://` URI SAN via `cert.URIs` (already parsed `*url.URL`s), check the trust domain (`url.Host`), optionally chain-verify, return the SPIFFE ID as identity:
```go
type SPIFFEValidator struct {
	TrustDomain string         // expected trust domain, e.g. "example.org"; "" accepts any
	Roots       *x509.CertPool // optional; if non-nil, the SVID chain is verified too
}

func (v SPIFFEValidator) Validate(cred tree.Credential, sigPub []byte) ([]byte, error) {
	leaf, intermediates, err := parseChain(cred)
	if err != nil {
		return nil, err
	}
	if v.Roots != nil {
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:         v.Roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		}); err != nil {
			return nil, fmt.Errorf("ironcore: SVID chain verification failed: %w", err)
		}
	}
	if err := bindSignatureKey(leaf, sigPub); err != nil {
		return nil, err
	}
	id, err := spiffeID(leaf)
	if err != nil {
		return nil, err
	}
	if v.TrustDomain != "" && id.Host != v.TrustDomain {
		return nil, fmt.Errorf("ironcore: SPIFFE trust domain %q != expected %q", id.Host, v.TrustDomain)
	}
	return []byte(id.String()), nil
}

func spiffeID(leaf *x509.Certificate) (*url.URL, error) {
	var found *url.URL
	for _, u := range leaf.URIs {
		if u.Scheme != "spiffe" {
			continue
		}
		if found != nil {
			return nil, fmt.Errorf("ironcore: multiple SPIFFE URI SANs in SVID")
		}
		found = u
	}
	if found == nil {
		return nil, fmt.Errorf("ironcore: no SPIFFE URI SAN in SVID")
	}
	if found.Host == "" {
		return nil, fmt.Errorf("ironcore: SPIFFE ID has empty trust domain")
	}
	return found, nil
}
```
**Authz hook (design spec §8)** — the library validates the binding and *exposes the verified identity*; the entitlement decision ("is this identity allowed on VNI X?") lives in metalnet's control plane:
```go
// Authorizer answers "is identity entitled to participate in vni?" The policy
// itself lives in the caller (metalnet control plane); the library only invokes it.
type Authorizer func(identity []byte, vni uint32) bool
```
*Validated: a SPIFFE SVID issued by a test CA chain-verifies; `bindSignatureKey` matches the Ed25519 cert key to the MLS `sigPub`; the URI-SAN extraction returns `spiffe://example.org/...` and rejects a wrong trust domain; an untrusted root fails `leaf.Verify`. Confirmed separately: a `mls/group` group **forms end-to-end with x509 leaf credentials** under suite `0xF001` — the default leaf capabilities do not reject x509 credentials.*

### N5. Multi-node scenario gate (design spec §10.3/§10.4/§10.5) — the integration test

The strict gate. `package ironcore_test`, suite `0xF001`. Helpers build N nodes as MLS members of one VNI group (Alice creates; Adds committed one-by-one; joiners `JoinFromWelcome`; existing members `ProcessCommit`). Assertions, after **every** epoch:
1. All members' `DeriveSAKeys(vni)` produce **byte-equal `Key` and equal `SPI`** (and equal `Epoch`).
2. The per-sender salts over the live leaf indices are **pairwise distinct** (and each member derives the same salt for a given sender).
3. After a **join** (membership change → new epoch), the SA `Key`/`SPI` **change** (rekey) and all members again agree (still converged).
4. An MLS application message (standing in for the ESP-protected payload — same `K_group`-derived AEAD path the data plane uses) **round-trips**: `decrypt == plaintext`.

This transitively proves the X-Wing suite, the exporter, the SA derivation, and the membership flow all interlock. Use basic credentials for the membership mechanics (credential *validation* is gated separately in N4); optionally thread an `Authorizer` + `SPIFFEValidator` over each joiner's credential before Add to demonstrate the §8 authz path.

---

## File structure

| File | New/Changed | Purpose |
|---|---|---|
| `mls/group/group.go` | **changed** (Task 0) | Add `pendingUpdates map[string][]byte` field to `Group`. |
| `mls/group/create.go` | **changed** (Task 0) | Initialize `pendingUpdates` in `NewGroup`. |
| `mls/group/join.go` | **changed** (Task 0) | Initialize `pendingUpdates` in `JoinFromWelcome`. |
| `mls/group/propose.go` | **changed** (Task 0) | `ProposeUpdate` → `(Proposal, error)`, store pending key by leaf-pubkey; **delete** `InstallPendingUpdateKey`. |
| `mls/group/process.go` | **changed** (Task 0) | `resolveOwnUpdatePriv` helper; `workingPriv` swap; clear pending on epoch change. |
| `mls/group/commit_gen.go` | **changed** (Task 0) | Clear `pendingUpdates` in the committer's atomic commit block. |
| `mls/group/active_test.go` | **changed** (Task 0) | Update T5 to drop the manual `InstallPendingUpdateKey`. |
| `mls/group/pending_update_test.go` | **new** (Task 0) | Convergence (different committer, no manual install) + superseded-update tests. |
| `ironcore/vni.go` | **new** (Task 1) | `GroupID(vni)` + `VNIOfGroupID` (N1). |
| `ironcore/vni_test.go` | **new** (Task 1) | Round-trip + fail-closed tests. |
| `ironcore/sa.go` | **new** (Task 2) | `SA`, `DeriveSAKeys`, `deriveSPI`, `SenderSalt`, `saContext`, constants (N2). |
| `ironcore/sa_test.go` | **new** (Task 2) | Self-consistency, distinct salts, rotation. |
| `ironcore/group.go` | **new** (Task 3) | `VNIGroup` wrapper (N3). |
| `ironcore/group_test.go` | **new** (Task 3) | Wrapper delegation + `DeriveSA` smoke test. |
| `ironcore/credential.go` | **new** (Task 4) | `PKIValidator`, `SPIFFEValidator`, `Authorizer`, `parseChain`/`bindSignatureKey`/`spiffeID` (N4). |
| `ironcore/credential_test.go` | **new** (Task 4) | Chain verify, SPIFFE extraction, sig-key binding, negative cases. |
| `ironcore/scenario_test.go` | **new** (Task 5) | Multi-node VNI gate under `0xF001` (N5). |
| `ironcore/testhelpers_test.go` | **new** (Task 5) | Shared test builders (signers, basic/x509 creds, N-node group construction). |

No `go.mod` change (same module `github.com/trevex/mls-mlkem-go`, Go 1.26.4, stdlib-only).

---

## Tasks

> **TDD discipline (REQUIRED SUB-SKILL `superpowers:test-driven-development`):** for every task, write the test(s) first, watch them fail (`nix develop -c go test ./… -run …` → red), then implement to green. One task = one commit. Run `nix develop -c gofmt -l <files>` (must print nothing) and `nix develop -c go vet ./ironcore/ ./mls/group/` (clean) before each commit. The convergence/scenario tests are the gates — keep their assertions strict (byte-equal `K_group`/`SPI`, distinct salts, `decrypt == plaintext`).

### Task 0 — Atomic pending-update tracking (MLS-core fix, `mls/group`) — committed first

- [ ] **0.1 Write the failing tests** in `mls/group/pending_update_test.go` (`package group_test`). Two tests under suite `0xF001` (and also `0x0001` for breadth), each building a 3-member group (Alice→Add Bob→Add Carol) via the existing active helpers (`makeSigner`, `makeCred`, `makeLifetime`, `EncodeKeyPackageMessage`, `JoinFromWelcome`, `assertConverged`):
  - `TestPendingUpdateConvergesDifferentCommitter`: Bob `ProposeUpdate()` (no second return value), `FrameProposal`, Alice `Commit(ByReference: [updateMsg])`, **Bob `ProcessCommit([updateMsg], commit)` with no manual install**, Carol processes too → `assertConverged(alice, bob, carol)`.
  - `TestSupersededUpdateOldKeyStillUsable`: Bob `ProposeUpdate()` (pending stored, `g.priv` untouched), then **Carol** `Commit{}` (path-only, *not* Bob's update); Bob `ProcessCommit(nil, carolCommit)` must succeed (decrypts Carol's path with Bob's **old** leaf key), Alice processes → `assertConverged(alice, bob, carol)`.
  These fail to compile against Plan 9 (`ProposeUpdate` still returns 3 values) — that compile failure *is* the initial red.
- [ ] **0.2 Implement the fix** per N0: `group.go` field; `create.go`/`join.go` init; `propose.go` signature change + store-by-pubkey + delete `InstallPendingUpdateKey`; `process.go` `resolveOwnUpdatePriv` + `workingPriv` + clear-on-epoch; `commit_gen.go` clear-on-epoch.
- [ ] **0.3 Update `active_test.go` T5** to the new API (drop `bobNewLeafPriv` and the `InstallPendingUpdateKey` line; add a comment "atomic pending-update: no manual key install needed").
- [ ] **0.4 Green + full regression:** `nix develop -c go test ./mls/...` all green (the existing KAT + active suites must still pass — the fix is behavior-preserving for every non-superseded path). `gofmt`/`vet` clean. **Commit** ("mls/group: atomic pending-update tracking; remove InstallPendingUpdateKey").

> **Empirical-validation reference (done during planning):** the throwaway implementation of exactly this design passed the full `./mls/...` suite plus both new scenarios under `0xF001`; `gofmt -l` empty; `go vet` clean.

### Task 1 — VNI↔GroupID (`ironcore/vni.go`)

- [ ] **1.1** Write `ironcore/vni_test.go` (`package ironcore`): `GroupID`→`VNIOfGroupID` round-trips for `0, 1, 0x0A0B0C0D, ^uint32(0)`; distinct VNIs → distinct GroupIDs; `VNIOfGroupID` errors on wrong length, wrong tag, and a truncated id. Red (no `vni.go`).
- [ ] **1.2** Implement `ironcore/vni.go` per N1 (package doc comment on this file: it is the IronCore integration layer, design spec §3/§10). Green. `gofmt`/`vet`. **Commit.**

### Task 2 — exporter→ESP-SA derivation (`ironcore/sa.go`)

- [ ] **2.1** Write `ironcore/sa_test.go` (`package ironcore_test`): build a 3-member `0xF001` group (reuse the Task 5 helpers if landed, else a local builder); assert (a) all members' `DeriveSAKeys(vni)` give byte-equal `Key` (len 32), equal `SPI` (> 255), equal `Epoch`; (b) `SenderSalt(0/1/2)` pairwise distinct, len 4, and equal across members for a given sender; (c) after a path-only commit (epoch++), `Key` and `SPI` both change and members still agree. Red.
- [ ] **2.2** Implement `ironcore/sa.go` per N2 (`SA`, `saContext`, `DeriveSAKeys`, `deriveSPI`, `SenderSalt`, constants). Green. `gofmt`/`vet`. **Commit.**

### Task 3 — VNIGroup wrapper (`ironcore/group.go`)

- [ ] **3.1** Write `ironcore/group_test.go`: `NewVNIGroup(vni, g)`; assert `VNI()`, `GroupID()` equals `GroupID(vni)`, `Epoch()` tracks the group, and `DeriveSA()` equals `DeriveSAKeys(g, vni)` (byte-equal `Key`). Red.
- [ ] **3.2** Implement `ironcore/group.go` per N3. Green. `gofmt`/`vet`. **Commit.**

### Task 4 — CredentialValidator adapters (`ironcore/credential.go`)

- [ ] **4.1** Write `ironcore/credential_test.go`: a tiny test CA helper (Ed25519 self-signed CA; issue a leaf with a `spiffe://example.org/...` URI SAN). Assert:
  - `PKIValidator{Roots: pool}.Validate(x509cred, sigPub)` succeeds and returns the subject; fails against an unrelated root pool; fails when `sigPub` ≠ cert key; fails for a non-x509 credential.
  - `SPIFFEValidator{TrustDomain: "example.org"}.Validate(...)` returns `spiffe://example.org/...`; fails for `TrustDomain: "evil.example"`; fails on a cert with no SPIFFE SAN; with `Roots` set, chain-verifies (and fails against a wrong pool).
  - Both satisfy `group.CredentialValidator` (assign to a `var _ group.CredentialValidator = PKIValidator{}` / `SPIFFEValidator{}`).
  Red.
- [ ] **4.2** Implement `ironcore/credential.go` per N4 (`Authorizer`, `PKIValidator`, `SPIFFEValidator`, `parseChain`, `bindSignatureKey`, `spiffeID`). Green. `gofmt`/`vet`. **Commit.**

### Task 5 — Multi-node VNI scenario gate (`ironcore/scenario_test.go`)

- [ ] **5.1** Write `ironcore/testhelpers_test.go`: `newSigner`, `basicCred`, `x509SVIDCred(ca, caKey, spiffeID)`, and `buildVNIGroup(t, suite, vni, n)` returning `n` converged `*VNIGroup`s plus the machinery to add a new member and have all existing members process the commit.
- [ ] **5.2** Write `ironcore/scenario_test.go` (`TestMultiNodeVNIScenario`, suite `0xF001`) per N5:
  1. Form an N-node (N=4) VNI group; assert all derive byte-equal `Key`/`SPI`; assert per-sender salts over all live leaves pairwise distinct.
  2. Add a 5th node (membership change → new epoch); all existing members `ProcessCommit`, joiner `JoinFromWelcome`; re-derive SAs → `Key`/`SPI` rotated **and** all five agree (still converged).
  3. ESP-payload round-trip: one member `ProtectApplication(payload)`, another `UnprotectApplication` → `decrypt == plaintext`.
  4. (Optional, demonstrates §8) run a `SPIFFEValidator` + `Authorizer` over the joiner's x509 SVID before the Add.
  Make every assertion strict (`bytes.Equal` on `Key`, `==` on `SPI`, distinctness map for salts, `bytes.Equal` on plaintext).
- [ ] **5.3** Green. `gofmt`/`vet`. Run `nix develop -c go test ./ironcore/ ./mls/...` — all green. **Commit** ("ironcore: multi-node VNI scenario gate").

---

## Definition of Done

- [ ] `nix develop -c go build ./...` succeeds.
- [ ] `nix develop -c go test ./...` is **all green**, including the unchanged `mls/` KAT + active suites (Task 0 is behavior-preserving for every non-superseded path) and the new `ironcore/` tests.
- [ ] `nix develop -c gofmt -l mls/group ironcore` prints **nothing**; `nix develop -c go vet ./mls/group/ ./ironcore/` is clean.
- [ ] `InstallPendingUpdateKey` is gone; `ProposeUpdate` returns `(Proposal, error)`; a member whose Update is committed by another member converges with **no manual key install**, and a member whose Update is **superseded** still processes the competing commit with its old key (both covered by `mls/group/pending_update_test.go`).
- [ ] `ironcore.GroupID`/`VNIOfGroupID` round-trip and fail-closed on foreign ids.
- [ ] `DeriveSAKeys`: all members of a VNI group derive **byte-identical `K_group` and equal `SPI`** for an epoch; per-sender salts are **pairwise distinct** (disjoint GCM nonce spaces); the SA **rotates** on epoch change (epoch `n` and `n+1` both derivable as held value objects).
- [ ] `PKIValidator` and `SPIFFEValidator` implement `group.CredentialValidator`, validate real `crypto/x509` chains / SPIFFE URI-SANs, bind the cert key to the MLS `sigPub`, and reject untrusted roots / wrong trust domains / mismatched keys.
- [ ] `TestMultiNodeVNIScenario` (suite `0xF001`) passes: N nodes converge with matching SA keys, a join rekeys all to a new converged SA, and an ESP-payload round-trips.
- [ ] stdlib-only; no new module dependencies; the only library change outside `ironcore/` is the Task 0 `mls/group` fix.

---

## Notes for the remaining roadmap (out of scope here)

- **Plan 11 — B1 Sequencer (design spec §5.5).** The fenced single-writer-per-VNI `Ordering` implementation (epoch-numbered lease / fencing token over a strongly-consistent store) that enforces "at most one accepted Commit per `(group, epoch)`" (§5.1). The library defines the `Ordering` port; metalbond selects B1/B2.
- **External-commit join + fork-detect/recovery (design spec §5.6 / §10.3 "Join").** Needs external-commit *generation* (`external_init` proposal + `ExternalPub` from the published signed `GroupInfo`) — not yet in `mls/group`. The recovery helper (re-converge a stale/losing member via external Commit + signed GroupInfo under the lowest-`Hash(Commit)` tie-break) and active fork detection (`epoch_authenticator` out-of-band comparison) layer on top. This is also the restart-rejoin path (§9).
- **Membership controller (design spec §10.3).** Designated-committer election (active leaf with lowest index, deterministic handover), `external_senders`-driven Add/Remove proposals from the control plane, periodic empty-Update rekey timer for PCS. Will likely want a small read-only `Group.Members() []uint32` accessor (deliberately *not* added in this plan to keep the `mls/group` surface limited to the Task 0 correctness fix).
- **metalbond `DeliveryService`/`Ordering` adapter.** Lives in metalbond's repo (implements the ports against its wire protocol); this library never imports metalbond protobufs.
- **gRPC `MLSClient` interop (design spec §6).** Classical-suite conformance against OpenMLS/mls-rs; the X-Wing suite is validated by our own vectors + the scenario gate (no IANA PQ-MLS suite to interop with yet).
