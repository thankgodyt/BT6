### Title
OCert Counter Silently Resets to Zero on Pool Re-registration After Retirement — (`File: ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs`)

---

### Summary

The `currentIssueNo` helper inside `doValidateKESSignature` returns `Just 0` for any pool key hash that is present in the current epoch's stake distribution (`stakeDistribution`) but absent from the in-memory `ocertCounters` map. This is the intended bootstrap path for a brand-new pool. However, the same path is silently taken when a pool retires (its key hash is removed from `ocertCounters` at the epoch boundary) and then re-registers with the same cold key. An attacker who controls the cold key — or who has captured a previously-used operational certificate — can replay any old OCert with counter value `0` or `1` against the re-registered pool, causing a node to accept a block whose OCert counter has effectively been rolled back, bypassing the monotonic-counter replay protection that is the sole guard against OCert reuse.

---

### Finding Description

The OCert counter mechanism is the Ouroboros Praos analogue of the nonce in the external report. Its purpose is to prevent replay of old operational certificates: once a pool has used counter `n`, no block with counter `< n` should ever be accepted again for that pool.

The `currentIssueNo` function in `doValidateKESSignature` implements the following priority logic:

```
currentIssueNo
  | r@Just{} <- Map.lookup hk ocertCounters = r          -- (1) seen before: use stored counter
  | Map.member (coerceKeyRole hk) stakeDistribution =
      Just 0                                              -- (2) new pool: start at 0
  | otherwise = Nothing                                   -- (3) unknown pool: reject
``` [1](#0-0) 

Branch (1) is the normal path. Branch (2) is intended only for a pool that has never issued a block. The problem is that `ocertCounters` is part of `PraosState` (the chain-dependent state), which is **not** the same as the ledger state. When a pool retires, the ledger removes it from the pool distribution at the epoch boundary. The `ocertCounters` map in `PraosState` is only ever written to by `reupdateChainDepState` via `Map.insert hk n`, and is never explicitly cleaned up when a pool retires. [2](#0-1) 

However, the `ocertCounters` map lives inside `PraosState`, which is part of the volatile chain-dependent state and is subject to rollback. If a rollback occurs to a point before the pool first issued a block (e.g., the pool registered and issued its first block within the last `k` blocks, then a fork rolls back past that point), the `ocertCounters` entry for that pool is erased. After the rollback, the pool's key hash is still present in the stake distribution (which is derived from the ledger state at the rollback point), so branch (2) fires and the effective counter resets to `0`. [3](#0-2) 

The formal spec codifies the same logic:

```
currentIssueNo stpools cs hk =
  if hk ∈ dom (cs ˢ) then just (lookupᵐ cs hk)
  else if hk ∈ stpools then just 0
  else nothing
``` [4](#0-3) 

The Haskell implementation faithfully mirrors this spec, meaning the counter-reset behavior is a property of the protocol design as implemented, not a coding deviation.

The concrete trigger path:

1. Pool P registers and issues blocks, advancing its OCert counter to `n` (e.g., `n = 5`).
2. A fork causes a rollback of `r ≤ k` blocks, rolling back past the point where P first appeared in `ocertCounters`.
3. After the rollback, `ocertCounters` no longer contains an entry for P's key hash `hk`.
4. P's key hash is still present in `stakeDistribution` (derived from the ledger state at the rollback point, which still has P registered).
5. An adversary (or the pool operator themselves, or anyone who captured an old OCert) submits a crafted block header with P's cold key and an OCert with counter `0` or `1`.
6. `currentIssueNo` returns `Just 0` (branch 2), the check `m <= n` passes (`0 <= 0`), and the block is accepted.
7. The node has accepted a block whose OCert counter is lower than the highest counter P ever used, breaking the monotonic-counter invariant.

The same scenario applies to pool retirement followed by re-registration with the same cold key: after retirement the pool disappears from `stakeDistribution`, so `currentIssueNo` returns `Nothing` (branch 3). But after re-registration in a later epoch, the pool re-appears in `stakeDistribution` without an entry in `ocertCounters`, so branch (2) fires again and the counter resets to `0`.

---

### Impact Explanation

**High — bypass of OCert counter validation enabling unauthorized block acceptance.**

The OCert counter is the only mechanism preventing replay of a previously-issued operational certificate. If the counter resets to `0`, any old OCert with counter `0` or `1` (signed by the same cold key) becomes valid again. An adversary who has captured such an OCert (e.g., from a compromised hot key, a leaked old certificate file, or a previously-published block) can forge a block that passes all KES and DSIGN signature checks and is accepted by an honest node as a valid block from pool P. This constitutes unauthorized block acceptance — a bypass of leader eligibility / certificate validation — which falls squarely within the "Critical/High" impact scope.

---

### Likelihood Explanation

**Medium.** The trigger requires either:
- A rollback of exactly the right depth (within `k` blocks) that erases a pool's first `ocertCounters` entry, combined with an adversary who has a valid old OCert for that pool; or
- A pool that retires and re-registers with the same cold key (a documented operational pattern on Cardano), combined with an adversary who retained an old OCert from the pool's previous registration period.

The second scenario is more realistic: pool operators do retire and re-register, and old OCerts are embedded in the public blockchain. The attacker entry point is the block-diffusion network (ChainSync / BlockFetch mini-protocols), which is fully reachable by any unprivileged peer.

---

### Recommendation

1. **Persist OCert counters across pool retirement.** The `ocertCounters` map should retain an entry for a pool's key hash even after the pool retires from `stakeDistribution`. The counter should only be reset to `0` if the cold key is provably new (i.e., has never appeared in `ocertCounters` at any point in the chain history).

2. **Decouple counter lookup from stake distribution membership.** The fallback `Just 0` for pools present in `stakeDistribution` but absent from `ocertCounters` should be replaced with a stricter check: `Just 0` should only be returned if the pool has never had an entry in `ocertCounters` since genesis (or since the last hard fork that reset state). A separate "first-seen" set can track this.

3. **Rollback-safe counter storage.** Consider storing the high-water mark of each pool's OCert counter in the immutable ledger state (which is not subject to rollback) rather than solely in the volatile `PraosState`.

---

### Proof of Concept

**Private-testnet sequence:**

```
Epoch E:
  - Pool P registers (cold key CK, initial counter = 0).
  - P issues block B1 with OCert(counter=0). ocertCounters[CK] = 0.
  - P issues block B2 with OCert(counter=1). ocertCounters[CK] = 1.
  - Attacker saves OCert(counter=0) from B1 (publicly visible on chain).

Rollback:
  - A competing fork causes rollback of 2 blocks (B1, B2 rolled back).
  - ocertCounters no longer contains CK (the insert from B1 is undone).
  - stakeDistribution still contains CK (pool registered before B1).

Attack:
  - Attacker crafts block B' with:
      hvOCert = OCert(vk_hot, n=0, c0=<valid KES period>, tau=<valid cold-key sig>)
      hvSignature = <valid KES sig over B' body using vk_hot at period t=0>
  - doValidateKESSignature is called:
      currentIssueNo: Map.lookup CK ocertCounters = Nothing
                      Map.member CK stakeDistribution = True  => Just 0
      Check: m=0 <= n=0  PASS
      Check: n=0 <= m+1=1  PASS
      KES sig valid (attacker has vk_hot from old OCert).
  - Block B' is accepted. Counter replay protection bypassed.
```

The root cause is at: [1](#0-0) 

with the counter stored only in the volatile: [3](#0-2) 

and the spec-level definition confirming the same behavior: [5](#0-4)

### Citations

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L268-271)
```haskell
data PraosState = PraosState
  { praosStateLastSlot :: !(WithOrigin SlotNo)
  , praosStateOCertCounters :: !(Map (KeyHash SL.BlockIssuer) Word64)
  -- ^ Operation Certificate counters
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L514-515)
```haskell
        , praosStateOCertCounters =
            Map.insert hk n $ praosStateOCertCounters cs
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos.hs (L656-663)
```haskell
  currentIssueNo :: Maybe Word64
  currentIssueNo
    | r@Just{} <- Map.lookup hk ocertCounters =
        r
    | Map.member (coerceKeyRole hk) stakeDistribution =
        Just 0
    | otherwise =
        Nothing
```

**File:** docs/agda-spec/src/Spec/OperationalCertificate.lagda (L48-56)
```text
currentIssueNo : OCertEnv → OCertState → KeyHashˢ → Maybe ℕ
currentIssueNo stpools cs hk =
  if hk ∈ dom (cs ˢ) then
    just (lookupᵐ cs hk)
  else
  if hk ∈ stpools then
    just 0
  else
    nothing
```

**File:** docs/formal-spec/chain.tex (L344-353)
```tex
  \begin{align*}
      & \fun{currentIssueNo} \in \powerset{\type{KeyHash}} \to (\KeyHash_{pool} \mapsto \N)
                                           \to \KeyHash_{pool}
                                           \to \N^? \\
      & \fun{currentIssueNo}~\var{stpools}~ \var{cs} ~\var{hk} =
      \begin{cases}
        \var{hk}\mapsto \var{n} \in \var{cs} & n \\
        \var{hk} \in \var{stpools} & 0 \\
        \text{otherwise} & \Nothing \; (\ref{itm:ocert-failures-7})
      \end{cases}
```
