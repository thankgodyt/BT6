### Title
Inverted Boolean in `noCertsFromTwoRoundsAgo` Silently Suppresses Peras Certificate Inclusion in Rounds 0 and 1 - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs`)

---

### Summary

In `noCertsFromTwoRoundsAgo`, the early-exit guard for `currRoundNo < 2` returns `Bool False` — the wrong boolean — causing the entire `needCertRules` conjunction to evaluate to `False` in Peras rounds 0 and 1. This unconditionally suppresses certificate inclusion during those rounds, violating the CIP-0140 Peras block-creation rule and silently breaking the chain-selection boost that Peras certificates are designed to provide.

---

### Finding Description

The function `noCertsFromTwoRoundsAgo` is one of three sub-predicates that must all be `True` for `needCert` to return `IncludeCert`. Its purpose is to confirm that no certificate from two rounds ago is already present in the node's certificate snapshot (to avoid redundant inclusion).

When `currRoundNo < 2`, the code short-circuits to avoid an unsigned underflow in `currRoundNo - 2`:

```haskell
-- We cannot have possibly seen a certificate from two rounds ago if we are
-- in round 0 or 1. In that case, this is vacuously false.
| currRoundNo < 2 =
    NoCertsFromTwoRoundsAgo currRoundNo
      := Bool False          -- ← BUG: should be Bool True
```

The comment itself reveals the confusion: it says "vacuously false" but the predicate is named `noCertsFromTwoRoundsAgo` — i.e., "there are **no** certs from two rounds ago." When `currRoundNo < 2`, rounds −2 and −1 do not exist, so the set `certIds` trivially cannot contain a certificate from two rounds ago. Therefore `containsCertFromTwoRoundsAgo` is vacuously `False`, and `Not (Bool False)` = `Bool True`. The correct short-circuit value is `Bool True`, not `Bool False`.

The otherwise-branch correctly computes `Not (Bool containsCertFromTwoRoundsAgo)`, which would evaluate to `Bool True` when the set is empty — confirming the intended semantics. [1](#0-0) 

The bug propagates directly into `needCertRules`:

```haskell
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv          -- False in rounds 0 and 1
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
```

Because `:/\:` short-circuits on the first `False`, the entire conjunction is `False` whenever `currRoundNo < 2`, and `needCert` always returns `DoNotIncludeCert`. [2](#0-1) 

The conformance test model in `Test/Consensus/Peras/Cert/Inclusion.hs` replicates the same wrong value:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then False          -- ← same bug in the model
    else not ((currRoundNo - 2) `Set.member` certIds)
```

Because both the production predicate and the reference model agree on `False`, `prop_needCert` passes without detecting the defect. [3](#0-2) 

---

### Impact Explanation

Peras certificates carry a chain-selection boost: a block that includes a valid certificate for a recent round is preferred over an equally-long chain that does not. Suppressing certificate inclusion in rounds 0 and 1 means:

- A certificate formed in round 0 (the first Peras voting round) can never be embedded in any block produced in round 1, regardless of whether all other inclusion conditions (`latestCertSeenIsNotExpired`, `latestCertSeenIsNewerThanLatestCertOnChain`) are satisfied.
- The chain-selection weight contributed by that certificate is permanently lost for all honest nodes, because the window to include it passes before round 2.
- An adversary who knows this invariant can exploit the missing boost during the protocol's earliest rounds — precisely when the chain is shortest and most susceptible to reorganisation — to make honest nodes prefer a less-secure fork.

This matches the **High** impact category: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The defect is deterministic and affects every Peras-enabled node unconditionally during rounds 0 and 1 of every Peras era. No special attacker capability is required; the wrong outcome is produced by the node itself during normal block production. The only mitigating factor is that the affected window is narrow (two rounds at era start), but it is guaranteed to trigger on every chain restart or era transition that initialises a new Peras round counter.

---

### Recommendation

Change the short-circuit branch in `noCertsFromTwoRoundsAgo` from `Bool False` to `Bool True`, and correct the comment:

```haskell
-- We cannot have possibly seen a certificate from two rounds ago if we are
-- in round 0 or 1. In that case, this is vacuously TRUE.
| currRoundNo < 2 =
    NoCertsFromTwoRoundsAgo currRoundNo
      := Bool True
```

Apply the same correction to the reference model in `Test/Consensus/Peras/Cert/Inclusion.hs`:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then True   -- vacuously true: no rounds −2 or −1 exist
    else not ((currRoundNo - 2) `Set.member` certIds)
```

After the fix, add a targeted unit test that constructs a `PerasCertInclusionView` with `currRoundNo ∈ {0, 1}` and an empty `certIds`, and asserts that `noCertsFromTwoRoundsAgo` evaluates to `True`.

---

### Proof of Concept

**Scenario:** Peras is active. A certificate for round 0 is formed and gossiped. A block producer is elected in round 1 and calls `needCert` with:

```
currRoundNo          = 1
certIds              = {}          -- no cert from round −1 (doesn't exist)
latestCertSeen       = cert for round 0
latestCertOnChain    = Origin      -- no cert on chain yet
perasParams._A       = 10          -- cert valid for 10 rounds
```

Expected (per CIP-0140): `IncludeCert` — all three conditions are satisfied.

Actual (buggy code):

1. `noCertsFromTwoRoundsAgo`: `currRoundNo (1) < 2` → returns `Bool False`.
2. `needCertRules` short-circuits on the first `False`.
3. `needCert` returns `DoNotIncludeCert`.

The certificate is never embedded. The chain-selection boost for round 0 is permanently lost. [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L159-167)
```haskell
-- | Evaluate whether we need to include a certificate in the block we are building.
needCert ::
  PerasCertInclusionView cert blk ->
  PerasCertInclusionRulesDecision cert
needCert pciv =
  evalPred (needCertRules pciv) $ \e ->
    case e of
      ETrue{} -> IncludeCert e (lcsCert (latestCertSeen pciv))
      EFalse{} -> DoNotIncludeCert e
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L246-263)
```haskell
noCertsFromTwoRoundsAgo
  PerasCertInclusionView
    { currRoundNo
    , certIds
    }
    -- We cannot have possibly seen a certificate from two rounds ago if we are
    -- in round 0 or 1. In that case, this is vacuously false.
    | currRoundNo < 2 =
        NoCertsFromTwoRoundsAgo currRoundNo
          := Bool False
    -- If we are in round 2 or higher, check whether our certificate snapshot
    -- contains a certificate from two rounds ago.
    | otherwise =
        NoCertsFromTwoRoundsAgo currRoundNo
          := Not (Bool containsCertFromTwoRoundsAgo)
   where
    containsCertFromTwoRoundsAgo =
      (currRoundNo - 2) `Set.member` certIds
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L318-324)
```haskell
needCertRules ::
  PerasCertInclusionView cert blk ->
  Pred PerasCertInclusionRule
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
```

**File:** ouroboros-consensus/test/consensus-test/Test/Consensus/Peras/Cert/Inclusion.hs (L109-112)
```haskell
    noCertsFromTwoRoundsAgo =
      if currRoundNo < 2
        then False
        else not ((currRoundNo - 2) `Set.member` certIds)
```
