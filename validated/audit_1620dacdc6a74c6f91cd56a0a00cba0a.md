### Title
Inverted Boolean in `noCertsFromTwoRoundsAgo` Permanently Blocks Peras Certificate Inclusion in Rounds 0 and 1 - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs`)

---

### Summary

`noCertsFromTwoRoundsAgo` returns `Bool False` when `currRoundNo < 2`, but the correct value is `Bool True`. Because this predicate is the first conjunct in `needCertRules`, `evalPred` short-circuits to `DoNotIncludeCert` for every call to `needCert` in rounds 0 and 1, regardless of whether all other conditions are satisfied. No Peras certificate can ever be included in a block during the first two rounds of the protocol. The companion test model in `Test/Consensus/Peras/Cert/Inclusion.hs` carries the identical inversion, so `prop_needCert` passes and masks the defect.

---

### Finding Description

In `noCertsFromTwoRoundsAgo`:

```haskell
-- We cannot have possibly seen a certificate from two rounds ago if we are
-- in round 0 or 1. In that case, this is vacuously false.
| currRoundNo < 2 =
    NoCertsFromTwoRoundsAgo currRoundNo
      := Bool False          -- ← BUG: should be Bool True
``` [1](#0-0) 

The predicate is named `NoCertsFromTwoRoundsAgo` — it is `True` when the node has **not** seen a certificate from two rounds ago. In rounds 0 and 1, rounds −2 and −1 do not exist, so the condition is vacuously **true** (there are no certs from two rounds ago). The comment itself says "vacuously false", which is semantically wrong.

`needCertRules` is a conjunction of three predicates:

```haskell
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
``` [2](#0-1) 

`evalPred` short-circuits on the first `False` in a conjunction:

```haskell
a :/\: b ->
  case go a of
    Left a' -> Left a'   -- short-circuit
    ...
``` [3](#0-2) 

So `needCert` always returns `DoNotIncludeCert` in rounds 0 and 1, no matter what the other two conditions evaluate to.

The test model in `needCertModel` carries the identical inversion:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then False          -- ← same bug
    else not ((currRoundNo - 2) `Set.member` certIds)
``` [4](#0-3) 

Because `prop_needCert` compares the implementation against this model, the test passes and the defect is invisible to the test suite.

---

### Impact Explanation

`needCert` is the gate that block producers use to decide whether to embed a Peras certificate in the block they are forging. When it returns `DoNotIncludeCert`, no certificate is embedded, so no Peras weight boost is attached to that block.

In rounds 0 and 1 of Peras, every honest block producer is told never to include a certificate. Consequently:

- No block on the honest chain carries a Peras weight boost during those rounds.
- An adversary who forks the chain in rounds 0 or 1 faces no Peras-boosted competition; chain selection falls back to pure Praos weight.
- The adversary needs only enough Praos stake to outweigh the honest chain in those two rounds — a far lower bar than what Peras is designed to require.

This is a chain-selection bug that lets an unprivileged peer (one who simply withholds their own blocks until rounds 0–1 and then presents a heavier Praos fork) make an honest node prefer a less-secure chain, violating the Peras security assumptions for the protocol's initial rounds.

---

### Likelihood Explanation

The defect is deterministic and unconditional: every node running this code will exhibit it in rounds 0 and 1. An adversary who is aware of the bug can plan a fork attack timed to those rounds. The rounds are predictable (they are the first two rounds after Peras activates), so the attack window is known in advance. No special privileges, key compromise, or majority stake are required beyond what a standard Praos fork attack demands.

---

### Recommendation

Change `Bool False` to `Bool True` in the `currRoundNo < 2` branch of `noCertsFromTwoRoundsAgo`:

```haskell
| currRoundNo < 2 =
    NoCertsFromTwoRoundsAgo currRoundNo
      := Bool True   -- vacuously true: no cert from round -2 or -1 can exist
``` [5](#0-4) 

Fix the identical inversion in the test model:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then True   -- fix: vacuously true
    else not ((currRoundNo - 2) `Set.member` certIds)
``` [4](#0-3) 

Update the comment to read "vacuously true" and add a targeted unit test that asserts `needCert` can return `IncludeCert` when `currRoundNo ∈ {0, 1}` and the other two conditions hold.

---

### Proof of Concept

Construct a `PerasCertInclusionView` with `currRoundNo = 1`, a valid `latestCertSeen` from round 1, `latestCertOnChain = Origin` (no cert on chain yet), and `certIds = Set.empty`. All three conditions should be satisfied:

- `noCertsFromTwoRoundsAgo`: round −1 does not exist → should be `True`
- `latestCertSeenIsNotExpired`: cert from round 1 is not expired → `True`
- `latestCertSeenIsNewerThanLatestCertOnChain`: no cert on chain → `True`

Expected result: `IncludeCert`.
Actual result with current code: `DoNotIncludeCert` — because `noCertsFromTwoRoundsAgo` returns `Bool False`, short-circuiting the conjunction before the other two predicates are evaluated. [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L242-263)
```haskell
-- | noCertsFromTwoRoundsAgo: we haven't seen a certificate from two rounds ago
noCertsFromTwoRoundsAgo ::
  PerasCertInclusionView cert blk ->
  Pred PerasCertInclusionRule
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/Pred.hs (L158-164)
```haskell
    a :/\: b ->
      case go a of
        Left a' -> Left a' -- short-circuit
        Right a' ->
          case go b of
            Right b' -> Right (a' :/\: b')
            Left b' -> Left b'
```

**File:** ouroboros-consensus/test/consensus-test/Test/Consensus/Peras/Cert/Inclusion.hs (L109-112)
```haskell
    noCertsFromTwoRoundsAgo =
      if currRoundNo < 2
        then False
        else not ((currRoundNo - 2) `Set.member` certIds)
```
