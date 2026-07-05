### Title
Inverted `noCertsFromTwoRoundsAgo` Guard Silently Suppresses Peras Certificate Inclusion in Rounds 0 and 1 - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs`)

### Summary

`noCertsFromTwoRoundsAgo` in `Ouroboros.Consensus.Peras.Cert.Inclusion` returns `Bool False` when `currRoundNo < 2`, but the correct value is `Bool True`. Because this predicate is the first conjunct of `needCertRules`, the entire conjunction short-circuits to `False` in rounds 0 and 1, causing `needCert` to always return `DoNotIncludeCert` during those rounds. Block producers therefore never embed a Peras certificate in any block produced in rounds 0 or 1, violating CIP-0140 and silently disabling the Peras chain-selection boost for the opening rounds of every Peras epoch.

### Finding Description

`needCertRules` is the conjunction that governs whether a block producer must embed a Peras certificate:

```haskell
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
```

The first conjunct is implemented as:

```haskell
noCertsFromTwoRoundsAgo
  PerasCertInclusionView{ currRoundNo, certIds }
  -- We cannot have possibly seen a certificate from two rounds ago if we are
  -- in round 0 or 1. In that case, this is vacuously false.
  | currRoundNo < 2 =
      NoCertsFromTwoRoundsAgo currRoundNo
        := Bool False          -- ← BUG: should be Bool True
  | otherwise =
      NoCertsFromTwoRoundsAgo currRoundNo
        := Not (Bool containsCertFromTwoRoundsAgo)
```

The comment itself states the correct reasoning: *"we cannot have possibly seen a certificate from two rounds ago"* when `currRoundNo < 2`. That means the predicate **"no certs from two rounds ago"** is vacuously **true** — there are no rounds −2 or −1 from which a certificate could exist. The code, however, returns `Bool False`, which is the opposite of the correct value.

Because `evalPred` short-circuits a conjunction on the first `False` branch, `needCert` always returns `DoNotIncludeCert` in rounds 0 and 1, regardless of whether the other two conditions (`latestCertSeenIsNotExpired`, `latestCertSeenIsNewerThanLatestCertOnChain`) are satisfied.

The test model in `Test.Consensus.Peras.Cert.Inclusion` replicates the same wrong value:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then False          -- ← same bug in the model
    else not ((currRoundNo - 2) `Set.member` certIds)
```

Because both the production predicate and the reference model share the same incorrect constant, `prop_needCert` passes despite the bug — the test only verifies internal consistency between two identically-wrong implementations, not conformance to the CIP-0140 specification.

### Impact Explanation

**High — Chain-selection bug that weakens Peras security beyond intended assumptions.**

Peras certificates are the mechanism by which the protocol boosts chain selection: a block carrying a certificate for round `r` receives additional weight, making it harder for an adversary to fork the chain at that point. CIP-0140 requires that a block producer include a certificate whenever all three inclusion rules are satisfied, including in rounds 0 and 1.

With this bug, no certificate is ever embedded in a block during rounds 0 and 1. An adversary who knows this (the code is open-source) can present a competing fork during those rounds knowing that honest nodes will evaluate chain selection using only the base Praos weight, without the Peras boost. This is precisely the scenario the Peras boost is designed to prevent. The adversary does not need any special privilege — they only need to produce a competing chain fragment during the affected rounds, which is the standard Praos adversarial model.

### Likelihood Explanation

**High.** The condition `currRoundNo < 2` is triggered deterministically at the start of every Peras epoch (rounds 0 and 1 occur unconditionally). Any deployment of Peras will hit this code path. The bug is silent — no error is raised, no log is emitted, and the existing test suite passes because the reference model carries the same defect.

### Recommendation

Change `Bool False` to `Bool True` in the `currRoundNo < 2` branch of `noCertsFromTwoRoundsAgo`:

```haskell
  | currRoundNo < 2 =
      NoCertsFromTwoRoundsAgo currRoundNo
        := Bool True   -- vacuously true: no rounds -2 or -1 exist
```

Fix the corresponding line in the test model (`needCertModel` in `Test.Consensus.Peras.Cert.Inclusion`):

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then True          -- vacuously true
    else not ((currRoundNo - 2) `Set.member` certIds)
```

### Proof of Concept

Concrete input that demonstrates the wrong decision:

```
currRoundNo  = 1
certIds      = {}          -- no certs in DB (consistent with round 1)
latestCertSeen = cert with round 0
latestCertOnChain = Origin -- no cert on chain yet
_A (perasCertMaxRounds) = 10
```

Expected per CIP-0140:
- `noCertsFromTwoRoundsAgo` → **True** (round −1 does not exist)
- `latestCertSeenIsNotExpired` → **True** (1 ≤ 10 + 0)
- `latestCertSeenIsNewerThanLatestCertOnChain` → **True** (Origin case)
- `needCert` → **IncludeCert**

Actual with the bug:
- `noCertsFromTwoRoundsAgo` → **False** (hardcoded `Bool False`)
- Conjunction short-circuits → `needCert` → **DoNotIncludeCert**

The certificate is silently dropped; the block is produced without it; the Peras chain-selection boost for round 0 is lost.

---

**Root cause file:** `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs`, lines 253–255 [1](#0-0) 

**Mirrored defect in test model:** `ouroboros-consensus/test/consensus-test/Test/Consensus/Peras/Cert/Inclusion.hs`, lines 109–112 [2](#0-1) 

**Conjunction entry point:** `needCertRules`, lines 318–324 [3](#0-2)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L251-260)
```haskell
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
