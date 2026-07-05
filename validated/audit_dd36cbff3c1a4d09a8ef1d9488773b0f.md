### Title
Inverted Boolean in `noCertsFromTwoRoundsAgo` Silently Suppresses Peras Certificate Inclusion During Bootstrapping Rounds — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs`)

---

### Summary

The `noCertsFromTwoRoundsAgo` predicate in the Peras certificate inclusion logic returns a hardcoded `Bool False` when `currRoundNo < 2`, but the correct value is `Bool True` (vacuously true). Because `needCertRules` is a conjunction of all three inclusion predicates, this inverted constant causes `needCert` to unconditionally return `DoNotIncludeCert` during Peras rounds 0 and 1, silently suppressing all valid certificate inclusions during the Peras bootstrapping phase.

---

### Finding Description

In `Ouroboros.Consensus.Peras.Cert.Inclusion`, the function `noCertsFromTwoRoundsAgo` is intended to check that the node has not already seen a certificate from two rounds ago (which would make including a new one redundant). When `currRoundNo < 2`, two rounds ago does not exist, so the predicate should be **vacuously true** — there are definitionally no certificates from two rounds ago. Instead, the code returns `Bool False`:

```haskell
-- ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs
noCertsFromTwoRoundsAgo
  PerasCertInclusionView { currRoundNo, certIds }
    -- We cannot have possibly seen a certificate from two rounds ago if we are
    -- in round 0 or 1. In that case, this is vacuously false.   <-- comment is wrong
    | currRoundNo < 2 =
        NoCertsFromTwoRoundsAgo currRoundNo
          := Bool False                                           <-- should be Bool True
    | otherwise =
        NoCertsFromTwoRoundsAgo currRoundNo
          := Not (Bool containsCertFromTwoRoundsAgo)
``` [1](#0-0) 

The comment itself acknowledges the confusion: it says "vacuously false" but the correct logical term for a condition that holds because its antecedent is impossible is "vacuously **true**."

This predicate feeds directly into `needCertRules`, which is a pure conjunction (`:/\:`):

```haskell
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
``` [2](#0-1) 

Because `Bool False` short-circuits the conjunction, `needCert` always returns `DoNotIncludeCert` for rounds 0 and 1, regardless of whether the other two conditions (`latestCertSeenIsNotExpired`, `latestCertSeenIsNewerThanLatestCertOnChain`) are satisfied. [3](#0-2) 

The test model in `Test/Consensus/Peras/Cert/Inclusion.hs` replicates the same incorrect logic:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then False                                                    -- same bug
    else not ((currRoundNo - 2) `Set.member` certIds)
``` [4](#0-3) 

Because the test model mirrors the production bug, the `prop_needCert` property test passes, masking the defect entirely.

---

### Impact Explanation

The Peras protocol boosts chain weight by including certificates in blocks. `needCert` is the gate that decides whether a forging node must embed a certificate in the block it is building. With `noCertsFromTwoRoundsAgo` returning `False` for rounds 0 and 1, no certificate is ever included during those rounds, even when one is available and all other inclusion conditions are met.

This breaks the Peras protocol's certificate inclusion invariant during the bootstrapping phase: the chain does not accumulate the weight boost that the protocol specification requires, causing chain selection to deviate from the intended Peras security model. An adversary aware of this gap could time a competing fork to exploit the missing weight boost during rounds 0 and 1, making honest nodes prefer a less-boosted (and thus less-secure) chain.

This matches the **High** impact category: a chain-selection bug that causes honest nodes to operate outside the intended security assumptions of the Peras protocol.

---

### Likelihood Explanation

The bug fires **deterministically** for every block forged during Peras rounds 0 and 1. No attacker action is required; the condition `currRoundNo < 2` is a pure function of the current round number. Every Peras-enabled node will silently suppress certificate inclusion during the bootstrapping phase. The masking test model means the defect is not caught by the existing property-based test suite.

---

### Recommendation

Change `Bool False` to `Bool True` in the `currRoundNo < 2` branch of `noCertsFromTwoRoundsAgo`, and update the comment to reflect the correct reasoning:

```haskell
-- We cannot have possibly seen a certificate from two rounds ago if we are
-- in round 0 or 1. In that case, this is vacuously TRUE.
| currRoundNo < 2 =
    NoCertsFromTwoRoundsAgo currRoundNo
      := Bool True
``` [5](#0-4) 

The same correction must be applied to the test model in `Test/Consensus/Peras/Cert/Inclusion.hs`:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then True   -- vacuously true: no round (currRoundNo - 2) exists
    else not ((currRoundNo - 2) `Set.member` certIds)
``` [4](#0-3) 

---

### Proof of Concept

1. Construct a `PerasCertInclusionView` with `currRoundNo = 0` or `currRoundNo = 1`, a valid `latestCertSeen` (not expired), and `latestCertOnChain = Origin` (so `latestCertSeenIsNewerThanLatestCertOnChain` is trivially `True`).
2. Call `needCert` on this view.
3. Observe that the result is always `DoNotIncludeCert`, even though both `latestCertSeenIsNotExpired` and `latestCertSeenIsNewerThanLatestCertOnChain` evaluate to `True`.
4. The root cause is `noCertsFromTwoRoundsAgo` returning `Bool False` unconditionally for `currRoundNo < 2`, short-circuiting the conjunction in `needCertRules` before the other predicates are consulted. [6](#0-5)

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

**File:** ouroboros-consensus/test/consensus-test/Test/Consensus/Peras/Cert/Inclusion.hs (L109-112)
```haskell
    noCertsFromTwoRoundsAgo =
      if currRoundNo < 2
        then False
        else not ((currRoundNo - 2) `Set.member` certIds)
```
