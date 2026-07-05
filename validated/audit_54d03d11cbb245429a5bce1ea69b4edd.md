### Title
Wrong Vacuous Truth Value in `noCertsFromTwoRoundsAgo` Permanently Blocks Peras Certificate Inclusion in Rounds 0 and 1 — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs`)

---

### Summary

The `noCertsFromTwoRoundsAgo` predicate in `Peras/Cert/Inclusion.hs` returns `Bool False` (instead of `Bool True`) for the vacuous case when `currRoundNo < 2`. Because `needCertRules` is a pure conjunction of three predicates, this single `False` short-circuits the entire conjunction, causing `needCert` to unconditionally return `DoNotIncludeCert` in rounds 0 and 1. No Peras certificate can ever be included in a block during those rounds, violating CIP-0140. The test-model in the property test carries the identical bug, so `prop_needCert` does not detect the defect.

---

### Finding Description

`noCertsFromTwoRoundsAgo` is one of three sub-predicates in the `needCertRules` conjunction that governs Peras certificate inclusion:

```haskell
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
``` [1](#0-0) 

The predicate is supposed to check that no certificate from two rounds ago is present in the node's certificate database. When `currRoundNo < 2` (rounds 0 and 1), rounds −2 and −1 do not exist, so the database cannot possibly contain a certificate from two rounds ago. The condition "no certs from two rounds ago" is therefore **vacuously true**. The code, however, returns `Bool False` and labels this "vacuously false":

```haskell
| currRoundNo < 2 =
    NoCertsFromTwoRoundsAgo currRoundNo
      := Bool False   -- BUG: should be Bool True
``` [2](#0-1) 

Because `:/\:` short-circuits on the first `False`, the entire `needCertRules` predicate evaluates to `False` whenever `currRoundNo < 2`, and `needCert` always returns `DoNotIncludeCert`: [3](#0-2) 

The property-test model in `Test/Consensus/Peras/Cert/Inclusion.hs` replicates the same wrong value:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then False   -- BUG: same wrong value as the implementation
    else not ((currRoundNo - 2) `Set.member` certIds)
``` [4](#0-3) 

Because both the implementation and the model agree on the wrong answer, `prop_needCert` passes and provides no protection against this defect. [5](#0-4) 

---

### Impact Explanation

The Peras protocol's chain-boost security guarantee depends on certificates being included in blocks. `needCert` is the sole gate that decides whether a block producer embeds a certificate. With the bug, no certificate is ever embedded in rounds 0 and 1, regardless of whether all other inclusion conditions (`latestCertSeenIsNotExpired`, `latestCertSeenIsNewerThanLatestCertOnChain`) are satisfied.

Concretely, in round 1 a node that has received a valid round-0 certificate (i.e., `latestCertSeen = NotOrigin cert`) will construct a `PerasCertInclusionView` successfully (the `mkPerasCertInclusionView` guard only rejects `Origin`), call `needCert`, and receive `DoNotIncludeCert` due to the bug. The block it forges omits the certificate, so the Peras chain boost is not applied. Nodes with a correct implementation that do include the certificate produce a more-preferred chain, causing honest nodes running this code to permanently diverge from the canonical chain during the Peras bootstrapping phase. This breaks the cross-era Peras protocol invariant mandated by CIP-0140 and constitutes a ledger-invariant violation for production Cardano nodes.

**Impact class**: High — hard-fork/era-transition/protocol-invariant mismatch that breaks cross-era consensus for production Cardano nodes.

---

### Likelihood Explanation

The defective branch is taken unconditionally whenever `currRoundNo < 2`. Every Peras-enabled node will pass through rounds 0 and 1 exactly once at Peras activation. The trigger requires no adversarial input; it is a deterministic consequence of normal protocol operation. Any node that has seen a certificate in round 0 and attempts to include it in a round-1 block will silently omit it.

---

### Recommendation

Change `Bool False` to `Bool True` in the vacuous branch of `noCertsFromTwoRoundsAgo`:

```haskell
-- We cannot have possibly seen a certificate from two rounds ago if we are
-- in round 0 or 1. In that case, this is vacuously TRUE.
| currRoundNo < 2 =
    NoCertsFromTwoRoundsAgo currRoundNo
      := Bool True
``` [6](#0-5) 

Apply the same correction to the test model:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then True   -- vacuously true
    else not ((currRoundNo - 2) `Set.member` certIds)
``` [4](#0-3) 

---

### Proof of Concept

1. Construct a `PerasCertInclusionView` with `currRoundNo = 1`, a non-`Origin` `latestCertSeen` (e.g., a certificate from round 0), `latestCertOnChain = Origin`, and an empty `certIds`.
2. All three sub-predicates should evaluate to `True` under the correct semantics:
   - `noCertsFromTwoRoundsAgo`: vacuously true (round −1 does not exist)
   - `latestCertSeenIsNotExpired`: true if `_A ≥ 1`
   - `latestCertSeenIsNewerThanLatestCertOnChain`: true because `latestCertOnChain = Origin`
3. Call `needCert` on this view.
4. **Observed**: `DoNotIncludeCert` — the certificate is silently dropped.
5. **Expected**: `IncludeCert` — the certificate should be embedded in the block.

The block forged from this view omits the Peras certificate, violating CIP-0140 §Block-Creation and losing the chain boost for round 0's certificate. [3](#0-2) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L316-324)
```haskell
-- | We need to include a certificate in the block we are building if all the
-- rules in this conjunction are satisfied.
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

**File:** ouroboros-consensus/test/consensus-test/Test/Consensus/Peras/Cert/Inclusion.hs (L133-179)
```haskell
prop_needCert :: Property
prop_needCert = forAll genPerasCertInclusionView $ \pciv -> do
  -- Determine whether we should include a cert according to the model
  let PerasCertInclusionDecisionModel
        { shouldIncludeCert
        , noCertsFromTwoRoundsAgo
        , latestCertSeenIsNotExpired
        , latestCertSeenIsNewerThanLatestCertOnChain
        } =
          needCertModel pciv
  -- Some helper functions to report success/failure
  let chain = flip (foldr ($)) . reverse
  let ok desc =
        chain
          [ tabulate "NoCertsFromTwoRoundsAgo" [show noCertsFromTwoRoundsAgo]
          , tabulate "LatestCertSeenIsNotExpired" [show latestCertSeenIsNotExpired]
          , tabulate
              "LatestCertSeenIsNewerThanLatestCertOnChain"
              [show latestCertSeenIsNewerThanLatestCertOnChain]
          , tabulate
              "NoCertsFromTwoRoundsAgo|LatestCertSeenIsNotExpired|LatestCertSeenIsNewerThanLatestCertOnChain"
              [ show
                  ( noCertsFromTwoRoundsAgo
                  , latestCertSeenIsNotExpired
                  , latestCertSeenIsNewerThanLatestCertOnChain
                  )
              ]
          , tabulate "Should include cert according to model" [show shouldIncludeCert]
          , tabulate "Actual result" [desc]
          ]
          $ property True
  let failure desc =
        counterexample desc $
          property False
  -- Now check that the real implementation agrees with the model
  let certInclusionDecision = needCert pciv
  case certInclusionDecision of
    IncludeCert (ETrue _includeCertReason) _cert
      | shouldIncludeCert ->
          ok $ certInclusionDecisionTag certInclusionDecision
      | otherwise ->
          failure $ "Expected not to include cert, but got: " <> show certInclusionDecision
    DoNotIncludeCert (EFalse _doNotIncludeCertReason)
      | not shouldIncludeCert ->
          ok $ certInclusionDecisionTag certInclusionDecision
      | otherwise ->
          failure $ "Expected to include cert, but got: " <> show certInclusionDecision
```
