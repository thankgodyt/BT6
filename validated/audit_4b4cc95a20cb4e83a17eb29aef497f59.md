### Title
Inverted Boolean Guard in `noCertsFromTwoRoundsAgo` Permanently Blocks Peras Certificate Inclusion in Rounds 0 and 1 - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs`)

---

### Summary

The `noCertsFromTwoRoundsAgo` predicate in the Peras certificate inclusion logic returns `Bool False` when `currRoundNo < 2`, but the correct value is `Bool True` (vacuously — no certificate from two rounds ago can exist when the protocol has not yet reached round 2). Because `needCertRules` is a strict conjunction, this single `False` short-circuits the entire rule, causing `needCert` to always return `DoNotIncludeCert` in Peras rounds 0 and 1. The test model in the companion test file mirrors the same inverted constant, so the existing property test does not detect the defect.

---

### Finding Description

**Root cause — production file:**

`noCertsFromTwoRoundsAgo` is supposed to evaluate to `True` when the node has not seen a certificate from two rounds ago. For rounds 0 and 1 this condition is vacuously satisfied (round −2 and round −1 do not exist), so the predicate should return `Bool True`. Instead the code returns `Bool False`:

```haskell
-- We cannot have possibly seen a certificate from two rounds ago if we are
-- in round 0 or 1. In that case, this is vacuously false.   ← comment is wrong
| currRoundNo < 2 =
    NoCertsFromTwoRoundsAgo currRoundNo
      := Bool False                                           ← should be Bool True
``` [1](#0-0) 

The conjunction that drives the inclusion decision is:

```haskell
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
``` [2](#0-1) 

Because `evalPred` short-circuits on the first `False` in a conjunction, the `Bool False` returned for rounds 0 and 1 makes `needCert` unconditionally return `DoNotIncludeCert` for those rounds, regardless of whether the other two rules are satisfied. [3](#0-2) 

**Test model mirrors the bug:**

The conformance test in `Test/Consensus/Peras/Cert/Inclusion.hs` defines its own reference model that also returns `False` for `currRoundNo < 2`:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then False          -- ← same inverted constant
    else not ((currRoundNo - 2) `Set.member` certIds)
``` [4](#0-3) 

Because the implementation and the model agree on the wrong value, `prop_needCert` passes, providing false assurance. [5](#0-4) 

---

### Impact Explanation

Peras certificates are the mechanism by which the Peras protocol boosts chain selection weight. A block producer calls `needCert` to decide whether to embed a certificate in the block it is forging. With this bug, no certificate is ever embedded in any block produced during Peras rounds 0 and 1. This means:

1. The Peras chain-weight boost is entirely absent for the first two rounds of the protocol, breaking the protocol's fast-finality and chain-selection-security guarantees precisely at protocol start — the moment when the chain has the least accumulated weight and is most vulnerable to adversarial forks.
2. Any adversary aware of this defect can present a competing fork during rounds 0–1 knowing that the honest chain will carry no certificate boost, weakening the chain-selection advantage that Peras is designed to provide.

This maps to the allowed impact category: **High — Peras voting/certificate check bug that breaks cross-era consensus or ledger invariants for production Cardano nodes**, and **High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions**.

---

### Likelihood Explanation

The bug is deterministic and unconditional: every node running Peras will exhibit it in rounds 0 and 1 on every chain start or restart. No special attacker capability is required beyond knowing the protocol round number. The defect is masked by the test model carrying the same error, so it has not been caught by the existing test suite.

---

### Recommendation

In `noCertsFromTwoRoundsAgo`, change the early-exit branch from `Bool False` to `Bool True`:

```haskell
| currRoundNo < 2 =
    NoCertsFromTwoRoundsAgo currRoundNo
      := Bool True   -- vacuously true: no round (currRoundNo - 2) exists
```

Fix the companion comment to read "vacuously true" and apply the same correction to the reference model in `Test/Consensus/Peras/Cert/Inclusion.hs` (line 111: `then True`).

---

### Proof of Concept

Construct a `PerasCertInclusionView` with `currRoundNo = 0` (or `1`), a valid `latestCertSeen` from round 0, `latestCertOnChain = Origin`, and any non-expired `perasParams`. Evaluate `needCert`:

```haskell
let view = PerasCertInclusionView
      { perasParams            = someParams   -- _A >= 1
      , currRoundNo            = PerasRoundNo 0
      , latestCertSeen         = LatestCertSeenView cert (PerasRoundNo 0)
      , latestCertOnChain      = Origin       -- no cert on chain yet
      , certIds                = Set.empty
      }
-- latestCertSeenIsNotExpired:              0 <= _A + 0  => True
-- latestCertSeenIsNewerThanLatestCertOnChain: Origin    => True
-- noCertsFromTwoRoundsAgo:                currRoundNo < 2 => Bool False  ← BUG
result = needCert view
-- result = DoNotIncludeCert ...   (expected: IncludeCert ...)
```

The `DoNotIncludeCert` result is produced solely because `noCertsFromTwoRoundsAgo` returns `Bool False` instead of `Bool True`, directly analogous to the ZeroLendToken `require(!paused && !whitelisted[from])` pattern that blocks the privileged path due to an inverted boolean constant.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L251-255)
```haskell
    -- We cannot have possibly seen a certificate from two rounds ago if we are
    -- in round 0 or 1. In that case, this is vacuously false.
    | currRoundNo < 2 =
        NoCertsFromTwoRoundsAgo currRoundNo
          := Bool False
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
