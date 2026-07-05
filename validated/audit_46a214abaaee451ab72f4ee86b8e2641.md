### Title
Inverted Boolean in `noCertsFromTwoRoundsAgo` Permanently Suppresses Peras Certificate Inclusion in Rounds 0 and 1 - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs`)

### Summary

`noCertsFromTwoRoundsAgo` returns `Bool False` when `currRoundNo < 2`, but the predicate's own semantics require `Bool True` in that case. Because this predicate is the first conjunct in `needCertRules`, the conjunction short-circuits to `False` for every block forged in Peras rounds 0 and 1, causing `needCert` to unconditionally return `DoNotIncludeCert`. Peras certificates that should be included on-chain during the protocol's initial rounds are silently dropped by every honest block producer.

### Finding Description

`noCertsFromTwoRoundsAgo` is a predicate that is supposed to evaluate to `True` when the node has **not** seen a certificate from two rounds ago — one of three conditions that must all hold before a certificate is embedded in a newly forged block.

```haskell
-- noCertsFromTwoRoundsAgo: we haven't seen a certificate from two rounds ago
noCertsFromTwoRoundsAgo
  PerasCertInclusionView { currRoundNo, certIds }
    -- We cannot have possibly seen a certificate from two rounds ago if we are
    -- in round 0 or 1. In that case, this is vacuously false.
    | currRoundNo < 2 =
        NoCertsFromTwoRoundsAgo currRoundNo
          := Bool False          -- ← BUG: should be Bool True
    | otherwise =
        NoCertsFromTwoRoundsAgo currRoundNo
          := Not (Bool containsCertFromTwoRoundsAgo)
``` [1](#0-0) 

When `currRoundNo < 2` there are no negative-numbered rounds, so it is **impossible** to have seen a certificate from two rounds ago. The predicate "we haven't seen a cert from two rounds ago" is therefore vacuously **true**, not false. The comment itself acknowledges this impossibility ("we cannot have possibly seen a certificate from two rounds ago") yet assigns `Bool False`, which is the opposite of the correct value.

Because `needCertRules` is a conjunction:

```haskell
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
``` [2](#0-1) 

and `evalPred` short-circuits on the first `False` conjunct:

```haskell
a :/\: b ->
  case go a of
    Left a' -> Left a'   -- short-circuit
    ...
``` [3](#0-2) 

`needCert` will always produce `DoNotIncludeCert` for rounds 0 and 1, regardless of whether the other two conditions are satisfied. [4](#0-3) 

The test model in `Test/Consensus/Peras/Cert/Inclusion.hs` replicates the same wrong value:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then False          -- ← same bug in the model
    else not ((currRoundNo - 2) `Set.member` certIds)
``` [5](#0-4) 

Because the conformance test `prop_needCert` compares the implementation against this model, the test passes even though both are wrong, masking the defect entirely. [6](#0-5) 

### Impact Explanation

**Impact: Medium.**

Peras certificates are the mechanism by which the Peras protocol boosts chain selection and provides faster settlement. `needCert` is the production gate that decides whether a certificate is embedded in a forged block. With the inverted boolean, every honest block producer silently omits certificates during rounds 0 and 1 of the Peras protocol. Any certificate produced in those rounds is never anchored on-chain, materially weakening the Peras settlement guarantees for the protocol's initial window and creating a gap that an adversary aware of the defect can exploit to mount a chain-reorganisation attack that Peras certificates would otherwise prevent.

This falls within: *"Medium. Public node API or miniprotocol flaw … that materially weakens block, transaction, vote, certificate, or state-query authorization without relying on DoS."*

### Likelihood Explanation

**Likelihood: High.**

Every Peras-enabled Cardano node passes through rounds 0 and 1 exactly once, at protocol start. The condition `currRoundNo < 2` is deterministic and always fires during those rounds. No special attacker capability is required; the bug triggers automatically for all honest block producers.

### Recommendation

Change `Bool False` to `Bool True` in the `currRoundNo < 2` branch of `noCertsFromTwoRoundsAgo`:

```haskell
    | currRoundNo < 2 =
        NoCertsFromTwoRoundsAgo currRoundNo
          := Bool True   -- vacuously true: no certs from two rounds ago can exist
```

Update the test model in `Test/Consensus/Peras/Cert/Inclusion.hs` correspondingly:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then True
    else not ((currRoundNo - 2) `Set.member` certIds)
```

### Proof of Concept

1. Construct a `PerasCertInclusionView` with `currRoundNo = 0` or `currRoundNo = 1`, a non-empty `certIds`, a non-expired `latestCertSeen`, and `latestCertOnChain = Origin`.
2. Call `needCert` on this view.
3. Observe that the result is always `DoNotIncludeCert` with the short-circuit evidence pointing to `NoCertsFromTwoRoundsAgo := Bool False`, even though all other conditions are satisfied and a certificate should be included.
4. Manually evaluate `needCertRules`: `noCertsFromTwoRoundsAgo` returns `Bool False` → conjunction short-circuits → `evalPred` returns `EFalse` → `needCert` returns `DoNotIncludeCert`. [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L160-167)
```haskell
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
