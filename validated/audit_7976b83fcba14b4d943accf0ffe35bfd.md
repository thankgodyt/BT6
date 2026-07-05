### Title
`noCertsFromTwoRoundsAgo` Returns Wrong Boolean in Rounds 0 and 1, Suppressing Peras Certificate Inclusion When It Is Required - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs`)

---

### Summary

The `noCertsFromTwoRoundsAgo` predicate in the Peras certificate inclusion logic returns `Bool False` in rounds 0 and 1, with the comment "this is vacuously false." The comment and the return value are both semantically wrong: in rounds 0 and 1 there are no rounds two rounds prior, so the predicate "we haven't seen a certificate from two rounds ago" is vacuously **true**, not false. Because `needCertRules` is a conjunction, this incorrect `False` short-circuits the entire rule and suppresses certificate inclusion in rounds 0 and 1 even when all other conditions are satisfied. The test-model in the test file replicates the same wrong value, so the unit test passes while the bug persists undetected.

---

### Finding Description

`needCertRules` is the conjunction of three sub-predicates:

```haskell
needCertRules pciv =
  noCertsFromTwoRoundsAgo pciv
    :/\: latestCertSeenIsNotExpired pciv
    :/\: latestCertSeenIsNewerThanLatestCertOnChain pciv
``` [1](#0-0) 

The first sub-predicate is:

```haskell
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
``` [2](#0-1) 

The predicate name is `noCertsFromTwoRoundsAgo` — "there are no certificates from two rounds ago." In rounds 0 and 1 there are no rounds two rounds prior, so this statement is vacuously **true**. The code returns `False`, which is the opposite of the correct value. The comment compounds the error by calling it "vacuously false."

The test model in the test file mirrors the same wrong logic:

```haskell
noCertsFromTwoRoundsAgo =
  if currRoundNo < 2
    then False          -- ← same bug in the model
    else not ((currRoundNo - 2) `Set.member` certIds)
``` [3](#0-2) 

Because both the implementation and the model are wrong in the same way, `prop_needCert` passes, masking the defect.

The analog to the PuttyV2 report is exact:

| PuttyV2 | Ouroboros Consensus |

### Citations

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
