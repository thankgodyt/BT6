### Title
`validatePerasCert` Unconditionally Accepts Any Certificate, Bypassing Peras Vote/Certificate Validation and Enabling Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. Because this function is the sole gate used by the network-facing Peras certificate ingest path (`makePerasCertPoolWriterFromChainDB`), any unprivileged peer can inject an arbitrarily crafted `PerasCert` that will be accepted, stored in `PerasCertDB`, and used to boost a block of the attacker's choosing during chain selection.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the universal `BlockSupportsPeras` instance (lines 318–389) provides the only deployed implementation of `validatePerasCert`:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

This function ignores every field of `cert` and always returns `Right`. There is no check of:
- the certificate's round number against the current epoch/round,
- the aggregate vote signature,
- voter eligibility or committee membership,
- the boosted block's existence or validity, or
- any quorum threshold.

The network-facing writer, `makePerasCertPoolWriterFromChainDB` (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`, lines 113–137), passes this stub directly as the validation function:

```haskell
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
```

`processCerts` (lines 156–185 of the same file) calls `validateCert` on every inbound certificate; because `validatePerasCert` always returns `Right`, every certificate passes and is timestamped and forwarded to `ChainDB.addPerasCertAsync`.

Once stored in `PerasCertDB`, the certificate is incorporated into the `PerasWeightSnapshot` used by `weightedSelectView` (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs`, lines 94–112) to compute `wsvWeightBoost` and `wsvTotalWeight`. Chain selection in `chainSelection` (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs`, lines 1111–1184) then uses `preferAnchoredCandidate` with these boosted weights to decide whether to switch chains.

The same stub problem exists for `validatePerasVote` (lines 360–371), which skips all signature verification and only checks stake-distribution membership.

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` that names any block as the boosted target. Because `validatePerasCert` never rejects anything, the certificate is accepted, stored, and applied to chain selection. The attacker can:

1. **Boost a block on a minority fork** to give it a `wsvTotalWeight` exceeding the honest chain, causing the victim node to switch to the attacker's fork.
2. **Repeatedly inject certificates** for different blocks to destabilize chain selection, causing repeated rollbacks up to `k` blocks.
3. **Boost the Genesis point** (handled as a special case in `chainSelSync` but only after the certificate is already stored).

This constitutes a bypass of Peras certificate/vote validation that enables unauthorized certificate acceptance and chain-selection manipulation — matching the "Critical: Bypass of Peras voting or certificate checks" and "High: Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact categories.

---

### Likelihood Explanation

The attack requires only a network connection to the target node. No stake, no keys, and no privileged access are needed. The object-diffusion mini-protocol for Peras certificates is reachable from any peer. The stub is the **only** deployed implementation (the universal instance covers all `StandardHash blk` types, including Cardano blocks), and the TODO comments confirm no real validation has been wired in yet.

---

### Recommendation

Replace the stub `validatePerasCert` (and `validatePerasVote`) with implementations that perform full cryptographic and structural validation before any certificate or vote is stored or used in chain selection:

1. Verify the aggregate vote signature against the claimed committee members' public keys.
2. Check voter eligibility and committee membership for the certificate's round.
3. Verify the quorum threshold is met by the attesting stake.
4. Validate the certificate's round number against the current epoch/round context.
5. Confirm the boosted block exists and is within the valid age window (`perasCertMaxRounds`).

Until real validation is implemented, the Peras certificate ingest path should be disabled or gated behind a feature flag that is off by default, preventing untrusted peers from injecting certificates that influence chain selection.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Unprivileged peer
  → object-diffusion mini-protocol (PerasCert channel)
  → makePerasCertPoolWriterFromChainDB  [PerasCert.hs:118]
  → processCerts ... (validatePerasCert mkPerasParams) ...  [PerasCert.hs:126]
  → validatePerasCert params cert = Right ValidatedPerasCert{...}  [SupportsPeras.hs:353]
  → ChainDB.addPerasCertAsync chainDB cert  [PerasCert.hs:132]
  → PerasCertDB.addCert  [PerasCertDB/Impl.hs:169]
  → PerasWeightSnapshot updated with boosted block
  → chainSelection uses wsvTotalWeight including attacker-supplied boost
  → node switches to attacker's fork
```

**Crafted certificate (Haskell pseudocode):**

```haskell
-- Attacker constructs a certificate boosting a block on a minority fork
let craftedCert = PerasCert
      { pcCertRound    = someRoundNo   -- any round
      , pcCertBoostedBlock = forkTipPoint  -- attacker's fork tip
      }
-- Send via object-diffusion protocol; validatePerasCert returns Right unconditionally
-- The node's chain selection now sees forkTipPoint with perasWeight boost added
-- If boost > (honestChainLength - forkLength), node switches to fork
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-358)
```haskell
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- certs to the ChainDB and ignore the returned promise.
          -- The async action is still launched and executed behind the scenes
          -- even though we drop the promise.
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L94-112)
```haskell
weightedSelectView ::
  ( GetHeader1 h
  , HasHeader (h blk)
  , HeaderHash blk ~ HeaderHash (h blk)
  , BlockSupportsProtocol blk
  ) =>
  BlockConfig blk ->
  PerasWeightSnapshot blk ->
  AnchoredFragment (h blk) ->
  WithEmptyFragment (WeightedSelectView (BlockProtocol blk))
weightedSelectView bcfg weights = \case
  AF.Empty{} -> EmptyFragment
  frag@(_ AF.:> (getHeader1 -> hdr)) ->
    NonEmptyFragment
      WeightedSelectView
        { wsvBlockNo = blockNo hdr
        , wsvWeightBoost = weightBoostOfFragment weights frag
        , wsvTiebreaker = tiebreakerView bcfg hdr
        }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1127-1138)
```haskell
chainSelection chainSelEnv chainDiffs onSuccess =
  assert
    ( all
        (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . Diff.getSuffix . fst)
        chainDiffs
    )
    $ assert
      ( all
          (isJust . Diff.apply curChain . fst)
          chainDiffs
      )
    $ go (sortCandidates (NE.toList chainDiffs))
```
