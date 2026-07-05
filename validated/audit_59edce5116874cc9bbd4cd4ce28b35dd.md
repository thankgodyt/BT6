### Title
Stub `validatePerasCert` Unconditionally Accepts All Peer-Supplied Peras Certificates, Enabling Unauthorized Chain-Weight Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance ships a deliberately incomplete `validatePerasCert` that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural checks. This stub is wired directly into the production inbound-certificate pipeline (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can therefore inject arbitrary Peras certificates that boost any block of their choosing, causing the victim node's chain-selection logic to assign inflated weight to an adversarially chosen chain fragment.

---

### Finding Description

**Root cause — stub validation that always succeeds**

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must approve a certificate before it is stored and used in chain selection. The only concrete instance in the codebase is the "degenerate" catch-all:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [1](#0-0) 

No signature, round-number range, boosted-block existence, or committee-membership check is performed. Every certificate is immediately wrapped in `ValidatedPerasCert` and returned as `Right`.

**Production wiring — stub is the live validator**

`makePerasCertPoolWriterFromChainDB` (the production writer used by the object-diffusion mini-protocol) passes this stub directly as the `validateCert` argument to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate; if all pass (they always do), each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Chain-selection consequence**

`ChainDB.addPerasCertAsync` feeds the certificate into `chainSelSync`, which reads the `PerasWeightSnapshot` derived from all stored certificates and uses it to re-evaluate whether a candidate chain is now heavier than the current selection: [4](#0-3) 

The weight boost (`perasWeight params = PerasWeight 15`) is applied to whichever block the attacker names in `pcCertBoostedBlock`, regardless of whether that block was legitimately certified by a quorum of stake holders.

---

### Impact Explanation

An unprivileged peer connected via the Peras object-diffusion mini-protocol can craft a `PerasCert` naming any block point and any round number. Because `validatePerasCert` never rejects, the certificate is stored and its boost is immediately reflected in `getPerasWeightSnapshot`. Chain selection then compares candidate chains using these inflated weights. A sufficiently large boost (or a sequence of fake certificates across multiple rounds) can cause the victim node to switch to, and remain on, a chain that would otherwise be non-preferred — a direct violation of the Ouroboros chain-selection security invariant. This matches the **High** impact category: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is active in the production codebase and reachable by any peer that connects to the node. No privileged keys, stake majority, or operator access are required. The attacker only needs to send a well-formed `PerasCert` CBOR message (the serialisation instance is public). The stub is the only instance in the codebase, so there is no era or configuration flag that activates a real validator.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS/KES signature against the claimed committee members.
2. That the claimed voters collectively hold sufficient stake to meet the quorum threshold.
3. That `pcCertRound` falls within the acceptable window relative to the current slot.
4. That `pcCertBoostedBlock` refers to a block that is actually present in the node's volatile or immutable DB.

Until a real implementation is available, the inbound certificate pipeline should refuse all peer-supplied certificates (return a hard error rather than silently accepting them) so that the stub cannot be exploited.

---

### Proof of Concept

1. Connect to a victim node as a normal peer via the Peras object-diffusion mini-protocol.
2. Craft a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of an adversarial block on a fork>`.
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })`.
4. The certificate is forwarded to `ChainDB.addPerasCertAsync`. `chainSelSync` adds it to `PerasCertDB` and recomputes the weight snapshot.
5. The adversarial block now carries a `PerasWeight 15` boost. If the adversarial fork's total weight (block count × 1 + boost) exceeds the honest chain's weight, the victim node switches to the adversarial fork.
6. Repeat with additional fake certificates to maintain the boost across rounds, keeping the victim permanently on the adversarial chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasValidationErr blk
    = PerasValidationErr
    deriving stock (Show, Eq)

  -- TODO: enrich with actual error types
  -- see https://github.com/tweag/cardano-peras/issues/120
  data PerasForgeErr blk
    = PerasForgeErr
    deriving stock (Show, Eq)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-510)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
```
