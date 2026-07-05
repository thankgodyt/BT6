### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Forge Peras Certificates and Manipulate Chain Selection - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` — it accepts every inbound Peras certificate from every peer without performing any cryptographic verification. Because this is the only instance wired into the certificate inbound pipeline (`makePerasCertPoolWriterFromChainDB`), an unprivileged peer can send a crafted `PerasCert` boosting any block it chooses, causing the receiving node to apply an illegitimate weight boost to that block and potentially switch to a non-canonical chain.

### Finding Description

**Root cause — stub validation that always succeeds:**

The catch-all production instance at `SupportsPeras.hs` lines 318–389 is the only `BlockSupportsPeras` instance in the codebase:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  -- TODO: perform actual validation against all possible 'PerasValidationErr' variants
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert = cert
        , vpcCertBoost = perasWeight params
        }
``` [1](#0-0) 

No signature check, no quorum check, no round-number bounds check — every `PerasCert` is unconditionally wrapped in `ValidatedPerasCert` and returned as `Right`.

**Inbound pipeline wires this directly to peer input:**

`makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback for every certificate batch received from a remote peer:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` then stores every "validated" certificate and calls `addPerasCertAsync`, which triggers chain selection for the boosted block: [3](#0-2) 

**Chain selection consumes the forged boost:**

`chainSelSync` for a `ChainSelAddPerasCert` message reads the certificate's `boostedBlock` from the (unverified) cert content and calls `chainSelectionForBlock` for it: [4](#0-3) 

The `PerasWeightSnapshot` used during chain selection is built directly from the stored (unverified) certificates: [5](#0-4) 

**Analog to the DeFi bug:**

| DeFi (`FeeFollowModule`) | Ouroboros Consensus |
|---|---|
| `transferFrom(follower, ...)` — `follower` is an attacker-controlled input parameter used as the authoritative "from" identity | `validatePerasCert params cert = Right ...` — the certificate's claimed quorum/boosted-block is an attacker-controlled input used as authoritative proof |
| No check that `follower == msg.sender` | No check that the certificate carries a valid aggregate BLS signature from a quorum of committee members |
| Allows draining any approved wallet | Allows boosting any block's chain weight |

**Secondary issue — `validatePerasVote` also skips signature verification:**

The same instance's `validatePerasVote` only performs a stake-distribution map lookup; it never calls `verifyVoteSignature`:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote{ vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [6](#0-5) 

An attacker can forge votes for any pool ID present in the stake distribution, accumulating enough fake stake to trigger certificate generation internally (via `updatePerasRoundVoteStates`), compounding the certificate-forgery path. [7](#0-6) 

### Impact Explanation

**High — Chain selection manipulation by an unprivileged peer.**

A single malicious peer can:
1. Craft a `PerasCert{pcCertRound = r, pcCertBoostedBlock = <fork tip>}` for any block it has seen.
2. Send it via the Peras certificate object-diffusion mini-protocol.
3. The receiving node stores it as `ValidatedPerasCert` with `vpcCertBoost = perasWeight params` (the full configured Peras weight).
4. Chain selection re-runs for the boosted block; if the fork's weight (chain length + Peras boost) now exceeds the current selection, the node switches to the attacker's preferred fork.

This satisfies the **High** impact category: "Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."

### Likelihood Explanation

**High likelihood** given:
- No privilege is required — any peer that can open a Peras certificate object-diffusion connection can send crafted certificates.
- The attack requires only constructing a valid CBOR-encoded `PerasCert` with attacker-chosen fields; no key material is needed.
- The stub is the only `BlockSupportsPeras` instance; there is no override for Cardano blocks that would perform real validation.
- The TODO comment (`cardano-peras/issues/120`) confirms the gap is known but not yet closed.

### Recommendation

1. **Implement real `validatePerasCert`**: verify the aggregate BLS signature over `(electionId, candidate)` against the declared voter set, check that the voter set constitutes a quorum, and verify each non-persistent voter's VRF eligibility proof. The `CryptoSupportsAggregateVoteSigning` / `CryptoSupportsBatchVRFVerification` interfaces in `Committee.Crypto` already define the required primitives.

2. **Implement real `validatePerasVote`**: call `verifyVoteSignature` (or the equivalent from `CryptoSupportsVoteSigning`) before accepting a vote as `ValidatedPerasVote`. The `EveryoneVotes` and `WFALS` committee implementations already show the correct pattern.

3. **Do not ship the stub instance in production**: gate the degenerate `instance StandardHash blk => BlockSupportsPeras blk` behind a compile-time flag or replace it with a proper Cardano-era-specific instance before enabling the Peras mini-protocol on mainnet.

### Proof of Concept

```
Given:
  - Honest node N running with Peras enabled
  - Attacker peer A connected to N via the Peras cert object-diffusion mini-protocol
  - Honest chain tip H at block B_H (block number 1000)
  - Adversarial fork tip at block B_A (block number 999, one block shorter)

Steps:
1. A constructs a PerasCert:
     PerasCert { pcCertRound = 42, pcCertBoostedBlock = B_A }
   (no valid aggregate signature needed — validatePerasCert ignores it)

2. A sends the cert to N via the object-diffusion protocol.

3. N calls processCerts → validatePerasCert mkPerasParams cert → Right ValidatedPerasCert{vpcCertBoost = perasWeight params}

4. N stores the cert in PerasCertDB; chainSelSync fires chainSelectionForBlock for B_A.

5. Chain selection computes:
     weight(fork ending at B_A) = blockNo(B_A) + perasWeight params
   If perasWeight params > 1 (the default), this exceeds weight(H) = blockNo(B_H) = 1000
   when blockNo(B_A) + boost > 1000.

6. N switches to the adversarial fork, rolling back its honest selection.

Expected outcome: N adopts the attacker's non-canonical chain without any key material from the attacker.
``` [8](#0-7) [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-389)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-535)
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
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes

  -- Deliver promise indicating that we processed the cert.
  lift $ atomically $ putTMVar varProcessed certResult
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-212)
```haskell
  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
```
