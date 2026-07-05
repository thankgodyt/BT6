### Title
Peras Certificate Verification Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or quorum verification. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as the boosted target; the node accepts it, stores it in `PerasCertDB`, and immediately re-runs chain selection with the injected boost weight, potentially switching to a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` instance for `StandardHash blk` — the degenerate instance used for all blocks — implements `validatePerasCert` as an unconditional success:

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
``` [1](#0-0) 

No aggregate BLS signature is verified, no voter eligibility is checked, no quorum threshold is enforced, and no round-number bounds are validated. The `PerasValidationErr` data type is a single opaque constructor with no variants, making it structurally impossible to express any of these errors. [2](#0-1) 

This stub is wired directly into the production node-to-node certificate diffusion handler:

```haskell
(validatePerasCert mkPerasParams)
``` [3](#0-2) [4](#0-3) 

The `processCerts` function, called on every batch of inbound certificates from a peer, passes each certificate through this no-op validator and, on success, stores it and triggers chain selection: [5](#0-4) 

The network entry point in the node-to-node handler wires this directly to the `ChainDB`: [6](#0-5) 

Once a certificate is accepted, `chainSelSync` processes it by calling `chainSelectionForBlock` on the boosted block, potentially switching the node's preferred chain: [7](#0-6) 

The Peras weight boost is defined as `PerasWeight 15` by default, meaning a single injected certificate adds 15 units of weight to the targeted block's chain — enough to override a legitimate chain that is 15 blocks shorter. [8](#0-7) 

The glossary confirms that Peras weight directly governs chain selection preference: [9](#0-8) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block in the receiving node's VolatileDB as `pcCertBoostedBlock`. The node accepts it without any verification, stores it, and re-runs chain selection. If the boosted block is on a fork, the node may switch to that fork, diverging from the canonical chain. Multiple injected certificates for the same fork compound the boost. This constitutes a **chain selection manipulation** that lets an unprivileged peer make an honest node prefer a non-canonical chain, matching the "High" impact tier: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*, and also the "Critical" tier: *bypass of certificate verification that enables unauthorized certificate acceptance*.

---

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is an active, externally reachable network handler. Any peer that can establish a node-to-node connection can send crafted certificates. No stake, no keys, and no prior knowledge beyond the target block's hash (observable from ChainSync) are required. The attack requires only a single well-formed CBOR-encoded `PerasCert` message.

---

### Recommendation

1. Implement real certificate validation in `validatePerasCert` before Peras is enabled in production: verify the aggregate BLS signature against the declared voter set, check each voter's eligibility against the epoch stake snapshot, and confirm the total vote weight meets the quorum threshold (`perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`).
2. Until real validation is implemented, gate the Peras certificate diffusion handler behind the Peras feature flag so it is unreachable when Peras is disabled.
3. Enrich `PerasValidationErr` with concrete error variants (as noted in issue #120) so that validation failures are distinguishable and auditable.
4. Apply the same scrutiny to `validatePerasVote`, which also carries a `TODO` for full validation and whose `stakeAboveThreshold` comparison has an acknowledged unit-mismatch risk between absolute and relative stake values. [10](#0-9) 

---

### Proof of Concept

**Setup:** A private testnet with Peras enabled. Attacker controls one peer connected to the honest node. The honest node has two competing chain tips: canonical tip `C` (length N) and fork tip `F` (length N−14, i.e., 14 blocks shorter).

**Steps:**

1. Attacker observes the honest node's chain via ChainSync and learns the hash and slot of the fork tip block `F`.
2. Attacker constructs a CBOR-encoded `PerasCert`:
   ```
   pcCertRound    = <any round number not yet in PerasCertDB>
   pcCertBoostedBlock = RealPoint <slot of F> <hash of F>
   ```
   No valid aggregate signature or voter list is needed — the field is accepted as-is.
3. Attacker sends this certificate via the Peras certificate diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = PerasWeight 15}` unconditionally. [11](#0-10) 
5. The certificate is stored in `PerasCertDB`; `addPerasCertAsync` enqueues a `ChainSelAddPerasCert` message.
6. `chainSelSync` computes the total weight of the fork chain as `(N−14) + 15 = N+1`, which exceeds the canonical chain's weight of `N`.
7. The honest node switches to the fork, diverging from the canonical chain.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L153-162)
```haskell
-- | Check whether a given vote stake is above the quorum threshold.
--
-- TODO: this function assumes that the 'PerasVoteStake' and the quorum
-- threshold used in 'PerasParams' are expressed in the same units. That is,
-- both are either absolute or relative (normalized) values. Under the current
-- current implementation of 'PerasParams', this function only makes sense when
-- both values are relative (normalized) values, so we should either normalize
-- the 'PerasVoteStake' before calling this function, or change this function to
-- accept a stake distribution and perform the normalization internally.
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-348)
```haskell
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
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-127)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-173)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
```

**File:** docs/website/contents/references/glossary.md (L516-527)
```markdown
## ;Peras ;weight ;boost

Peras is an extension of Praos enabling faster settlement under optimistic conditions.
To this end, Peras can result in a block `B` receiving a *boost*, which means that any chain containing `B` gets additional weight when being compared to other chains.

Consider a chain fragment `F`:

- Its ;*weight boost* is the sum of all boosts received by points on this fragment (excluding the anchor). Note that the same point can be boosted multiple times.

- Its ;*total weight* is its tip block number plus its weight boost.

Note that these notions are always relative to a particular anchor, so different chain fragments must have the same anchor when their total weight is to be compared.
```
