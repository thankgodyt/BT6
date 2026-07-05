### Title
Peras Certificate Verification Bypass via Stub `validatePerasCert` Always Returning `Right` - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance for all `StandardHash blk` block types implements `validatePerasCert` as a stub that unconditionally returns `Right`, accepting every inbound Peras certificate without any cryptographic or structural validation. This stub is wired directly into the production inbound certificate processing pipeline (`makePerasCertPoolWriterFromChainDB`). An unprivileged peer can send a crafted `PerasCert` with an arbitrary round number and boosted-block point; the node will accept it, store it in the `PerasCertDB`, and trigger chain selection for the attacker-chosen block, potentially switching to a non-canonical chain.

---

### Finding Description

`BlockSupportsPeras` declares `validatePerasCert` as the mandatory gate before any received certificate is stored or acted upon: [1](#0-0) 

The only concrete instance in the codebase is a self-described "degenerate instance for all blks to get things to compile": [2](#0-1) 

Its implementation of `validatePerasCert` ignores every field of the certificate and always returns `Right`: [3](#0-2) 

This stub is not isolated to tests. The production `ObjectDiffusion` inbound writer for certificates passes it verbatim as the `validateCert` argument: [4](#0-3) 

`processCerts` then calls `validateCert <$> certsNotAlreadyInDb`; because the stub never returns `Left`, the `([], validatedCerts)` branch is always taken and every certificate is forwarded to `ChainDB.addPerasCertAsync`: [5](#0-4) 

`chainSelSync` then processes the certificate: it adds it to `PerasCertDB` and, if the boosted block is in the `VolatileDB`, immediately triggers `chainSelectionForBlock` for that block: [6](#0-5) 

The same pattern applies to `validatePerasVote`: the stub only checks that the voter ID exists in the stake distribution map but performs no BLS signature verification, allowing a peer to forge votes for any registered pool without possessing its private key: [7](#0-6) 

---

### Impact Explanation

**Critical — Bypass of Peras certificate/vote verification enabling unauthorized certificate acceptance and chain-selection manipulation.**

Because `validatePerasCert` always succeeds, an unprivileged peer can:

1. Craft a `PerasCert` naming any `PerasRoundNo` and any `Point blk` as the boosted block.
2. Deliver it over the `ObjectDiffusion` mini-protocol.
3. Cause the receiving node to store the certificate and run `chainSelectionForBlock` for the attacker-chosen block.
4. If the attacker also controls or has pre-delivered the corresponding block header (which is in the `VolatileDB`), the node will switch to the attacker's preferred fork, violating chain-selection safety.

The `ValidatedPerasCert` wrapper is the type-level proof that a certificate passed validation. Because the stub manufactures this proof unconditionally, the type system's safety guarantee is voided for all production block types. [8](#0-7) 

---

### Likelihood Explanation

**High.** The `ObjectDiffusion` mini-protocol is a standard peer-to-peer channel reachable by any connected node. No special privileges, keys, or stake are required to send a `PerasCert` message. The only existing filter is the duplicate-round check (`Set.member roundNo certIds`), which is trivially bypassed by using a fresh round number. The stub is the sole instance for all `StandardHash blk` types, so no override exists for Cardano production blocks.

---

### Recommendation

1. **Remove the universal stub instance.** The `instance StandardHash blk => BlockSupportsPeras blk` at line 320 of `SupportsPeras.hs` must not be the live implementation for production block types. It should be replaced with a concrete instance for the Cardano HFC block type that performs full BLS aggregate-signature verification against the committee's public keys and the declared stake distribution.

2. **Implement `validatePerasCert` with real cryptographic checks.** At minimum, verify: (a) the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` is valid under the committee's aggregate public key; (b) the signers collectively hold stake above the quorum threshold; (c) the round number is within the valid window relative to the current tip.

3. **Implement `validatePerasVote` with signature verification.** The current stub only checks stake-distribution membership. It must also verify the BLS signature on `(pvVoteRound, pvVoteBlock)` against the voter's registered public key.

4. **Track the open issue.** The TODOs reference `https://github.com/tweag/cardano-peras/issues/120` and `issues/73`. These must be resolved before Peras is enabled on any network that accepts external peers.

---

### Proof of Concept

**Private-testnet sequence (no special privileges required):**

```
1. Start a local Cardano node with Peras enabled (private testnet).

2. Connect an adversarial peer to the node via the ObjectDiffusion mini-protocol.

3. The adversarial peer sends a PerasCert message:
     PerasCert { pcCertRound = <any fresh round R>
               , pcCertBoostedBlock = <Point of a block B already in the node's VolatileDB> }

4. The node calls:
     processCerts ... (validatePerasCert mkPerasParams) ... [crafted_cert]
   validatePerasCert returns Right unconditionally.

5. The node calls ChainDB.addPerasCertAsync with the crafted ValidatedPerasCert.

6. chainSelSync fires chainSelectionForBlock for block B.

7. If B is the tip of a fork with lower cumulative density than the current chain,
   the Peras weight boost (perasWeight params) is added to B's fork weight,
   potentially causing the node to switch to the attacker's fork.

8. Repeat with different round numbers to inject multiple fake boosts for the
   same or different blocks, arbitrarily inflating fork weights.
```

The root cause is confirmed at: [9](#0-8) 
called from: [10](#0-9)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
