### Title
Peras Certificate Validation Bypass Enables Unprivileged Peer to Inject Arbitrary Boost Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The default `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally accepts every inbound Peras certificate without performing any cryptographic or protocol-level checks. An unprivileged peer can send a crafted `PerasCert` message that claims to boost any arbitrary block for any round number. The receiving node accepts it, inserts it into the `PerasCertDB`, and uses the resulting inflated `PerasWeightSnapshot` in chain selection, potentially causing the node to prefer a chain that the Peras protocol would never have certified.

### Finding Description

**Root cause — always-`Right` validation stub**

In `SupportsPeras.hs` the catch-all `instance StandardHash blk => BlockSupportsPeras blk` provides a degenerate `validatePerasCert` that returns `Right` for every input:

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

No BLS aggregate-signature check, no committee-membership proof, no round-validity check, and no boosted-block eligibility check is performed. [1](#0-0) 

**Production entry path**

`makePerasCertPoolWriterFromChainDB` in `PerasCert.hs` wires this stub directly into the live certificate-diffusion writer that processes every certificate received from a remote peer:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` calls `validateCert` on every certificate not already in the DB. Because the stub always returns `Right`, the entire batch of crafted certificates passes and each is timestamped and forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

**Boost injection into chain selection**

`implAddCert` in `PerasCertDB/Impl.hs` deduplicates only by round number; a fresh round number means the certificate is stored unconditionally: [4](#0-3) 

`implGetWeightSnapshot` then recomputes the `PerasWeightSnapshot` from every stored certificate, including the injected one: [5](#0-4) 

`weightedSelectView` uses this snapshot to compute `wsvWeightBoost`, and `preferCandidate` compares `wsvTotalWeight` values to decide whether to switch chains: [6](#0-5) 

`chainSelSync` then triggers a full chain-selection pass for the boosted block: [7](#0-6) 

### Impact Explanation

A crafted `PerasCert` for a fresh round number, pointing at any block in the VolatileDB, will be accepted, stored, and reflected in the weight snapshot. If the attacker-chosen block is the tip of a competing fork, the node's `preferCandidate` comparison will now see that fork as heavier than the honest chain and switch to it. This is an unauthorized Peras certificate acceptance that directly drives a chain-selection error — the node adopts a chain that the Peras quorum never actually certified, violating the Peras safety guarantee.

This matches the allowed critical impact: *"Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

### Likelihood Explanation

Any peer that can open a Peras-cert diffusion connection to the node can exploit this. No stake, no keys, no admin access, and no prior knowledge of the chain state is required beyond knowing a block hash present in the target node's VolatileDB (obtainable via the ChainSync mini-protocol). The only precondition is that the node has Peras enabled.

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that:
1. Verifies the BLS aggregate signature over the election identifier and boosted-block hash.
2. Checks that every included voter seat is a valid committee member for the claimed round (persistent or non-persistent via VRF proof).
3. Confirms the boosted block's slot satisfies `PerasBlockMinSlots` relative to the round start.
4. Confirms the round number falls within the valid voting window (not in cooldown, not too old).

Until the real validation is in place, the node should refuse to process inbound `PerasCert` messages when Peras is enabled, rather than silently accepting all of them.

### Proof of Concept

```
-- Attacker connects to the target node via the Peras-cert diffusion
-- mini-protocol and sends:
PerasCert
  { pcCertRound      = PerasRoundNo 9999   -- any fresh round not yet in DB
  , pcCertBoostedBlock = <hash of a block on attacker's fork>
  }
```

`processCerts` calls `validatePerasCert mkPerasParams` → `Right (ValidatedPerasCert …)`.  
`implAddCert` stores it (round 9999 not in `pcdsCertIds`).  
`implGetWeightSnapshot` now includes `PerasWeight (perasWeight mkPerasParams)` for the attacker's block.  
`chainSelSync` triggers chain selection; `preferCandidate` sees the attacker's fork as heavier and switches.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L174-198)
```haskell
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
