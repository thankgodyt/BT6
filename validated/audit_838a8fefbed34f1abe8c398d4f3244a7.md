### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection Weight - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing no cryptographic or protocol-level validation. Because this stub is the only validation gate before a certificate is stored in `PerasCertDB` and applied to Peras chain-selection weight, any unprivileged peer can inject a crafted certificate that boosts an arbitrary block, causing an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory validation step before a `PerasCert` is accepted. The universal instance (the only one in the codebase) implements it as a stub that always succeeds:

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

This stub is called directly in the inbound certificate processing path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls this validator on every inbound certificate from a peer, and since it always returns `Right`, every certificate passes: [3](#0-2) 

The accepted certificate is then added to `PerasCertDB` via `implAddCert`, which stores it without any further validation check: [4](#0-3) 

`implGetWeightSnapshot` then materialises the stored certificates directly into a `PerasWeightSnapshot` used by chain selection: [5](#0-4) 

`chainSelSync` reads this snapshot and, if the boosted block is in the VolatileDB, immediately triggers `chainSelectionForBlock` for it: [6](#0-5) 

`weightedSelectView` computes the total weight of a candidate fragment including the fraudulent boost, and `preferCandidate` uses this to decide whether to switch chains: [7](#0-6) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` that claims to boost any block — including one on a minority or adversarial fork — and send it via the object diffusion mini-protocol. Because `validatePerasCert` always returns `Right`, the certificate is accepted, stored, and its boost weight is applied to chain selection. If the fraudulent boost is large enough to make the minority fork's `wsvTotalWeight` exceed the honest chain's, the node will switch to the adversarial chain. This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical, less-secure chain beyond the intended Peras security assumptions.

---

### Likelihood Explanation

The entry path is the standard Peras certificate object-diffusion mini-protocol, reachable by any connected peer. No special privileges, keys, or stake are required. The attacker only needs to construct a `PerasCert` value with a chosen `pcCertBoostedBlock` and `pcCertRound` and send it. The `PerasCert` type is fully serialisable and its fields are unconstrained at the network layer. Likelihood is **High** for any deployment where Peras object diffusion is active.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that checks:
- The certificate's VRF/BLS committee signatures against the registered committee for the claimed round.
- That the boosted block's slot falls within the valid Peras round window.
- That the certificate round number is not in a cooldown period.

Until real validation is implemented, the `processCerts` path should refuse all inbound certificates from untrusted peers rather than silently accepting them.

---

### Proof of Concept

1. Connect a peer to a node running with Peras object diffusion enabled.
2. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to a block on a minority fork and `pcCertRound` set to any valid round number not already in the node's `PerasCertDB`.
3. Send the certificate via the object diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
5. The certificate is stored in `PerasCertDB`; `implGetWeightSnapshot` includes the boost in the `PerasWeightSnapshot`.
6. `chainSelSync` detects the boosted block in the VolatileDB and calls `chainSelectionForBlock`.
7. `weightedSelectView` computes the minority fork's total weight as `blockNo + fraudulentBoost`, which exceeds the honest chain's weight.
8. The node switches to the minority fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-127)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          -- We do not want to block the writer thread on waiting for ChainSel
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-198)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
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
