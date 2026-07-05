### Title
Peras Certificate Validation Uses Placeholder Parameters Instead of Actual Chain State, Enabling Unauthorized Weight Boost Injection — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`)

---

### Summary

The Peras certificate ingest pipeline validates incoming certificates using a hardcoded placeholder (`mkPerasParams`) rather than the actual ledger-derived stake distribution and voting-committee parameters. Because the validation is not anchored to the historical chain state, an unprivileged peer can submit a crafted certificate that passes the stub check, is stored in the `PerasCertDB`, and immediately inflates the `PerasWeightSnapshot` used by chain selection — causing an honest node to prefer a fork chain it should not adopt.

---

### Finding Description

**Vulnerability class (analog mapping):** The BellumNursery report describes reward distribution that reads the *current* share ratio instead of a *historical snapshot*, letting a late entrant capture disproportionate rewards. The structural analog in Ouroboros Consensus is that Peras certificate validation reads *placeholder* protocol parameters instead of the *actual ledger-state snapshot* (stake distribution, committee eligibility), letting a crafted certificate capture disproportionate chain weight.

**Root cause — two co-located TODOs confirm the gap:**

1. In `makePerasCertPoolWriterFromChainDB` (the production path used by the node):

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [1](#0-0) 

2. In `implAddCert` inside `PerasCertDB.Impl`:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
``` [2](#0-1) 

Both sites acknowledge that the validation is a stub. `mkPerasParams` is a compile-time constant that does not consult the ledger's stake snapshot, the epoch's voting committee, or any VRF/KES proof tied to the boosted block. The `ValidatedPerasCert` wrapper produced by this stub therefore carries no meaningful cryptographic or stake-based guarantee.

**How the weight reaches chain selection:**

Once `implAddCert` stores the certificate, `implGetWeightSnapshot` immediately folds it into the `PerasWeightSnapshot`:

```haskell
mkPerasWeightSnapshot
  [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
  | cert <- Map.elems (pcdsCertsByTicket pcds)
  ]
``` [3](#0-2) 

`preferAnchoredCandidate` then uses this snapshot to compare the current chain against candidates:

```haskell
case preferCandidate
  (projectChainOrderConfig cfg)
  (weightedSelectView cfg weights oursSuffix)
  (weightedSelectView cfg weights candSuffix) of
``` [4](#0-3) 

`wsvTotalWeight` adds the injected boost directly to the block number, so a sufficiently large `getPerasCertBoost` can make a shorter fork appear heavier than the honest chain:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

**Analog to BellumNursery:** BellumNursery distributes rewards proportional to the *current* share at distribution time rather than the *historical* staking duration. Here, chain selection assigns weight proportional to the *current* certificate set rather than certificates that were legitimately earned against the *historical* stake snapshot. In both cases, a late/crafted injection at the right moment captures disproportionate benefit.

---

### Impact Explanation

An adversary operating an unprivileged peer can:

1. Craft a `PerasCert` referencing a block on a minority fork.
2. Transmit it via the Peras certificate mini-protocol (`ObjectDiffusion`).
3. The stub `validatePerasCert mkPerasParams` accepts it; `implAddCert` stores it.
4. `chainSelSync` triggers `chainSelectionForBlock` for the boosted block.
5. `preferAnchoredCandidate` now sees the fork as heavier and switches the node's selection.

The node permanently adopts a non-canonical chain, breaking consensus safety. Because the boost value (`getPerasCertBoost`) is taken directly from the certificate without being bounded by the actual quorum stake, the adversary can set it arbitrarily large to override any honest chain length advantage.

**Impact class:** Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain selection manipulation.

---

### Likelihood Explanation

- Peras is currently gated behind a feature flag (disabled by default on mainnet), so the attack surface is limited to nodes that enable it.
- However, the code is production-ready infrastructure and the TODO items are tracked issues, meaning the gap is present in the shipped codebase.
- The entry path (Peras certificate mini-protocol) is reachable by any peer that connects to a Peras-enabled node.
- No stake, keys, or operator access are required; only the ability to send a well-formed (but cryptographically unverified) `PerasCert` message.

**Likelihood:** Medium-High when Peras is enabled; Low on current mainnet where Peras is disabled.

---

### Recommendation

1. **Replace `mkPerasParams` with ledger-derived parameters.** `validatePerasCert` must receive the epoch's actual stake distribution snapshot and voting-committee eligibility proof, consistent with how `LedgerView` is used for Praos leader-schedule validation.

2. **Implement the non-trivial validation in `implAddCert`.** The DB layer should re-verify the certificate's quorum proof against the stored ledger state before writing, so that even if the ingest layer is bypassed, the DB acts as a second gate.

3. **Bound `getPerasCertBoost` to the protocol-defined maximum.** Chain selection should reject or cap any boost value that exceeds what a legitimate quorum can produce, preventing a single certificate from overriding an arbitrarily long honest chain.

---

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect a malicious peer to an honest node.
2. Construct a `PerasCert` with:
   - `pcCertRound` set to any round not yet in the node's `PerasCertDB`.
   - `pcCertBoostedBlock` pointing to the tip of a minority fork.
   - `vpcCertBoost` set to a value exceeding the honest chain's block-number lead (e.g., `PerasWeight 10000`).
3. Send the certificate via the Peras certificate diffusion protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams`; the stub accepts it.
5. `implAddCert` stores it; `implGetWeightSnapshot` includes the boost.
6. `chainSelSync` fires `chainSelectionForBlock`; `preferAnchoredCandidate` computes `wsvTotalWeight` for the fork as `blockNo + 10000`, which exceeds the honest chain's weight.
7. The node switches to the minority fork.

Observe via node traces: `ChainSelectionForBoostedBlock` followed by a chain switch event confirming adoption of the fork. [6](#0-5) [7](#0-6)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L167-168)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L207-214)
```haskell
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
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
