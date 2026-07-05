### Title
Peras Certificate Validation Stub Unconditionally Accepts All Certificates, Enabling Chain-Selection Weight Manipulation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function is a production stub that unconditionally returns `Right` (success) for every inbound certificate, performing zero cryptographic or structural checks. When Peras is enabled, any unprivileged peer can send a crafted `PerasCert` that artificially boosts any block, causing the node's `PerasWeightSnapshot` to diverge from the legitimate certificate state and making chain selection prefer a non-canonical fork.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must be passed before a certificate influences chain selection. The catch-all instance — which applies to every `StandardHash blk` type, including the production Cardano block — implements this gate as a no-op stub:

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

The comment above the instance declaration makes the intent explicit:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [2](#0-1) 

A certificate that passes `validatePerasCert` is stored in the `PerasCertDB` and its boost weight is immediately added to the `PerasWeightSnapshot` used by chain selection. The chain-selection path for an incoming certificate is:

1. `addPerasCertAsync` → `chainSelSync (ChainSelAddPerasCert cert ...)` calls `PerasCertDB.addCert`.
2. The boost is reflected in `getPerasWeightSnapshot`, which is read by `chainSelectionForBlock` and `constructPreferableCandidates`.
3. `WeightedSelectView` computes `wsvTotalWeight = blockNo + weightBoost`; a sufficiently large artificial boost makes a shorter fork appear heavier than the honest chain. [3](#0-2) [4](#0-3) 

The same structural gap exists for vote validation: `validatePerasVote` only performs a stake-distribution membership lookup and never verifies the BLS signature on the vote, so a peer can fabricate votes for any voter ID present in the distribution. [5](#0-4) 

The `PerasWeightSnapshot` therefore tracks "validated" certificates whose content has never been authenticated. This is the direct analog of the external report's rebasing-token issue: just as the Axelar hub tracked a balance that diverged from the real on-chain balance because rebases happened outside the tracked transfer path, the Peras weight snapshot diverges from the legitimate certificate state because the validation gate is absent — any certificate, regardless of authenticity, updates the snapshot.

---

### Impact Explanation

When Peras is enabled, an unprivileged peer can:

1. Craft a `PerasCert` claiming to boost a block on a weaker fork (e.g., a fork that is one block shorter than the honest chain).
2. Send it via the Peras certificate miniprotocol; `validatePerasCert` returns `Right` unconditionally.
3. The `PerasWeightSnapshot` is updated with `perasWeight params` for the attacker-chosen block.
4. `chainSelectionForBlock` is triggered for the boosted block; `preferAnchoredCandidate` now computes a higher `wsvTotalWeight` for the weaker fork.
5. The honest node switches to the non-canonical chain, violating the Common Prefix property.

This matches the **High** impact category: *chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions*.

---

### Likelihood Explanation

Peras is disabled by default in the current release, so the attack surface is not exposed on mainnet today. However:

- The code is in production source files (not test or mock modules), and the Peras miniprotocol infrastructure is fully wired up.
- Any private testnet or future deployment that enables Peras is immediately vulnerable.
- The attack requires only the ability to send a single well-formed (but cryptographically unauthenticated) `PerasCert` message — no stake, no keys, no prior chain knowledge beyond the target block's `Point`.

Likelihood is **Medium**: not exploitable on mainnet today, but trivially exploitable in any Peras-enabled environment.

---

### Recommendation

1. **Remove the catch-all stub instance** or gate it behind a compile-time flag that is never enabled in production builds. The `BlockSupportsPeras` instance for the Cardano block type must implement real BLS aggregate-signature verification for both `validatePerasCert` and `validatePerasVote` before Peras is enabled on any network.

2. **Add a runtime guard** in `chainSelSync (ChainSelAddPerasCert ...)` that rejects certificates when Peras validation is known to be a stub (e.g., check a feature flag or require a non-degenerate `PerasCfg`).

3. **Track the issue** referenced in the TODO comments (`tweag/cardano-peras#120` and `#73`) as a security-blocking prerequisite for Peras activation.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start two nodes with Peras enabled and a known `perasWeight` (e.g., `PerasWeight 15`).
2. Let the honest chain grow to block `N` (block number `N`).
3. Construct a fork of length `N - 1` (one block shorter).
4. Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = tipOfFork }` — no signing key required.
5. Submit the certificate to the target node via `addPerasCertAsync`.
6. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCertBoost = PerasWeight 15 }`.
7. `PerasWeightSnapshot` now assigns weight `(N-1) + 15 = N+14` to the fork tip vs. `N + 0 = N` for the honest tip.
8. `preferAnchoredCandidate` returns `ShouldSwitch`; the node rolls back to the attacker's fork. [1](#0-0) [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
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
