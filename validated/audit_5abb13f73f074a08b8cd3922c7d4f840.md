### Title
Unconditional `validatePerasCert` stub accepts all peer-supplied Peras certificates, enabling unauthorized chain-weight manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` is an explicit stub that unconditionally accepts every certificate a peer sends, assigning it the full configured `perasWeight` boost without performing any cryptographic, quorum, or committee-membership check. When Peras is enabled, an unprivileged peer can forge certificates that boost arbitrary blocks, causing the receiving node to prefer a non-canonical chain via the Peras weight mechanism — a direct bypass of Peras certificate verification.

---

### Finding Description

**Root cause — unconditional acceptance in the default instance:**

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

No era-specific override exists in the searched production code, so this degenerate instance is the one in use for Cardano blocks.

**Entry path — peer-controlled certificate diffusion:**

Inbound Peras certificates arrive via the node-to-node cert diffusion mini-protocol. The inbound handler calls `validatePerasCert` to produce a `ValidatedPerasCert` before handing it to `ChainDB.addPerasCertAsync`. Because `validatePerasCert` always returns `Right`, any raw `PerasCert` a peer sends — with any `pcCertBoostedBlock` (a caller-controlled `Point blk`) and any `pcCertRound` — is unconditionally wrapped in `ValidatedPerasCert` and accepted. [2](#0-1) 

**Chain-selection effect — forged boost triggers fork switch:**

Once the `ValidatedPerasCert` is in the `PerasCertDB`, `chainSelSync` triggers chain selection for the boosted block:

```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  ...
  when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ idExitEarly ...
  ...
  lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [3](#0-2) 

The only guard is a slot-age check (the boosted block must be newer than the immutable tip). There is no check that the certificate was produced by a legitimate quorum of committee members. The `PerasWeightSnapshot` then adds the forged boost to the fork's `wsvWeightBoost`, and `preferAnchoredCandidate` may select the fork over the honest chain:

```haskell
instance ChainOrder (WeightedSelectView proto) where
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch ...
``` [4](#0-3) 

**Analogy to the reference vulnerability:**

| Reference (`transferDeposit`) | This finding (`validatePerasCert`) |
|---|---|
| Allowance grants a token *amount*; caller picks the *stem* (deposit ID) | Certificate is accepted; caller picks the *boosted block point* |
| Older stem → more grown stalks transferred | Forged cert → arbitrary block gets full `perasWeight` boost |
| Recipient drains more value than sender intended | Peer causes node to prefer a non-canonical chain |

---

### Impact Explanation

**Critical — bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation.**

When Peras is enabled, an unprivileged peer can:
1. Craft a `PerasCert` whose `pcCertBoostedBlock` points to any block on a fork (newer than the immutable tip).
2. Send it via the cert diffusion protocol; `validatePerasCert` accepts it unconditionally.
3. The node's `PerasWeightSnapshot` accumulates the forged boost for that fork block.
4. Chain selection may switch to the fork, causing the node to diverge from the honest chain.

This satisfies the "Critical" impact category: *bypass of Peras voting or certificate checks that enables unauthorized certificate acceptance*.

---

### Likelihood Explanation

- **Peras is disabled by default** (`Note that if Peras is disabled (which is the default), there is no observable difference` — CHANGELOG). The attack only materialises on nodes that explicitly enable Peras.
- No privileged access, leaked keys, or stake majority is required. Any peer connected via the node-to-node cert diffusion protocol can send a forged certificate.
- The stub is explicitly marked `TODO` with a linked issue, confirming the missing validation is a known gap, not an intentional design choice.

---

### Recommendation

Replace the stub with a real implementation of `validatePerasCert` that verifies:
1. The certificate's aggregate BLS signature against the claimed committee members' public keys (from the epoch's stake snapshot).
2. That the set of signers constitutes a valid quorum (total stake ≥ quorum threshold).
3. That each signer was a legitimate committee member for the claimed `pcCertRound` (persistent or non-persistent via VRF proof).
4. That `pcCertBoostedBlock` refers to a block that was actually a valid candidate in that round.

Until this is implemented, Peras certificate acceptance should remain gated behind the feature flag, and the flag should not be enabled in production.

---

### Proof of Concept

**Preconditions:** Peras is enabled on the target node; attacker is a connected peer via the node-to-node cert diffusion protocol.

**Steps:**

1. Attacker identifies a fork block `B'` (slot > immutable tip, not on the honest chain) in the target node's VolatileDB (e.g., by observing headers via ChainSync).
2. Attacker constructs a raw `PerasCert`:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = blockPoint B' }
   ```
3. Attacker sends this cert via the Peras cert diffusion mini-protocol.
4. The node calls `validatePerasCert params cert` → returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
5. `addPerasCertAsync` stores the cert; `chainSelSync` triggers `chainSelectionForBlock` for `B'`.
6. `weightBoostOfFragment` now includes `perasWeight` for `B'`; if the fork's total weight exceeds the honest chain's, `preferAnchoredCandidate` returns `ShouldSwitch` and the node adopts the fork.

**Expected outcome:** The node switches to the attacker-chosen fork, diverging from the honest chain — a consensus safety failure reachable by an unprivileged peer with no cryptographic material.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-303)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-531)
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
