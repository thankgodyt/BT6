### Title
Degenerate `BlockSupportsPeras` instance unconditionally accepts all Peras certificates, bypassing signature and quorum validation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras blk` instance in `SupportsPeras.hs` implements `validatePerasCert` as a function that unconditionally returns `Right`, accepting every certificate regardless of its round number, boosted block, voter set, or aggregate BLS signature. Because the `PerasCertDB` stores only `ValidatedPerasCert` values and the weight snapshot fed into chain selection is built directly from those stored values, any unprivileged peer can inject a crafted certificate that artificially boosts an arbitrary block by `perasWeight params` (15) in chain selection, potentially causing an honest node to prefer an adversary-controlled chain.

---

### Finding Description

**Root cause — unconditional `Right` in `validatePerasCert`**

The degenerate instance (lines 318–389) is the only `BlockSupportsPeras` instance in the `ouroboros-consensus` package and applies to every `StandardHash blk`:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
  validatePerasCert params cert =
    Right
      ValidatedPerasCert
        { vpcCert    = cert
        , vpcCertBoost = perasWeight params   -- always 15; never derived from voters
        }
```

No signature check, no quorum check, no round-number sanity check is performed. The function always returns `Right`, so every certificate that arrives from a peer is treated as fully valid.

**How the accepted certificate reaches chain selection**

1. A peer delivers a certificate via the Peras miniprotocol; `addPerasCertAsync` / `chainSelSync` is called.
2. `implAddCert` stores the `ValidatedPerasCert` in `pcdsCertsByTicket` (no further validation gate).
3. `implGetWeightSnapshot` builds the `PerasWeightSnapshot` used by chain selection:

```haskell
mkPerasWeightSnapshot
  [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
  | cert <- Map.elems (pcdsCertsByTicket pcds)
  ]
```

`getPerasCertBoost cert` returns `vpcCertBoost`, which was set to `perasWeight params` (15) for every accepted certificate.

4. `chainSelectionForBlock` reads this snapshot and passes it to `constructPreferableCandidates` and `preferAnchoredCandidate`, which use `totalWeightOfFragment` to compare chains. A block that has been boosted by a crafted certificate carries 15 extra weight units.

**Analogy to the external report**

In the LoopFi bug, `pool.repayCreditAccount(debtData.debt, 0, loss)` passes `profit = 0` instead of `debtData.accruedInterest`, so the interest component is silently dropped from the accounting. Here, `validatePerasCert` passes `vpcCertBoost = perasWeight params` (a fixed constant) instead of a value derived from actual cryptographic verification, so the validity component is silently dropped from the accounting — every certificate is treated as if it were legitimately formed.

---

### Impact Explanation

An unprivileged peer can send a crafted `PerasCert` naming any block as the boosted block. The certificate bypasses all validation and is stored in the `PerasCertDB`. The targeted block then receives +15 weight in every subsequent chain-selection comparison. If the adversary's fork contains that block and the honest chain does not, the node will switch to the adversary's fork even if it is shorter by up to 14 blocks. This constitutes a **chain-selection safety failure** and a **bypass of Peras certificate checks** enabling unauthorized certificate acceptance.

---

### Likelihood Explanation

The Peras certificate miniprotocol is wired into the live `ChainDB` API (`addPerasCertAsync`, `ChainSelAddPerasCert`). Any peer that can open a connection to the node can submit a certificate. No stake, key material, or privileged access is required. The degenerate instance is the only `BlockSupportsPeras` instance in the repository; no overriding instance for Cardano blocks was found in `ouroboros-consensus-cardano`.

---

### Recommendation

Replace the unconditional `Right` in the degenerate `validatePerasCert` with a proper implementation that:

1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)`.
2. Checks that the combined stake of the voters meets the quorum threshold (`stakeAboveThreshold`).
3. Validates that each voter's eligibility proof is well-formed.
4. Derives `vpcCertBoost` from the verified voter set rather than from a fixed protocol parameter.

Until a full implementation is ready, the function should return `Left` for all certificates (disabling Peras boosts) rather than `Right` (accepting all certificates).

---

### Proof of Concept

1. Connect to a node with the Peras miniprotocol active.
2. Construct a `PerasCert` with `pcCertRound = R` and `pcCertBoostedBlock = <adversary block point>` — voters and signature fields can be arbitrary because they are never checked.
3. Submit the certificate via `addPerasCertAsync`.
4. `implAddCert` stores it; `implGetWeightSnapshot` returns a snapshot giving the adversary's block +15 weight.
5. When `chainSelectionForBlock` next runs for any block on the adversary's fork, `preferAnchoredCandidate` will prefer that fork over an honest chain that is up to 14 blocks longer, causing the node to switch to the adversary-controlled chain. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-686)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)

  -- The current chain we're working with here is not longer than @k@ blocks
  -- (see 'getCurrentChain' and 'cdbChain'), which is easier to reason about
  -- when doing chain selection, etc.
  assert (fromIntegral (AF.length curChain) <= unNonZero k) pure ()

  let
    immBlockNo :: WithOrigin BlockNo
    immBlockNo = AF.anchorBlockNo curChain

  if
    -- The chain might have grown since we added the block such that the
    -- block is older than the immutable tip.
    | olderThanImmTip hdr immBlockNo -> do
        traceWith addBlockTracer $ IgnoreBlockOlderThanImmTip p

    -- The block is invalid
    | Just (InvalidBlockInfo reason _) <- Map.lookup (headerHash hdr) invalid -> do
        traceWith addBlockTracer $ IgnoreInvalidBlock p reason

        -- We wouldn't know the block is invalid if its prefix was invalid,
        -- hence 'InvalidBlockPunishment.BlockItself'.
        InvalidBlockPunishment.enact
          punish
          InvalidBlockPunishment.BlockItself

    -- Try to select a chain involving the block.
    | otherwise -> do
        -- Construct all 'ChainDiff's involving the block.
        chainDiffs <-
          constructPreferableCandidates
            cdb
            weights
            curChain
            (Map.singleton (headerHash hdr) hdr)
            (headerRealPoint hdr)

        let traceNoChange = traceWith addBlockTracer $ StoreButDontChange p

            chainSelEnv = mkChainSelEnv cdb blockCache weights curChain (Just (p, punish))

        case NE.nonEmpty chainDiffs of
          Just chainDiffs' -> do
            -- Find the best valid candidate and, if valid, perform a
            -- switch. Log if none were found.
            flip whenNothing traceNoChange
              =<< chainSelection
                chainSelEnv
                chainDiffs'
                (switchTo cdb weights (Just p))
          -- No candidate better than our chain.
          Nothing -> traceNoChange
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L121-177)
```haskell
data PerasParams = PerasParams
  { perasIgnoranceRounds :: !PerasIgnoranceRounds
  , perasCooldownRounds :: !PerasCooldownRounds
  , perasBlockMinSlots :: !PerasBlockMinSlots
  , perasCertMaxRounds :: !PerasCertMaxRounds
  , perasCertArrivalThreshold :: !PerasCertArrivalThreshold
  , perasRoundLength :: !PerasRoundLength
  , perasWeight :: !PerasWeight
  , perasQuorumStakeThreshold :: !PerasQuorumStakeThreshold
  , perasQuorumStakeThresholdSafetyMargin :: !PerasQuorumStakeThresholdSafetyMargin
  }
  deriving (Show, Eq, Generic, NoThunks)

-- | Instantiate default Peras protocol parameters.
--
-- NOTE: in the future this will depend on a concrete 'BlockConfig'.
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
