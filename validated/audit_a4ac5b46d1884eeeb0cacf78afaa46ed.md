### Title
Peras Certificate Validation Stub Unconditionally Accepts All Certificates, Enabling Unauthorized Chain-Selection Weight Boost — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default instance of `BlockSupportsPeras` contains a stub implementation of `validatePerasCert` that unconditionally returns `Right` for every certificate, bypassing all cryptographic and structural validation. Similarly, `validatePerasVote` only checks whether the claimed voter ID exists in the stake distribution but performs no signature verification. An unprivileged peer can inject crafted Peras certificates (or forge quorum by sending fake votes attributed to legitimate high-stake pools) to artificially boost an adversarial chain fragment, causing an honest node to prefer and switch to a non-canonical chain.

---

### Finding Description

In `SupportsPeras.hs`, the default `BlockSupportsPeras` instance provides stub implementations for both `validatePerasCert` and `validatePerasVote`:

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

Every certificate, regardless of its content or origin, is wrapped in `ValidatedPerasCert` and assigned the full `perasWeight params` boost. No cryptographic proof, quorum threshold, round validity, or issuer authorization is checked.

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`validatePerasVote` only checks that the claimed voter ID appears in the stake distribution map — it does not verify any cryptographic signature on the vote. Any party that knows a legitimate pool ID (all pool IDs are public) can cast votes on that pool's behalf for any block.

The vote aggregation module (`Peras/Vote/Aggregation.hs`) accumulates stake-weighted votes per round and per target block; when the quorum threshold is crossed, a certificate is forged automatically. [3](#0-2) 

The resulting `ValidatedPerasCert` is stored in the `PerasCertDB` and its boost is recorded in the `PerasWeightSnapshot`. Chain selection then uses `wsvTotalWeight`, which adds `wsvWeightBoost` (the sum of all boosts on the fragment) to the block number when comparing candidate chains:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [4](#0-3) 

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch (Heavier ...)
    ...
``` [5](#0-4) 

When a certificate arrives via `ChainSelAddPerasCert`, the chain selection loop triggers `chainSelectionForBlock` for the boosted block, potentially switching the node to the adversarial fork: [6](#0-5) 

---

### Impact Explanation

**Analog to the external report:** In the NomadFacet bug, `totalRepayAmount` is derived from the same manipulable AMM spot price as `availableAmount`, so the slippage guard `totalRepayAmount ≤ availableAmount` is trivially satisfied by construction — the check is bypassed because the bound and the value come from the same manipulable source. Here, `validatePerasCert` always returns `Right` regardless of the certificate's content — the validation check is trivially bypassed because no actual check is performed. In both cases, a critical guard that should reject adversarial input is rendered ineffective.

**Consensus impact:** An unprivileged peer can cause an honest node to switch to a non-canonical chain by:
1. Sending fake votes attributed to high-stake pools (whose IDs are public) for a target block on an adversarial fork.
2. The vote aggregator reaches quorum and forges a certificate.
3. The certificate is accepted unconditionally by `validatePerasCert`.
4. The boosted block's chain fragment gains enough `wsvTotalWeight` to exceed the honest chain.
5. The node switches to the adversarial fork.

This is a **chain-selection safety failure** triggered by an unprivileged peer via crafted network messages, matching the "High/Critical" impact tier: bypass of Peras certificate/vote checks enabling unauthorized certificate acceptance and non-canonical chain preference.

---

### Likelihood Explanation

Peras is currently **disabled by default** (per the CHANGELOG: "Note that if Peras is disabled (which is the default), there is no observable difference"), but the code is present in the production codebase and can be enabled via configuration. The attack requires only:
- Knowledge of legitimate pool IDs (fully public via the stake distribution).
- Ability to send Peras mini-protocol messages to a node with Peras enabled.
- No key compromise, no stake majority, no admin access.

Once Peras is enabled on any network (testnet or mainnet), this is immediately exploitable by any peer.

---

### Recommendation

1. **`validatePerasCert`**: Implement full certificate validation before the TODO is resolved in production: verify the certificate's round number is within the valid window, that the boosted block exists and is on a plausible chain, and that the certificate carries a valid aggregate BLS/threshold signature from a quorum of committee members.

2. **`validatePerasVote`**: Add cryptographic signature verification over the vote content (round, target block, voter ID) using the voter's registered VRF/cold key before accepting the vote as `ValidatedPerasVote`.

3. **Guard Peras activation**: Ensure that enabling Peras in configuration is gated on the validation stubs being fully implemented, e.g., via a compile-time or runtime assertion.

---

### Proof of Concept

**Setup:** A private testnet with Peras enabled. Attacker is an unprivileged peer connected to an honest node.

**Steps:**

1. Attacker observes the public stake distribution and identifies a high-stake pool `P` with pool ID `pid`.
2. Attacker constructs `PerasVote` messages claiming `pid` as the voter, targeting a block `B'` on an adversarial fork (shorter or equal length to the honest chain).
3. Attacker sends enough such votes (attributed to pools summing to quorum stake) via the Peras vote mini-protocol.
4. The honest node calls `validatePerasVote` for each vote; since `pid` is in the stake distribution, each vote is accepted as `ValidatedPerasVote` without signature verification.
5. The vote aggregator (`Peras/Vote/Aggregation.hs`) accumulates stake and crosses the quorum threshold, forging a `ValidatedPerasCert` for `B'`.
6. `chainSelSync` processes `ChainSelAddPerasCert`; `validatePerasCert` returns `Right` unconditionally.
7. The `PerasWeightSnapshot` is updated; `B'`'s chain fragment gains `perasWeight params` boost.
8. `chainSelectionForBlock` is triggered; `wsvTotalWeight` of the adversarial fragment now exceeds the honest chain.
9. The honest node switches to the adversarial fork. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/Aggregation.hs (L1-60)
```haskell
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveAnyClass #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE ViewPatterns #-}

-- | Peras vote aggregation and certificate forging
--
-- This module implements the core voting logic for the Peras protocol, which
-- aggregates stake-weighted votes on chain blocks and forges certificates when
-- quorum is reached.
--
-- = Overview
--
-- In Peras, validators vote on specific blocks during designated voting rounds.
-- Each vote carries a stake weight, and votes are aggregated by:
--
--   * __Round__: each vote belongs to a specific 'PerasRoundNo'
--   * __Target__: within a round, votes are cast for different block 'Point's
--
-- As votes arrive, the system tracks the total stake backing each candidate
-- block. When one target accumulates enough stake to exceed the configured
-- quorum threshold, a certificate is automatically forged for that block,
-- making it a winner for that round.
--
-- = State Machine
--
-- For every round being voted for, the aggregation follows a state machine:
--
-- 1. __Quorum not reached__: multiple block targets are candidates, each
--    accumulating votes and stake. All targets compete to reach quorum first.
--
-- 2. __Quorum reached__: once a target reaches quorum, it becomes the winner
--    and a certificate is forged. All other targets become losers and continue
--    tracking votes without affecting the outcome.
--
-- = Quorum Threshold and Multiple Winners
--
-- The quorum threshold is parameterized via 'PerasCfg'. Depending on this
-- configuration and the stake distribution, it may be theoretically possible
-- for multiple targets to exceed the threshold within the same round.
--
-- This module treats multiple winners as an error condition and rejects votes
-- that would cause this, raising instead a 'RoundVoteStateLoserAboveQuorum'
-- exception. This indicates that either:
--   * The quorum threshold is misconfigured, or that
--   * We were extremely unlucky when randomly selecting the voting committee.
--
-- With a correct threshold configuration (e.g., > 3/4 of total stake + a small
-- safety margin to account for an unlucky local sortition when selecting
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
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

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
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
