### Title
Peras `validatePerasCert` Stub Unconditionally Accepts All Certificates, Enabling Unauthorized Chain-Weight Boost — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance's `validatePerasCert` method accepts every certificate unconditionally, performing zero cryptographic or structural verification. An unprivileged peer can submit a crafted `PerasCert` for any block, have it stored in `PerasCertDB` as a `ValidatedPerasCert`, and thereby inject a full Peras weight boost into chain selection for an adversarial block. This is the direct analog of the delegation-service bounded-collection bypass: just as fake delegators could fill the pool and distort staking, fake certificates can fill the cert DB and distort chain selection.

---

### Finding Description

In `Ouroboros/Consensus/Block/SupportsPeras.hs`, the only `BlockSupportsPeras` instance in the codebase is a degenerate catch-all:

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

No round number, boosted-block age (`PerasBlockMinSlots`), quorum proof, or cryptographic signature is checked. The function wraps any caller-supplied `PerasCert` in `Right ValidatedPerasCert` with the full configured `perasWeight`.

The `PerasCertDB` API stores these values via `addCert`:

```haskell
addCert ::
    WithArrivalTime (ValidatedPerasCert blk) ->
    STM m (m AddPerasCertResult)
``` [2](#0-1) 

The stored weights are then returned by `getWeightSnapshot`, which feeds directly into chain selection:

```haskell
getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
-- Return the Peras weights in order compare the current selection against
-- potential candidate chains
``` [3](#0-2) 

The inbound vote/cert processing path in `ObjectPool/PerasVote.hs` calls `validatePerasVote` (also a stub — only checks stake-distribution membership, no signature) before adding to the DB:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

The `implAddVote` function in `PerasVoteDB/Impl.hs` also carries the same TODO:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ...
``` [5](#0-4) 

A separate, acknowledged GC-bypass issue exists in `implGarbageCollect` (issue #218): an attacker can keep a round's vote state alive indefinitely by submitting votes with far-future target slots, because GC only fires when the **youngest** targeted slot is older than the threshold. That issue is resource-exhaustion only and is disqualified; it is noted here only for completeness. [6](#0-5) 

---

### Impact Explanation

**Critical / High — Bypass of Peras certificate verification enabling unauthorized chain-weight boost and chain-selection manipulation.**

Because `validatePerasCert` returns `Right` for any input, an attacker can inject a `ValidatedPerasCert` for any block point into `PerasCertDB`. The weight snapshot derived from this cert is used by `preferAnchoredCandidate` to compare candidate chains. A boosted adversarial block can be made to appear heavier than the honest chain tip, causing an honest node to switch to the adversarial fork. This satisfies:

- *"Bypass of … certificate … checks … that enables unauthorized … certificate acceptance."*
- *"Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

---

### Likelihood Explanation

**High.** The attack requires only network connectivity to reach the ObjectDiffusion inbound handler. No stake, KES/VRF keys, or operator privileges are needed. The degenerate instance is the only `BlockSupportsPeras` instance in the repository; there is no more-specific override for any concrete block type that would restore proper validation.

---

### Recommendation

1. Implement proper cryptographic validation inside `validatePerasCert`: verify the certificate's round number falls within the current or recent epoch, verify the boosted block satisfies `PerasBlockMinSlots`, and verify the certificate represents a genuine quorum of stake-weighted votes with valid BLS/VRF signatures (as already scaffolded in `Peras/Crypto/BLS.hs`).
2. Until real validation is in place, reject all inbound certificates at the protocol boundary rather than accepting them unconditionally.
3. Address issue #218 (GC bypass via far-future vote targets) in tandem, as it compounds the attack surface by keeping adversarial round state alive indefinitely.

---

### Proof of Concept

1. Connect to a Peras-enabled node via the ObjectDiffusion miniprotocol for certificates.
2. Craft a `PerasCert { pcCertRound = R, pcCertBoostedBlock = <adversarial block point> }`.
3. Submit it through the inbound handler; `processVotes`/`addCert` calls `validatePerasCert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
4. The certificate is stored in `PerasCertDB`.
5. `getWeightSnapshot` now includes the adversarial block's weight boost.
6. On the next chain-selection trigger, `preferAnchoredCandidate` compares the boosted adversarial candidate against the honest chain and may select the adversarial fork. [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L37-48)
```haskell
  { addCert ::
      WithArrivalTime (ValidatedPerasCert blk) ->
      STM m (m AddPerasCertResult)
  -- ^ Add a Peras certificate to the database. The STM transaction adds the
  -- certificate to the in-memory index, and the resulting 'm' action performs
  -- tracing and might perform side-effects in implementations with on-disk
  -- storage.
  -- The 'AddPerasCertResult' indicates whether the certificate was actually
  -- added, or if it was already present.
  --
  -- NOTE: Use the @join . atomically@ pattern to run both the transaction
  -- and the side-effects in sequence.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-65)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-112)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-174)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L302-314)
```haskell
        -- First, determine which rounds to delete based on the round vote
        -- state: a round is deleted only when the youngest target of all its
        -- votes is strictly older than the GC threshold.
        --
        -- NOTE:
        -- This conservative approach could cause round states to be kept
        -- for a long time if an attacker keeps adding votes for a given
        -- round but with a target far into the future,
        -- see https://github.com/tweag/cardano-peras/issues/218
        (roundsToDelete, pvsRoundVoteStates') =
          Map.partition
            (\rvs -> getPerasRoundVoteStateMaxTargetedSlot rvs < NotOrigin slotNo)
            pvdsRoundVoteStates
```
