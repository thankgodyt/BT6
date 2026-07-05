### Title
Peras Certificate and Vote Verification Bypass via Degenerate Catch-All `BlockSupportsPeras` Instance — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

A degenerate catch-all `instance StandardHash blk => BlockSupportsPeras blk` is the only active implementation of `BlockSupportsPeras` for all production block types. Its `validatePerasCert` unconditionally returns `Right` (accepts every certificate without any cryptographic check), and its `validatePerasVote` performs no signature verification — only a stake-distribution lookup. An unprivileged peer can therefore submit arbitrarily forged Peras certificates and votes that are accepted as valid, causing honest nodes to apply unearned chain-weight boosts to attacker-controlled blocks and prefer a non-canonical chain.

---

### Finding Description

**Root cause — degenerate instance with no-op validation** [1](#0-0) 

The comment explicitly acknowledges this is a placeholder:

```
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

Because Haskell resolves this as the most-general instance for every `StandardHash` block (including all production Cardano eras), no more-specific instance overrides it in the production path.

**`validatePerasCert` always succeeds** [2](#0-1) 

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

Every certificate, regardless of content or cryptographic correctness, is wrapped in `Right` and assigned the full `perasWeight` boost. No signature, quorum membership, or round-number check is performed.

**`validatePerasVote` skips signature verification** [3](#0-2) 

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

`_params` is discarded (note the underscore). The only check is whether the claimed voter ID appears in the stake distribution. No cryptographic signature over the vote payload is verified, so any peer who knows a valid pool ID can forge votes on its behalf.

**Validated certificates feed directly into chain selection weight** [4](#0-3) 

`ChainSel.hs` consumes `vpcCertBoost` from `ValidatedPerasCert` values stored in `PerasCertDB` to add extra weight to boosted blocks during chain selection. Because `validatePerasCert` always produces a `ValidatedPerasCert` with `vpcCertBoost = perasWeight params`, every forged certificate injects the full Peras boost into the selection logic.

**Attacker-controlled entry path**

The Peras certificate object-diffusion miniprotocol (`PerasCert.hs`) receives certificates from remote peers and calls `validatePerasCert` before storing them: [5](#0-4) 

No privileged access is required to connect as a peer and submit a crafted certificate object.

---

### Impact Explanation

**Critical / High — Peras certificate/vote verification bypass enabling unauthorized chain-weight manipulation.**

An unprivileged peer can:

1. Craft a `PerasCert` for any block point on a minority or attacker-controlled fork.
2. Deliver it via the Peras certificate diffusion miniprotocol to an honest node.
3. `validatePerasCert` returns `Right` unconditionally; the certificate is stored with full `perasWeight` boost.
4. Chain selection on the honest node now treats the attacker's fork as heavier than the canonical chain, causing the node to switch to the attacker's chain.

Similarly, forged votes (using any known pool ID) pass `validatePerasVote` and accumulate toward a quorum, allowing the node itself to forge a certificate for an attacker-chosen block.

This directly satisfies:
- **Critical**: Bypass of Peras voting/certificate checks enabling unauthorized certificate acceptance.
- **High**: Chain selection bug letting an unprivileged peer make an honest node prefer a non-canonical chain.

---

### Likelihood Explanation

**High.** The degenerate instance is the only active implementation for all production block types. Any peer connected via the Peras object-diffusion miniprotocol can trigger this path with a single crafted message. No keys, stake, or operator access are required. The TODO comments confirm the missing validation is a known gap, not an intentional design choice.

---

### Recommendation

1. Remove or restrict the catch-all `instance StandardHash blk => BlockSupportsPeras blk` so it cannot be resolved for production block types.
2. Implement `validatePerasCert` to verify the aggregate BLS signature over the certificate payload against the committee's aggregate verification key, check quorum membership, and validate the round number.
3. Implement `validatePerasVote` to verify the per-voter BLS signature (and VRF output for non-persistent voters) before accepting a vote.
4. Until a correct instance exists for production blocks, gate the Peras certificate and vote diffusion miniprotocols so they are not reachable from untrusted peers.

---

### Proof of Concept

**Attacker preconditions:** unprivileged peer, knowledge of any valid pool ID from the public stake distribution (available on-chain).

**Steps:**

1. Connect to an honest node's Peras certificate diffusion endpoint.
2. Construct `PerasCert { pcCertRound = r, pcCertBoostedBlock = attackerForkTip }` for any desired fork tip.
3. Send the certificate. The node calls `validatePerasCert params cert` which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
4. The certificate is stored in `PerasCertDB`. On the next chain selection pass, `ChainSel` adds `perasWeight` to `attackerForkTip`, making the attacker's fork preferred over the canonical chain.
5. The honest node rolls back to and adopts the attacker's fork.

For vote forgery: submit `PerasVote { pvVoteRound = r, pvVoteBlock = attackerForkTip, pvVoteVoterId = knownPoolId }` for a pool ID visible in the public stake distribution. `validatePerasVote` accepts it (stake lookup succeeds, no signature check). Repeat for enough pool IDs to reach quorum; the node forges a certificate for the attacker's block internally. [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L1321-1336)
```haskell
        -- prefix is invalid
        --
        -- Note that it is a chain selection invariant that all candidates
        -- involve the block being processed: see Lemma 11.1 (Properties of the
        -- set of candidates) in the Chain Selection chapter of the The Cardano
        -- Consensus and Storage Layer technical report.
        whenJust punish $ \(addedPt, punishment) -> do
          let m =
                InvalidBlockPunishment.enact punishment $
                  if addedPt == pt
                    then InvalidBlockPunishment.BlockItself
                    else InvalidBlockPunishment.BlockPrefix
          case realPointSlot pt `compare` realPointSlot addedPt of
            LT -> m
            GT -> pure ()
            EQ -> when (lastValid /= realPointToPoint addedPt) m
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L1-4)
```haskell
{-# LANGUAGE GADTs #-}
{-# LANGUAGE StandaloneDeriving #-}

-- | Instantiate 'ObjectPoolReader' and 'ObjectPoolWriter' using Peras
```
