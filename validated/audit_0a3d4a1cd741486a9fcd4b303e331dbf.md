### Title
`BlockSupportsPeras` Degenerate Instance Unconditionally Accepts Any Peras Certificate Without Validation, Enabling Crafted-Certificate Chain-Selection Bypass — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance used for all Cardano blocks implements `validatePerasCert` as an unconditional `Right` — it performs zero validation of the certificate's content (round number, boosted block, committee membership, or cryptographic proof). An unprivileged peer that can reach the Peras object-diffusion mini-protocol can send a crafted `PerasCert` pointing to any block in the node's VolatileDB, have it accepted as "validated", stored in the `PerasCertDB`, and trigger chain selection that boosts a non-canonical or adversarial block.

---

### Finding Description

The degenerate `BlockSupportsPeras` instance is declared as a catch-all for all `StandardHash blk` types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
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

`validatePerasCert` returns `Right` for **every** certificate regardless of its `pcCertRound` or `pcCertBoostedBlock` fields. No committee membership check, no signature/proof check, no round-number range check, and no check that the boosted block is a legitimate candidate.

This function is the one wired directly into the live object-diffusion inbound path:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)   -- ← always Right
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` partitions results into errors and successes; because `validatePerasCert` never produces an error, every inbound certificate is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

Once stored, `chainSelSync` processes the certificate and, if the boosted block is present in the VolatileDB, immediately triggers chain selection for it:

```haskell
-- Trigger chain selection for the boosted block.
lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [4](#0-3) 

The same pattern applies to `validatePerasVote`: it only checks stake-distribution membership but performs no cryptographic verification of the vote's content, meaning a peer can forge votes for any block using any valid voter ID. [5](#0-4) 

---

### Impact Explanation

**Critical / High — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

A crafted `PerasCert` from an unprivileged peer is unconditionally accepted as valid. Because the certificate carries a `pcCertBoostedBlock` field that directly drives `chainSelectionForBlock`, the adversary can:

1. Boost any block already in the node's VolatileDB (including a minority or adversarial fork tip), causing the node to re-evaluate chain selection with artificial extra weight on that block.
2. Inject certificates with arbitrary `pcCertRound` values, polluting the `PerasCertDB` and disrupting the round-based quorum logic that governs legitimate Peras voting.

Both outcomes allow an unprivileged network peer to make an honest node prefer a non-canonical chain beyond the intended Peras security assumptions, satisfying the **High** chain-selection impact criterion, and additionally constitute a **Critical** bypass of Peras certificate checks.

---

### Likelihood Explanation

Any peer that can establish a connection and speak the Peras object-diffusion mini-protocol can exploit this. No stake, no keys, and no prior authentication are required — only the ability to send a well-formed CBOR-encoded `PerasCert` message. The Peras object-diffusion infrastructure is wired into the live `ChainDB` and chain-selection path in the current codebase, making this reachable whenever the Peras cert diffusion protocol is active.

---

### Recommendation

Replace the unconditional `Right` stub with a real implementation that verifies:

1. **Committee membership and cryptographic proof** — the certificate must carry a valid aggregate signature (or equivalent proof) from a quorum of the elected Peras committee for the claimed round.
2. **Round-number range** — `pcCertRound` must be within the current or recent Peras window; stale or future rounds must be rejected.
3. **Boosted-block ancestry** — `pcCertBoostedBlock` must be a known, non-finalized block that is a plausible candidate (e.g., within the current volatile window).

Until the real implementation is ready, the stub should at minimum reject all inbound certificates (return `Left PerasValidationErr` unconditionally) rather than accept them all, so that the diffusion path is safely inert.

---

### Proof of Concept

Attack sequence against a node with Peras cert diffusion active:

1. Adversary identifies block `B_adv` on a minority fork that is present in the target node's VolatileDB (e.g., learned via the ChainSync protocol).
2. Adversary constructs a `PerasCert { pcCertRound = <any>, pcCertBoostedBlock = point(B_adv) }` — no committee keys or signatures needed.
3. Adversary sends the cert via the Peras object-diffusion mini-protocol.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally. [6](#0-5) 
5. `ChainDB.addPerasCertAsync` stores the cert; `chainSelSync` fires `chainSelectionForBlock` for `B_adv`. [4](#0-3) 
6. The node now evaluates `B_adv`'s chain with the artificial Peras boost weight, potentially switching to the adversarial fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-358)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-185)
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
    -- Some certs are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that cert validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasCertValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
