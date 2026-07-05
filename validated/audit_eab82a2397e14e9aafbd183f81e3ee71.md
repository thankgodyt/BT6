### Title
Peras Certificate Validation Stub Always Accepts Any Peer-Supplied Certificate — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must reject cryptographically or semantically invalid Peras certificates received from peers. A universal degenerate instance (`instance StandardHash blk => BlockSupportsPeras blk`) is the only instance in the codebase and its `validatePerasCert` unconditionally returns `Right` — i.e., every certificate is accepted without any check. The production-path pool writer (`makePerasCertPoolWriterFromChainDB`) calls exactly this stub. An unprivileged peer can therefore inject arbitrary, forged Peras certificates into the local `PerasCertDB` / `ChainDB`, bypassing all certificate verification.

---

### Finding Description

**Root cause — degenerate instance always succeeds:**

In `SupportsPeras.hs`, the only `BlockSupportsPeras` instance is explicitly labelled a placeholder:

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

No cryptographic check (BLS aggregate signature, VRF proof, committee membership, round number bounds, boosted-block validity) is performed. Every certificate is wrapped in `ValidatedPerasCert` and returned as valid.

**Production call-site — `makePerasCertPoolWriterFromChainDB`:**

The function explicitly documented as "for actual production use" passes this stub directly as the validation callback:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and only rejects a batch when at least one `Left` is returned. Because the stub never returns `Left`, every batch is accepted unconditionally. [3](#0-2) 

The same pattern applies to `validatePerasVote` in `makePerasVotePoolWriterFromChainDB`, which also calls the stub via `mkPerasParams`: [4](#0-3) 

Additionally, `getPerasCertInBlock` in the same degenerate instance always returns `Nothing`, meaning Peras certificates embedded in blocks are never extracted or applied during chain selection: [5](#0-4) 

---

### Impact Explanation

Peras certificates carry a configurable `perasWeight` boost that directly influences chain selection. A certificate accepted into the `PerasCertDB` / `ChainDB` can cause the local node to prefer a boosted (potentially adversarial) chain over the honest canonical chain. Because `validatePerasCert` never rejects, an unprivileged peer connected via the ObjectDiffusion mini-protocol can:

1. Forge certificates for arbitrary rounds and arbitrary block points.
2. Have them accepted and stored without any BLS signature, committee membership, or quorum check.
3. Influence chain selection in favour of a non-canonical chain via the Peras boost weight.

This matches the allowed impact: **bypass of Peras certificate/vote verification checks enabling unauthorized certificate acceptance**, and a **chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The ObjectDiffusion mini-protocol for Peras certificates is defined and the production pool-writer (`makePerasCertPoolWriterFromChainDB`) is the intended wiring point. Any peer that can establish an ObjectDiffusion connection and send a well-formed (serialisable) `PerasCert` message triggers the vulnerable path. No special privileges, keys, or stake are required — only a network connection to the node.

---

### Recommendation

1. **Replace the degenerate `BlockSupportsPeras` instance** with a concrete, era-aware instance (or instances) for `CardanoBlock` / Shelley-based eras that performs full BLS aggregate-signature verification, committee-membership checks, round-number bounds validation, and boosted-block point validation before returning `Right`.
2. **Implement `getPerasCertInBlock`** for the relevant eras so that certificates embedded in blocks are extracted and applied during chain selection.
3. Until the real implementation is ready, **do not wire the ObjectDiffusion Peras-cert mini-protocol** into the production node, mirroring the pattern used for other not-yet-active features.

---

### Proof of Concept

An attacker peer:

1. Connects to a node via the ObjectDiffusion mini-protocol for Peras certificates.
2. Sends a batch containing a single `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to an adversarial block.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{..}` unconditionally.
4. The certificate is timestamped and added to the `ChainDB` via `ChainDB.addPerasCertAsync`.
5. The node's chain selection now treats the adversarial block as boosted by `perasWeight`, potentially switching to a non-canonical chain.

No cryptographic material, stake, or operator access is required at any step.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L387-389)
```haskell
  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-152)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```
