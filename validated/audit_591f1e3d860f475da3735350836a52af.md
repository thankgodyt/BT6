### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Returns `Right` Without Checking Any Certificate Fields — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance used for all block types contains a stub `validatePerasCert` that unconditionally returns `Right` without inspecting any field of the supplied certificate. Because this function is wired directly into the network-facing Peras certificate ingest path, any unprivileged peer can inject an arbitrarily crafted `PerasCert` that will be accepted, timestamped, and stored in the `PerasCertDB` or `ChainDB` as if it were fully validated. The accepted certificate's boost weight then participates in chain selection, allowing a peer to steer an honest node toward a non-canonical chain without holding any stake or keys.

### Finding Description

The degenerate catch-all instance of `BlockSupportsPeras` is defined in the production source file `SupportsPeras.hs`:

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

The function accepts any `PerasCert blk` value and wraps it in `ValidatedPerasCert` with a non-zero `vpcCertBoost` derived from `perasWeight params`, without checking the certificate's round number, boosted-block pointer, or any cryptographic field. The `PerasValidationErr` data type is also a stub with a single constructor and no payload, so there is no mechanism to express a real rejection.

This stub is wired into two production-facing `ObjectPoolWriter` constructors in `PerasCert.hs`:

```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { ...
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams)   -- always Right
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    ...
    }
``` [2](#0-1) 

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { ...
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [3](#0-2) 

`processCerts` partitions the validation results and throws `PerasCertValidationError` only when the left partition is non-empty. Because `validatePerasCert` never produces a `Left`, the right partition always contains every inbound certificate, and all of them are unconditionally stored:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Once stored, each `ValidatedPerasCert` contributes its `vpcCertBoost` to the `PerasWeightSnapshot` returned by `getWeightSnapshot`, which is consumed by chain selection. A certificate boosting an attacker-controlled block therefore shifts the node's chain preference without any cryptographic proof of committee membership, quorum, or signature validity.

The analog to the OFT finding is exact: `quoteSend` returned `{nativeFee, lzTokenFee}` and the code used `nativeFee` while silently forwarding the unvalidated `lzTokenFee` to `send()`. Here, `validatePerasCert` returns `ValidatedPerasCert {vpcCert, vpcCertBoost}` and the downstream chain-selection code uses `vpcCertBoost` while the `vpcCert` payload is forwarded to storage completely unvalidated — the missing zero-check on `lzTokenFee` maps directly to the missing cryptographic check on `vpcCert`.

A secondary instance of the same pattern exists in `validatePerasVote`: it checks stake-distribution membership (analogous to checking `nativeFee`) but never verifies the vote signature (analogous to not checking `lzTokenFee`), so any registered pool identity can inject votes for arbitrary targets without possessing the corresponding signing key. [5](#0-4) 

### Impact Explanation

An unprivileged peer can inject `PerasCert` objects that boost an attacker-chosen block. Because the boost weight is added to the chain-selection score without any validation of committee membership, quorum, or BLS aggregate signature, the attacker can make an honest node prefer a non-canonical or adversarially-controlled chain. This constitutes a **High** chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Peras protocol.

### Likelihood Explanation

The code is in a production source file and is actively wired into the live object-diffusion ingest path. Any peer that can open a connection and send Peras certificate objects over the mini-protocol can trigger this path. No stake, keys, or operator access are required. The TODO comments confirm the stub is known to be incomplete, but the code is already deployed in the network-facing layer.

### Recommendation

1. Implement real cryptographic validation inside `validatePerasCert`: verify the BLS aggregate signature over the claimed voter set, confirm the round number is within the valid window, and confirm the boosted block point is a known block on the candidate chain.
2. Similarly, add vote-signature verification to `validatePerasVote` before accepting a vote as valid.
3. Until real validation is implemented, gate the `ObjectPoolWriter` constructors behind a feature flag or return `Left PerasValidationErr` unconditionally so that no unvalidated certificate can influence chain selection.
4. Add negative-scenario tests (analogous to the fix in the referenced OFT PR #1029) that confirm crafted certificates with invalid signatures, out-of-range round numbers, and unknown boosted blocks are rejected.

### Proof of Concept

1. Attacker connects to a target node via the Peras object-diffusion mini-protocol.
2. Attacker constructs a `PerasCert blk` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <attacker-controlled block point>` — no valid BLS signature or committee proof is required.
3. The certificate is delivered to `opwAddObjects` in `makePerasCertPoolWriterFromChainDB`.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }` unconditionally.
5. `ChainDB.addPerasCertAsync` stores the certificate; `getWeightSnapshot` subsequently returns a snapshot that includes the attacker's boost for the attacker-chosen block.
6. Chain selection now scores the attacker-controlled chain higher than the canonical chain by the Peras boost weight, causing the honest node to switch to the attacker's fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-109)
```haskell
makePerasCertPoolWriterFromCertDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  PerasCertDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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
