### Title
Peras Certificate Validation Bypass Allows Any Peer to Inject Arbitrary Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production instance of `validatePerasCert` in `SupportsPeras.hs` unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Any unprivileged peer can send a crafted `PerasCert` over the network that will be accepted and stored, then used to boost an arbitrary block's chain-selection weight, causing honest nodes to prefer a non-canonical chain.

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gating function that must approve every inbound Peras certificate before it is stored and acted upon. The production instance (the only instance, used for all block types via a blanket `StandardHash blk =>` instance) is:

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

This function is called unconditionally on every certificate received from a remote peer inside `processCerts`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

Both the `PerasCertDB`-backed and `ChainDB`-backed pool writers pass `validatePerasCert mkPerasParams` as the validation callback: [3](#0-2) 

Because `validatePerasCert` always returns `Right`, the `(errs, _)` branch is never taken. Every certificate from every peer passes validation and is stored as a `ValidatedPerasCert` carrying a `vpcCertBoost` weight equal to `perasWeight params`.

The analog to the external report is exact: just as Audius's `evaluateProposalOutcome` lacked a meaningful caller restriction (any staker could call it, but the restriction served no purpose), here the certificate validation gate exists in the interface but the implementation removes all restrictions — any peer, with any certificate content, passes.

### Impact Explanation

A stored `ValidatedPerasCert` directly influences chain selection. The `vpcCertBoost` field is used as extra weight when comparing chains: [4](#0-3) 

An attacker who injects a certificate for a block on a weaker fork causes honest nodes to assign that fork a higher chain-selection weight (by `perasWeight params = 15` per `mkPerasParams`), potentially making them switch to a non-canonical chain. This is a chain-selection manipulation reachable by any unprivileged peer with network access.

Impact classification: **High** — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

### Likelihood Explanation

The attack requires only that a peer send a well-formed `PerasCert` CBOR message (round number + block point) targeting a block on a weaker fork. No key material, stake, or privileged access is needed. The network diffusion layer (`makePerasCertPoolWriterFromChainDB`) is the direct inbound path and is active on every production node. [5](#0-4) 

Likelihood: **High** — the bypass is total (no check is performed), the entry path is the standard peer-to-peer certificate diffusion miniprotocol, and exploitation requires only crafting a valid CBOR-encoded certificate struct.

### Recommendation

Implement the missing validation inside `validatePerasCert` before the Peras certificate diffusion path is enabled in production. At minimum, the implementation must:

1. Verify the aggregate BLS signature over `(roundNo, boostedBlock)` against the claimed voter set.
2. Verify that the claimed voter set collectively holds stake above the quorum threshold (`stakeAboveThreshold`).
3. Verify that each voter in the set was a legitimate committee member for the claimed round (VRF eligibility proofs for non-persistent members).

Until these checks are in place, the certificate diffusion path should be disabled or gated behind a feature flag that is off by default. The existing `TODO` at issue `#120` should be treated as a security-critical blocker.

### Proof of Concept

1. Connect to a target node as a peer via the Peras certificate object-diffusion miniprotocol.
2. Construct a `PerasCert` with:
   - `pcCertRound` = any valid round number
   - `pcCertBoostedBlock` = the block point of a block on a weaker competing fork
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })` unconditionally.
4. The certificate is stored in the `PerasCertDB` / `ChainDB`.
5. Chain selection now assigns the targeted weaker-fork block an extra weight of 15, potentially causing the node to switch to the attacker-chosen fork. [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-137)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
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
