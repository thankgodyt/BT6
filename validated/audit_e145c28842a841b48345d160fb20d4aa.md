### Title
Unconditional Peras Certificate Acceptance Allows Any Peer to Inject Certificates for Arbitrary Rounds - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `validatePerasCert` function in the universal `BlockSupportsPeras` instance is a stub that unconditionally returns `Right` (success) for every inbound certificate, performing zero cryptographic or round-validity checks. The production inbound-certificate pipeline (`processCerts`) calls this stub directly. Any unprivileged peer can therefore send a crafted `PerasCert` claiming any round number and any boosted block, and the node will accept and store it, triggering chain-selection side-effects via the Peras boost weight.

### Finding Description

`BlockSupportsPeras` is the typeclass that governs Peras certificate validation. Its universal instance — used for all block types — provides the following stub implementation:

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

This stub is wired directly into the production inbound-certificate pipeline. Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` pass `(validatePerasCert mkPerasParams)` as the validation callback to `processCerts`:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  (validatePerasCert mkPerasParams)   -- always Right
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` itself is correctly structured: it calls the supplied validator and rejects the batch if any certificate fails. But because the validator never fails, every certificate from every peer is accepted and timestamped with the current wall-clock arrival time:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

The checks that are entirely absent from `validatePerasCert`:
- Committee membership / VRF eligibility of the certificate issuer
- Cryptographic signature over the certificate body
- Quorum threshold (sufficient stake-weighted votes backing the certificate)
- Round-number validity (the certificate's round must correspond to a live or recent Peras round, not an arbitrary past or future round)
- Boosted-block validity (the block referenced by `pcCertBoostedBlock` must exist and be on a valid chain)

The analog to the external report is direct: in `OptimismGovernorV5`, the Manager can push the `proposalDeadline` backward to reopen a completed vote. Here, the missing round-validity check means any peer can inject a certificate for any past round — effectively "reopening" a round that the protocol considers finalized — and the node will treat it as a legitimate boost.

### Impact Explanation

An accepted `ValidatedPerasCert` is stored in the `PerasCertDB` and, via `ChainDB.addPerasCertAsync`, triggers chain selection. Chain selection uses the Peras boost weight (`vpcCertBoost`) to prefer chains that include the boosted block: [4](#0-3) 

A crafted certificate for a past round pointing at an attacker-chosen block causes the honest node to artificially prefer that block's chain over the canonical chain. Because the certificate carries a full `perasWeight` boost regardless of actual quorum, a single adversarial peer can shift chain selection without controlling any stake. This constitutes a **bypass of Peras certificate verification enabling unauthorized certificate acceptance**, matching the Critical impact tier.

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is a standard peer-to-peer channel. Any node that connects to the victim and sends a well-formed CBOR-encoded `PerasCert` (two fields: `PerasRoundNo` and `Point blk`) will have it accepted. No stake, no keys, no prior relationship is required. The `PerasCert` serialisation is public: [5](#0-4) 

Likelihood is **High** once Peras is active on a live network: the attack requires only a TCP connection and knowledge of the wire format.

### Recommendation

Replace the stub with a real implementation that enforces, at minimum:

1. **Round-number bounds**: reject certificates whose `pcCertRound` is outside the current live window (e.g., more than `perasCertMaxRounds` rounds in the past or any number of rounds in the future).
2. **Quorum proof**: verify that the certificate is backed by a valid aggregate signature or a sufficient set of individual vote signatures from eligible committee members.
3. **Boosted-block existence**: verify that `pcCertBoostedBlock` refers to a block that is known and on a valid chain.

Until the full cryptographic scheme is in place, at minimum add a round-number staleness guard analogous to the `latestCertSeenIsNotExpired` check already present in the cert-inclusion logic:

```haskell
-- currRoundNo <= _A + certRound  (cert is not expired)
-- certRound  <= currRoundNo      (cert is not from the future)
``` [6](#0-5) 

### Proof of Concept

On a private testnet with Peras enabled:

1. Connect to the victim node via the object-diffusion mini-protocol for Peras certificates.
2. Construct a `PerasCert` with:
   - `pcCertRound = <any past round, e.g. round 0>`
   - `pcCertBoostedBlock = <point of a block on a minority fork>`
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
4. The certificate is stored with `WithArrivalTime now` and forwarded to `ChainDB.addPerasCertAsync`.
5. Chain selection re-runs with the injected boost weight applied to the minority-fork block.
6. Observe the victim node switching its selection to the minority fork despite it being shorter/weaker by Praos density. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L1-5)
```haskell
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeFamilies #-}
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/Inclusion.hs (L265-287)
```haskell
-- | latestCertSeenIsNotExpired: the latest certificate seen has not yet expired
-- according to the current round number and the Peras protocol parameters
latestCertSeenIsNotExpired ::
  PerasCertInclusionView cert blk ->
  Pred PerasCertInclusionRule
latestCertSeenIsNotExpired
  PerasCertInclusionView
    { perasParams
    , currRoundNo
    , latestCertSeen
    } =
    LatestCertSeenIsNotExpired latestCertSeenRoundNo
      := Bool (currRoundNo <= _A + latestCertSeenRoundNo)
   where
    latestCertSeenRoundNo =
      lcsCertRound latestCertSeen

    _A =
      PerasRoundNo $
        unPerasCertMaxRounds $
          perasCertMaxRounds $
            perasParams

```
