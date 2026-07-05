### Title
`validatePerasCert` Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate it receives, performing zero cryptographic or structural validation. Because this function is the sole validation gate in the inbound certificate processing pipeline (`processCerts`), any unprivileged peer can inject a crafted `PerasCert` for an arbitrary round and block point. The accepted certificate is stored in the `PerasCertDB` and applied as a chain-selection boost, allowing the attacker to make an honest node prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory validation hook for inbound Peras certificates. The only concrete instance in the codebase is the degenerate `StandardHash blk` instance, which is the implementation used in production:

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

This stub is wired directly into the inbound certificate processing path. `processCerts` — called by both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` — applies `validatePerasCert mkPerasParams` to every certificate received from a peer that is not already in the database:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [2](#0-1) 

Because `validateCert` always returns `Right`, the `(errs, _)` branch is unreachable. Every certificate in the batch is unconditionally accepted and stored. The `makePerasCertPoolWriterFromChainDB` path then forwards the certificate to `ChainDB.addPerasCertAsync`, where it participates in chain selection as a boost for the attacker-chosen block point. [3](#0-2) 

The `PerasCert` type carries only a round number and a block point — no cryptographic proof of quorum, no committee membership evidence, no signature:

```haskell
data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
``` [4](#0-3) 

A peer can therefore craft a `PerasCert` with any `pcCertBoostedBlock` and any `pcCertRound` and have it accepted without challenge.

---

### Analog to the Original Report

The Allora bug allowed `forecastValue` to be set to any value because `ForecastElements` was not filtered for duplicates before being fed into the inference calculation. The analog here is structurally identical: the certificate validation gate (`validatePerasCert`) performs no filtering or checking of the certificate's content before it is fed into the chain-selection weight calculation. In both cases, an attacker-supplied collection/object bypasses the validation step that is supposed to constrain the output of a security-critical computation.

---

### Impact Explanation

A `ValidatedPerasCert` carries a `vpcCertBoost` of `perasWeight params`. When stored and applied to chain selection, this boost is added to the weight of `pcCertBoostedBlock`. An attacker who injects a certificate for a minority or adversarial fork causes an honest node to assign that fork a higher chain weight than the canonical chain, potentially triggering a preference for the non-canonical chain. This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Peras protocol. [5](#0-4) 

---

### Likelihood Explanation

The attack requires only a network peer connection and the ability to send a single well-formed `PerasCert` CBOR message. No stake, no keys, no prior knowledge of the chain state is required. The `PerasCert` serialisation format is public and trivially constructable. The inbound path (`ObjectDiffusion` miniprotocol → `processCerts` → `validatePerasCert`) is reachable from any connected peer.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real validation function that checks, at minimum:

1. **Quorum proof**: the certificate must embed or reference a set of votes whose aggregate stake exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
2. **Duplicate-voter filtering**: the vote list must be deduplicated by `PerasVoterId` before stake is summed (note that `votesReachQuorum` itself does not deduplicate — see below).
3. **Committee membership**: each voter must be a valid member of the committee for the given round.
4. **Cryptographic signatures**: each vote's signature must be verified against the voter's registered key.

Additionally, `votesReachQuorum` should be hardened to deduplicate its input by voter ID before summing stake, since it is an exported function whose contract does not currently enforce uniqueness:

```haskell
totalVoteStake = mconcat (vpvVoteStake <$> votes)  -- no dedup by voter ID
``` [6](#0-5) 

---

### Proof of Concept

1. Connect to a node running the current codebase as a peer via the `ObjectDiffusion` miniprotocol.
2. Construct a `PerasCert` CBOR payload with `pcCertRound = <current round>` and `pcCertBoostedBlock = <point of an adversarial fork block>`.
3. Send the certificate via the miniprotocol's object-diffusion channel.
4. `processCerts` receives the cert, calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })`.
5. The cert is stored in `PerasCertDB` and forwarded to `ChainDB.addPerasCertAsync`.
6. Chain selection now applies `perasWeight` as a boost to the adversarial fork block, causing the node to prefer the non-canonical chain. [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L266-272)
```haskell
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
  allVotesMatchTarget target =
    all ((== (getPerasVoteTarget target)) . getPerasVoteTarget)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L323-328)
```haskell
  data PerasCert blk = PerasCert
    { pcCertRound :: PerasRoundNo
    , pcCertBoostedBlock :: Point blk
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
