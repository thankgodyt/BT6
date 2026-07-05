### Title
Incomplete Peras Certificate Validation Allows Unauthorized Certificate Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` (success) for every certificate it receives, performing no cryptographic or structural validation. Any unprivileged peer can inject an arbitrary `PerasCert` through the ObjectDiffusion miniprotocol, and it will be accepted, stored, and used to boost a block in chain selection.

### Finding Description
The universal `BlockSupportsPeras blk` instance in `SupportsPeras.hs` provides the production implementation of `validatePerasCert`. The implementation is explicitly marked as a TODO stub and always returns `Right` regardless of the certificate's content:

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

This stub is wired directly into the production inbound certificate processing path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`: [2](#0-1) 

`processCerts` calls this validator on every inbound certificate from a peer. Because the validator always returns `Right`, every certificate passes and is added to the database: [3](#0-2) 

The analog to the external report is direct: just as `proposeMajorityMetaVesTAmendment` fails to validate the length/format of `_callData` before processing it, `validatePerasCert` fails to validate any property of the certificate before accepting it. Both allow malformed or adversarially crafted input to pass through a critical validation gate.

### Impact Explanation
A `ValidatedPerasCert` carries a `vpcCertBoost` weight that is applied to the boosted block during chain selection. By injecting a certificate with an arbitrary `pcCertBoostedBlock` pointing to any block hash the attacker chooses, an adversary can cause an honest node to assign extra chain weight to a non-canonical block. This constitutes a bypass of Peras certificate verification that enables unauthorized certificate acceptance and can distort chain selection. [4](#0-3) 

### Likelihood Explanation
The ObjectDiffusion miniprotocol for Peras certificates is reachable by any peer that connects to the node. No special privileges, keys, or stake are required. The attacker only needs to craft a `PerasCert` CBOR message with a desired `pcCertRound` and `pcCertBoostedBlock` and send it over the wire. The `processCerts` path is the standard inbound handler for all peer-supplied certificates. [5](#0-4) 

### Recommendation
Replace the stub `validatePerasCert` implementation with a real validator that checks:
1. The aggregate BLS signature over `(pcCertRound, pcBoostedBlock)` against the expected committee verification keys for that round.
2. That the set of signers meets the quorum threshold for the given epoch's stake distribution.
3. That `pcCertRound` falls within the valid window relative to the current tip.

Until the full committee-selection plumbing is in place, at minimum the stub should be gated behind a compile-time flag or feature flag so it is never reachable in a production build. The existing `PerasCert.V1` module already defines the concrete BLS-based certificate structure and its `FromCBOR`/`ToCBOR` instances, which should be the basis for the real validator. [6](#0-5) 

### Proof of Concept
1. Connect to a node running this code as an unprivileged peer via the ObjectDiffusion miniprotocol for Peras certificates.
2. Craft a `PerasCert` CBOR payload with `pcCertRound = N` (any round) and `pcCertBoostedBlock = <hash of attacker-chosen block>`.
3. Send the certificate batch to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
5. The certificate is stored in the `PerasCertDB` / `ChainDB` via `addCert`.
6. The attacker-chosen block now carries the Peras boost weight in chain selection, potentially causing the node to prefer a non-canonical chain. [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L214-219)
```haskell
data ValidatedPerasVote blk = ValidatedPerasVote
  { vpvVote :: !(PerasVote blk)
  , vpvVoteStake :: !PerasVoteStake
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L91-110)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L49-86)
```haskell
-- | Concrete Peras certificates using BLS signatures
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
  }
  deriving (Show, Eq)

instance FromCBOR PerasCert where
  fromCBOR = do
    decodeListLenOf 4
    pcRoundNo <- fromCBOR
    pcBoostedBlock <- fromCBOR
    pcVoters <- fromCBOR
    pcSignature <- fromCBOR
    pure
      PerasCert
        { pcRoundNo
        , pcBoostedBlock
        , pcVoters
        , pcSignature
        }

instance ToCBOR PerasCert where
  toCBOR cert =
    encodeListLen 4
      <> toCBOR (pcRoundNo cert)
      <> toCBOR (pcBoostedBlock cert)
      <> toCBOR (pcVoters cert)
      <> toCBOR (pcSignature cert)

```
