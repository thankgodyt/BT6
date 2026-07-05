### Title
Peras Certificate Validation Stub Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The production `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every certificate received, performing zero validation. Any unprivileged peer can craft a `PerasCert` claiming to boost an arbitrary block in an arbitrary round, and the node will accept it, add it to the `PerasCertDB`, and trigger chain selection with the attacker-controlled boost weight.

### Finding Description
The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate for accepting inbound Peras certificates. The only deployed instance is a catch-all `instance StandardHash blk => BlockSupportsPeras blk` whose implementation is:

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

This stub is wired directly into the inbound certificate processing path. `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` both pass `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) [3](#0-2) 

`processCerts` validates each inbound certificate and, if all pass, adds them to the database. Because `validatePerasCert` always returns `Right`, every certificate from every peer passes: [4](#0-3) 

The accepted certificate is then stored in `PerasCertDB` and triggers chain selection via `addPerasCert` in the ChainDB, which applies the certificate's `vpcCertBoost` weight to the boosted block: [5](#0-4) 

The `PerasCert blk` data type in this instance carries only `pcCertRound :: PerasRoundNo` and `pcCertBoostedBlock :: Point blk` — no signature field — so there is nothing to verify even if the stub were replaced with a non-trivial body: [6](#0-5) 

The analog to the external report is exact: just as `setWhitelistedBidder` performs no check to exclude the pool manager from bidding, `validatePerasCert` performs no check to exclude any peer from injecting a certificate for any block.

### Impact Explanation
An unprivileged peer can send a crafted `PerasCert` naming any block hash and any round number. The receiving node accepts it unconditionally, stores it, and re-runs chain selection with the attacker-supplied boost weight applied to the attacker-chosen block. This can cause the honest node to prefer a non-canonical or adversarially-chosen chain over the canonical one, constituting a **High** chain-selection integrity violation: an unprivileged peer makes an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

### Likelihood Explanation
The vulnerability is reachable by any connected peer via the object-diffusion mini-protocol for Peras certificates. No key material, stake, or operator access is required. The attacker only needs to construct a valid CBOR-encoded `PerasCert` message with an arbitrary `pcCertRound` and `pcCertBoostedBlock`. The code path is exercised in normal node operation whenever a certificate is received from a peer.

### Recommendation
Replace the stub `validatePerasCert` implementation with a real one that:
1. Verifies the aggregate BLS signature over `(pcCertRound, pcCertBoostedBlock)` against the expected committee public keys.
2. Checks that the certificate's voter set meets the quorum threshold.
3. Verifies VRF eligibility proofs for non-persistent committee members.
4. Rejects certificates whose `pcCertBoostedBlock` does not correspond to a known block on the chain.

Until the real implementation is in place, the stub should at minimum reject all inbound certificates from peers (return `Left PerasValidationErr` unconditionally) rather than accept them all, to prevent the chain-selection manipulation vector.

The same analysis applies to `validatePerasVote`, which also omits BLS signature verification and accepts any vote from any peer claiming to be a pool operator in the stake distribution. [7](#0-6) 

### Proof of Concept
1. Connect to a target node running the Peras-enabled consensus layer.
2. Craft a CBOR-encoded `PerasCert` with `pcCertRound = N` (any round) and `pcCertBoostedBlock = <hash of attacker-chosen block>`.
3. Send it via the object-diffusion mini-protocol for Peras certificates.
4. The node calls `processCerts` → `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })`.
5. The certificate is stored in `PerasCertDB` and `addPerasCert` triggers chain selection.
6. Chain selection now applies the Peras boost weight to the attacker-chosen block, causing the node to prefer it over the canonical chain tip. [8](#0-7) [9](#0-8)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-104)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L125-126)
```haskell
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
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

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/ChainDB/Model.hs (L460-472)
```haskell
addPerasCert ::
  forall blk.
  (LedgerSupportsProtocol blk, LedgerTablesAreTrivial ExtLedgerState blk) =>
  TopLevelConfig blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  Model blk ->
  (AddPerasCertChainSelOutcome, Model blk)
addPerasCert cfg cert m
  | pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m) =
      (PerasCertIgnoredTooOld, m)
  | otherwise =
      let (certRes, perasCertModel') = PerasCertDBModel.addCert (perasCertModel m) cert
       in (PerasCertProcessed certRes, chainSelection cfg m{perasCertModel = perasCertModel'})
```
