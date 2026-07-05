### Title
Degenerate `validatePerasCert` Instance Unconditionally Accepts All Inbound Peras Certificates Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` typeclass declares a `validatePerasCert` method intended to cryptographically validate Peras certificates received from peers. The only deployed instance of this typeclass is a degenerate stub that unconditionally returns `Right` for every certificate, performing zero validation. Both production inbound-certificate handlers (`makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB`) wire this stub directly as their validation function. Any unprivileged peer can therefore inject arbitrary, structurally-minimal Peras certificates that are accepted, stored in the ChainDB, and applied as chain-selection boosts.

### Finding Description

**Root cause — missing implementation wired into production path**

`BlockSupportsPeras` declares:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The only concrete instance in the codebase is the catch-all degenerate instance:

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

This stub is not isolated to tests. Both production pool-writer constructors pass it verbatim as the `validateCert` argument to `processCerts`:

```haskell
-- makePerasCertPoolWriterFromCertDB (line 103)
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place

-- makePerasCertPoolWriterFromChainDB (line 126)
-- TODO replace when actual plumbing is in place
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` then calls `validateCert` on every inbound certificate and, because the stub always returns `Right`, every certificate passes and is forwarded to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

In the ChainDB path the accepted certificate is stored and triggers chain-selection side-effects via `ChainDB.addPerasCertAsync chainDB`.

**Analogy to the reference vulnerability**

The original report describes a manager contract that declares a `beneficiaryWithdraw()` interface but never provides an implementation, making the operation permanently unreachable. Here the `BlockSupportsPeras` class declares a `validatePerasCert` interface with a full signature, but the only deployed implementation is a stub that performs no work — the validation gate is permanently open rather than permanently closed, which is the mirror-image failure mode with equivalent severity.

**Secondary missing implementation: `getVotingCommitteeForElection`**

A second incomplete implementation exists in `AcrossEpochs.hs`:

```haskell
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
``` [4](#0-3) 

This function is exported from the module but is not yet called from any production site, so it does not currently create a reachable crash path. However, it means cross-epoch vote/certificate validation (the entire purpose of `InterEpochVotingCommittee`) is unimplemented and will panic if ever wired in. The primary finding above is the directly exploitable one.

### Impact Explanation

**Severity: Critical — Bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain-selection manipulation.**

A Peras certificate carries a `vpcCertBoost` weight that is applied during chain selection (`preferAnchoredCandidate`). Because `validatePerasCert` always returns `Right`, an attacker who can send any syntactically well-formed `PerasCert` message over the Peras certificate diffusion mini-protocol can:

1. Inject a certificate claiming to boost an arbitrary block at an arbitrary round number.
2. Have that certificate stored in the ChainDB of every honest node that receives it.
3. Cause honest nodes to apply the Peras boost to the attacker's chosen block, making them prefer a non-canonical or adversarially-selected chain over the honest chain.

This directly violates the Peras safety property that only a quorum-certified block may receive a boost, and it does so without requiring any stake, keys, or privileges.

### Likelihood Explanation

**High.** The entry point is the Peras certificate object-diffusion mini-protocol, which is a standard peer-to-peer channel reachable by any node that can establish a connection. No special privileges, stake, or cryptographic material are required. The attacker only needs to construct a `PerasCert` value with a chosen `pcCertRound` and `pcCertBoostedBlock` and send it; the node will accept and store it unconditionally. The TODO comments and the linked issue (`cardano-peras/issues/120`) confirm this is a known placeholder, not an intentional design.

### Recommendation

1. Replace the degenerate `validatePerasCert` stub with a real implementation that verifies the aggregate BLS signature over the certificate's voter set, checks committee membership and quorum threshold, and validates the election ID against the current epoch's `InterEpochVotingCommittee`.
2. Remove the `instance StandardHash blk => BlockSupportsPeras blk` catch-all instance or restrict it to test-only modules so that the compiler enforces a real implementation for production block types.
3. Implement `getVotingCommitteeForElection` in `AcrossEpochs.hs` before it is wired into any validation path.
4. Add a property test asserting that `validatePerasCert` rejects a certificate with a forged or missing aggregate signature.

### Proof of Concept

```
1. Attacker connects to an honest node via the Peras certificate
   object-diffusion mini-protocol.

2. Attacker constructs a minimal PerasCert:
     PerasCert { pcCertRound      = <target round>
               , pcCertBoostedBlock = <attacker-chosen block point> }

3. Attacker sends the certificate in a batch to the node.

4. makePerasCertPoolWriterFromChainDB.opwAddObjects is invoked.
   processCerts calls:
     validatePerasCert mkPerasParams cert
   which unconditionally returns:
     Right ValidatedPerasCert { vpcCert = cert
                               , vpcCertBoost = perasWeight mkPerasParams }

5. The certificate passes partitionEithers with zero errors.

6. ChainDB.addPerasCertAsync stores the certificate and triggers
   chain selection with the Peras boost applied to the attacker's block.

7. The honest node now prefers the attacker-chosen chain segment,
   diverging from the canonical chain.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/AcrossEpochs.hs (L68-74)
```haskell
-- | Get the voting committee corresponding to an election, if any
getVotingCommitteeForElection ::
  ElectionId crypto ->
  InterEpochVotingCommittee crypto committee ->
  Maybe (VotingCommittee crypto committee)
getVotingCommitteeForElection _electionId _interEpochVotingCommittee = do
  error "TODO: implement getVotingCommitteeForElection"
```
