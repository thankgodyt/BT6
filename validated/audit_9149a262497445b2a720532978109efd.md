### Title
Peras Certificate Validation Stub Unconditionally Accepts All Inbound Certificates — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` universal instance implements `validatePerasCert` as a stub that unconditionally returns `Right` (success) for every certificate, performing zero cryptographic or structural checks. This stub is wired directly into the production inbound-certificate processing path (`makePerasCertPoolWriterFromChainDB`). Any unprivileged peer can send crafted `PerasCert` objects that pass "validation" and are added to the ChainDB, where they apply a Peras weight boost to an arbitrary block and trigger chain selection.

### Finding Description

The `BlockSupportsPeras` instance in `SupportsPeras.hs` is explicitly marked as a degenerate placeholder:

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

This is not an isolated test helper — it is the **only** `BlockSupportsPeras` instance in the repository and is consumed directly by the production object-diffusion pool writer:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` calls `validateCert` on each inbound certificate; when all return `Right`, every certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [3](#0-2) 

Because `validatePerasCert` never returns `Left`, the `(errs, _)` branch is unreachable. Every certificate a peer sends is accepted and stored, carrying the full `perasWeight` boost.

The same pattern applies to `makePerasCertPoolWriterFromCertDB` (the test-isolation path), which also calls the same stub. [4](#0-3) 

The analog to the external report is exact: just as Notional's `CompoundV2AssetAdapter` skipped the required ERC20 `approve()` prerequisite before `mint()`, the Peras inbound path skips the required cryptographic prerequisite before accepting a certificate. In both cases the missing step is the authorization gate that should prevent unauthorized objects from being accepted.

### Impact Explanation

A `ValidatedPerasCert` stored in the ChainDB carries a `vpcCertBoost = perasWeight params` value. Chain selection reads this boost when comparing candidate chains: [5](#0-4) 

An attacker who injects a certificate boosting an arbitrary block can make an honest node prefer a non-canonical or adversary-controlled chain over the honest chain, constituting a chain-selection manipulation. Because the certificate is accepted without any committee membership, quorum, or signature check, the attacker needs no stake, no keys, and no privileged access — only a peer connection.

**Impact category:** Critical — bypass of Peras certificate verification enabling unauthorized certificate acceptance and chain-selection manipulation.

### Likelihood Explanation

The object-diffusion mini-protocol is reachable by any peer that can establish a node-to-node connection. No keys, stake, or operator access are required. The attacker only needs to send a well-formed `PerasCert` CBOR message. The stub is the universal instance with no override, so every node running Peras-enabled code is affected identically.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's committee membership proof (that the signers are eligible voters for the given round).
2. The aggregate/threshold signature over `(roundNo, boostedBlock)`.
3. That the quorum threshold is met by the signing committee members' combined stake.

Until the real implementation is ready, the inbound certificate path should reject all externally received certificates (return a hard `Left`) rather than accept them unconditionally, so that the stub cannot be exploited in a deployed node.

### Proof of Concept

1. Start a node with Peras object-diffusion enabled.
2. Connect as an unprivileged peer via the node-to-node protocol.
3. Send a `PerasCert` message with `pcCertRound = <any round>` and `pcCertBoostedBlock = <target block point>` over the object-diffusion mini-protocol.
4. Observe: `processCerts` calls `validatePerasCert mkPerasParams cert` → returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}` → cert is passed to `ChainDB.addPerasCertAsync`.
5. The ChainDB now holds a "validated" certificate boosting the attacker-chosen block. Chain selection subsequently applies the weight boost, potentially causing the node to prefer the attacker's target chain over the honest chain.

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
