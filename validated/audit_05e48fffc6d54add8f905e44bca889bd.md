### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection Weight - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production default `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional stub that always returns `Right` — accepting every inbound certificate without any cryptographic or structural verification. An unprivileged peer can send a crafted `PerasCert` pointing to any block, have it accepted as "validated", and cause the receiving node to apply a Peras weight boost to that block during chain selection, potentially making a non-canonical chain appear heavier than the honest chain.

### Finding Description

In `Ouroboros/Consensus/Block/SupportsPeras.hs`, the universal `BlockSupportsPeras` instance (which applies to all block types via `instance StandardHash blk => BlockSupportsPeras blk`) implements `validatePerasCert` as a no-op stub:

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

No signature check, no committee membership check, no round-number bounds check, and no boosted-block existence check is performed. The function unconditionally wraps the caller-supplied certificate in `ValidatedPerasCert` and assigns it the full `perasWeight` boost.

The production inbound path in `makePerasCertPoolWriterFromChainDB` calls this stub directly:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` then adds every certificate that passes this non-validation to the ChainDB: [3](#0-2) 

Once a certificate is stored, `implGetWeightSnapshot` builds a non-empty `PerasWeightSnapshot` from it, which activates the Peras-weighted branch of `preferAnchoredCandidate`: [4](#0-3) 

Chain selection then compares fragments using `wsvTotalWeight`, which adds the injected `wsvWeightBoost` to the block number: [5](#0-4) 

### Impact Explanation

An unprivileged peer can inject a `PerasCert` that boosts an arbitrary block — including a block on a shorter or adversarial fork — by the full `perasWeight` value. Because `wsvTotalWeight` sums block number and weight boost, a sufficiently large `perasWeight` can make a shorter adversarial chain appear heavier than the honest chain, causing the victim node to switch to the non-canonical fork. This is a **chain selection safety failure**: an honest node is made to prefer a non-canonical chain through a crafted network message from an unprivileged peer, with no stake majority or key compromise required.

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is reachable by any peer that can establish a node-to-node connection. The stub is the universal default instance — there is no per-era override that would restore real validation. The only gate is the round-number deduplication check (`Set.member roundNo alreadyInDb`), which an attacker trivially bypasses by using a fresh round number. The attack requires only the ability to connect to the node and send a single well-formed CBOR-encoded `PerasCert` message.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the BLS aggregate signature over the claimed committee voters.
2. Checks that all claimed voters are eligible committee members for the stated round.
3. Validates that `pcCertBoostedBlock` refers to a block that exists and is within the valid boosting window.
4. Enforces that `pcCertRound` is within the current or recent Peras round range.

Until real validation is in place, the Peras certificate inbound path should be disabled or gated behind a feature flag that is off by default in production.

### Proof of Concept

1. Connect to a target node via the Peras object-diffusion mini-protocol.
2. Craft a `PerasCert` with:
   - `pcCertRound` = any round number not yet in the node's cert DB
   - `pcCertBoostedBlock` = the `Point` of a block on an adversarial fork
3. Send the certificate. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
4. The certificate is added to the ChainDB. The `PerasWeightSnapshot` becomes non-empty.
5. On the next chain selection event, `preferAnchoredCandidate` enters the Peras-weighted branch and computes `wsvTotalWeight` for each candidate. The adversarial fork's fragment now carries the injected `perasWeight` boost, potentially exceeding the honest chain's total weight.
6. The node switches to the adversarial fork. [6](#0-5) [7](#0-6) [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-213)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
            (weightedSelectView cfg weights candSuffix) of
            ShouldSwitch r -> ShouldSwitch (Left r)
            ShouldNotSwitch o -> ShouldNotSwitch o
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
