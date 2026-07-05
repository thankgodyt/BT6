### Title
Peras Certificate Validation Bypass Allows Arbitrary Chain Weight Inflation — (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the catch-all `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate as valid, performing zero cryptographic or structural checks. An unprivileged peer can send crafted certificates via the ObjectDiffusion mini-protocol to inflate the Peras weight of any chain fragment arbitrarily, causing honest nodes to prefer a non-canonical chain. This is the direct analog of the ZetaChain supply-inflation bug: just as `MintCoins()` created tokens out of thin air without destroying them elsewhere, `validatePerasCert` creates chain-weight out of thin air without any legitimate quorum proof.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the gate that must be passed before a certificate is stored and used in chain selection. The production source file contains a degenerate catch-all instance that is active for every block type:

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

`validatePerasCert` returns `Right` for every input, unconditionally assigning the full configured `perasWeight` boost to any certificate a peer sends. No signature, quorum, round-number range, or boosted-block existence check is performed.

The inbound processing pipeline in `processCerts` calls this function on every certificate received from a peer:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [2](#0-1) 

Because `validateCert` (bound to `validatePerasCert mkPerasParams`) never returns `Left`, the `(errs, _)` branch is unreachable and every certificate is unconditionally added to the `PerasCertDB`.

The pool writer used in production wires this directly to the ChainDB:

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
    }
``` [3](#0-2) 

Once stored, `implGetWeightSnapshot` builds the `PerasWeightSnapshot` from every certificate in the DB:

```haskell
let weights =
      mkPerasWeightSnapshot
        [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
        | cert <- Map.elems (pcdsCertsByTicket pcds)
        ]
``` [4](#0-3) 

Chain selection then uses this snapshot in `preferAnchoredCandidate` → `weightedSelectView` → `weightBoostOfFragment` to compare candidate chains:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [5](#0-4) 

An attacker who injects a certificate boosting a block on a minority fork inflates that fork's `wsvTotalWeight`, potentially making `preferCandidate` return `ShouldSwitch` for a non-canonical chain.

The `chainSelSync` path confirms that receiving a certificate directly triggers chain selection for the boosted block:

```haskell
-- Trigger chain selection for the boosted block.
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [6](#0-5) 

---

### Impact Explanation

**High — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.**

An adversary with a single network connection can:

1. Craft a `PerasCert` whose `pcCertBoostedBlock` points to any block on a minority fork.
2. Send it via the ObjectDiffusion mini-protocol.
3. The certificate passes `validatePerasCert` (always `Right`) and is stored in `PerasCertDB`.
4. `chainSelSync` triggers chain selection for the boosted block.
5. `preferAnchoredCandidate` now sees the minority fork as heavier and switches to it.

The invariant broken is identical in structure to the ZetaChain bug: the total "weight supply" of the chain-selection metric should only increase when a legitimate quorum of stake-weighted votes is proven. The missing validation allows weight to be created out of thin air, breaking this conservation invariant.

---

### Likelihood Explanation

Peras is currently disabled by default (CHANGELOG: *"Note that if Peras is disabled (which is the default), there is no observable difference"*), which limits immediate exploitability on mainnet. However:

- The vulnerable code is in a production source file, not a test or stub.
- The TODO comments reference open issues (`#73`, `#120`) indicating the placeholder is known but not yet resolved.
- Any deployment that enables Peras (e.g., a private testnet, a future mainnet upgrade, or a node operator who opts in) is immediately exposed.
- The attack requires only a single peer connection and no special privileges.

---

### Recommendation

1. **Do not enable Peras in production** until `validatePerasCert` performs full cryptographic validation: aggregate BLS signature verification, quorum-stake threshold check, round-number range check, and boosted-block existence/era check.
2. Track resolution of `https://github.com/tweag/cardano-peras/issues/120` as a hard prerequisite for enabling Peras.
3. Add a runtime guard that refuses to process inbound certificates if the Peras feature flag is disabled, so the ObjectDiffusion handler cannot be reached even if the flag is accidentally toggled.
4. Consider replacing the catch-all `instance StandardHash blk => BlockSupportsPeras blk` with a compile-time error or an explicit `absurd`-style stub that panics loudly, rather than silently accepting all certificates.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  ObjectDiffusion mini-protocol
  │  sends PerasCert { pcCertRound = R, pcCertBoostedBlock = <minority-fork block> }
  ▼
processCerts  [PerasCert.hs:164]
  │  validatePerasCert mkPerasParams cert  →  always Right ValidatedPerasCert { vpcCertBoost = perasWeight }
  │  (no signature check, no quorum check, no round-range check)
  ▼
ChainDB.addPerasCertAsync  [ChainSel.hs:495]
  │  certificate stored in PerasCertDB
  ▼
chainSelSync  [ChainSel.hs:531]
  │  chainSelectionForBlock triggered for boosted block
  ▼
preferAnchoredCandidate  [AnchoredFragment.hs:204-210]
  │  weightedSelectView uses PerasWeightSnapshot containing attacker's boost
  │  minority-fork wsvTotalWeight = blockNo + perasWeight  >  honest-chain wsvTotalWeight
  ▼
ShouldSwitch  →  honest node adopts non-canonical chain
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L203-214)
```haskell
implGetWeightSnapshot ::
  (IOLike m, StandardHash blk) =>
  PerasCertDbEnv m blk ->
  STM m (WithFingerprint (PerasWeightSnapshot blk))
implGetWeightSnapshot PerasCertDbEnv{pcdbState} = do
  WithFingerprint pcds fp <- readTVar pcdbState
  let weights =
        mkPerasWeightSnapshot
          [ (getPerasCertBoostedBlock cert, getPerasCertBoost cert)
          | cert <- Map.elems (pcdsCertsByTicket pcds)
          ]
  pure (WithFingerprint weights fp)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
