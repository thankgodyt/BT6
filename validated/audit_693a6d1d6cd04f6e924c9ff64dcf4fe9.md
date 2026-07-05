### Title
Missing Peras Certificate Validation Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function performs **no actual validation** — it unconditionally returns `Right` for every inbound certificate. An unprivileged peer can therefore send a crafted `PerasCert` boosting any block of their choice. The certificate is accepted, stored, and used to inflate the Peras chain weight of the attacker-chosen block, causing the honest node to prefer a non-canonical chain over the canonical one.

---

### Finding Description

`PerasWeight` is defined as a `Word64` newtype with its `Semigroup` instance derived via `Sum Word64`:

```haskell
newtype PerasWeight = PerasWeight {unPerasWeight :: Word64}
deriving via Sum Word64 instance Semigroup PerasWeight
deriving via Sum Word64 instance Monoid PerasWeight
``` [1](#0-0) 

Chain selection in Peras compares chains by their **total weight** — block number plus accumulated boost — via `wsvTotalWeight`:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [2](#0-1) 

The `preferCandidate` logic switches to a candidate chain whenever its `wsvTotalWeight` exceeds the current selection's:

```haskell
preferCandidate cfg ours cand =
  case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
    LT -> ShouldSwitch ...
``` [3](#0-2) 

The weight boost for a fragment is accumulated from a `PerasWeightSnapshot` that is populated by inbound certificates. The critical gate — `validatePerasCert` — is a stub that **always returns `Right`** without checking committee membership, quorum, or any cryptographic proof:

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
``` [4](#0-3) 

This stub is wired directly into the production inbound-certificate processing path via `makePerasCertPoolWriterFromChainDB`:

```haskell
(validatePerasCert mkPerasParams)  -- TODO replace when actual plumbing is in place
``` [5](#0-4) 

`processCerts` calls this validator for every certificate received from a peer. If all certificates pass (which they always do with the stub), they are timestamped and added to the database, which then triggers chain selection:

```haskell
([], validatedCerts) ->
  mapM_ (addCert . WithArrivalTime now) validatedCerts
``` [6](#0-5) 

Chain selection for the boosted block is then triggered in `chainSelSync`:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [7](#0-6) 

The `forksAtMostKWeight` rollback guard also uses `totalWeightOfFragment`, which accumulates `PerasWeight` via the same `Sum Word64` monoid — meaning a fraudulently boosted block can also cause the rollback guard to pass when it should not:

```haskell
forksAtMostKWeight weights maxWeight ours theirs =
  case ours `AF.intersect` theirs of
    Nothing -> False
    Just (_, _, ourSuffix, _) ->
      totalWeightOfFragment weights ourSuffix <= maxWeight
``` [8](#0-7) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any block as the boosted block. Because `validatePerasCert` performs no cryptographic or committee-membership checks, the certificate is accepted unconditionally. The fraudulent boost is added to the `PerasWeightSnapshot` and used in `wsvTotalWeight` comparisons. The honest node may then switch to a non-canonical fork that contains the attacker-chosen block, violating chain-selection safety. Additionally, the fraudulent boost can cause `forksAtMostKWeight` to return `True` for a fork that exceeds the legitimate rollback bound `k`, allowing the node to roll back more than `k` weight — directly violating the Ouroboros security parameter.

This matches the allowed impact: **Critical — bypass of Peras certificate/vote checks that enables unauthorized certificate acceptance and chain-selection manipulation**.

---

### Likelihood Explanation

Any peer connected via the Peras certificate mini-protocol can send a crafted certificate. No stake, keys, or special privileges are required. The attack is reachable as soon as Peras certificate diffusion is active. The stub is explicitly marked as a TODO in production code with no runtime guard disabling it.

---

### Recommendation

1. Implement real cryptographic and committee-membership validation inside `validatePerasCert` before the Peras certificate mini-protocol is enabled on any network. At minimum, verify that the certificate carries a valid quorum of signatures from the elected committee for the claimed round.
2. Until real validation is in place, gate the inbound certificate path with a feature flag that rejects all certificates, so the stub cannot be reached from the network.
3. Add an overflow guard to `wsvTotalWeight` (and `totalWeightOfFragment`) analogous to the guard already present in `pureTryAddTx` for `ByteSize32`, since `Sum Word64` addition silently wraps around and could corrupt chain-weight comparisons if boost values are ever large.

---

### Proof of Concept

**Private-testnet sequence:**

1. Start two nodes A (honest) and B (attacker) on a private Peras-enabled testnet.
2. Node B mines a short fork `F` branching off the canonical chain at block `N`.
3. Node B crafts a `PerasCert` with `pcCertBoostedBlock = blockPoint (tip of F)` and `pcCertRound = <any valid round>`. No signatures or committee proofs are included.
4. Node B sends this certificate to node A via the Peras certificate mini-protocol.
5. `processCerts` on node A calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{..}` unconditionally.
6. The certificate is stored; `chainSelSync` triggers `chainSelectionForBlock` for the tip of `F`.
7. `wsvTotalWeight` for `F`'s tip now includes the fraudulent boost (`perasWeight params`, e.g. 15). If `F`'s block number plus 15 exceeds the canonical chain's block number, node A switches to `F`.
8. Node A is now on a non-canonical chain chosen solely because of a certificate that was never validated.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L84-91)
```haskell
newtype PerasWeight
  = PerasWeight {unPerasWeight :: Word64}
  deriving Show via Quiet PerasWeight
  deriving stock Generic
  deriving newtype (Enum, Eq, Ord, NoThunks, Condense)

deriving via Sum Word64 instance Semigroup PerasWeight
deriving via Sum Word64 instance Monoid PerasWeight
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L81-87)
```haskell
  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L85-89)
```haskell
forksAtMostKWeight weights maxWeight ours theirs =
  case ours `AF.intersect` theirs of
    Nothing -> False
    Just (_, _, ourSuffix, _) ->
      totalWeightOfFragment weights ourSuffix <= maxWeight
```
