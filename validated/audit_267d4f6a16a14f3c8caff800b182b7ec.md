### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Crafted Peras Certificates and Manipulate Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. Any unprivileged peer reachable via the Peras object-diffusion mini-protocol can therefore inject an arbitrary `PerasCert` (any round number, any boosted block point) that is accepted, stored in the `PerasCertDB`/`ChainDB`, and immediately incorporated into the `PerasWeightSnapshot` used by chain selection. A crafted certificate boosting a block on an adversarial fork adds `perasWeight = 15` units of weight to that fork, potentially causing the victim node to prefer and adopt a non-canonical chain.

---

### Finding Description

The degenerate `BlockSupportsPeras` instance (the only instance in the codebase, used for all block types) implements `validatePerasCert` as:

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

This is the function called by `processCerts` in the production inbound-certificate handler:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          (validatePerasCert mkPerasParams)   -- always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
``` [2](#0-1) 

`processCerts` partitions the results of `validateCert` and adds all `Right` values to the database. Because `validatePerasCert` is always `Right`, every inbound certificate passes: [3](#0-2) 

Once stored, the certificate is reflected in the `PerasWeightSnapshot` returned by `getWeightSnapshot`/`getPerasWeightSnapshot`, which is the live input to `preferAnchoredCandidate` and `compareAnchoredFragments` during chain selection: [4](#0-3) 

The `WeightedSelectView` used when Peras weights are non-empty compares `wsvTotalWeight = blockNo + weightBoost`, so a fork whose tip has a boosted block can be preferred over a longer canonical chain: [5](#0-4) 

The default `perasWeight` is 15, meaning a single injected certificate can make a fork 15 blocks shorter than the canonical chain appear heavier: [6](#0-5) 

---

### Impact Explanation

An unprivileged peer can craft a `PerasCert` naming any `pcCertBoostedBlock` (e.g., the tip of an adversarial fork) and any `pcCertRound`. Because `validatePerasCert` never rejects it, the certificate is stored and the `PerasWeightSnapshot` is updated. Chain selection (`chainSelectionForBlock`, `initialChainSelection`) then uses this snapshot and may switch the node to the adversarial fork. This constitutes:

- **Bypass of Peras certificate verification** enabling unauthorized certificate acceptance (Critical scope).
- **Chain selection error** letting an unprivileged peer make an honest node prefer a non-canonical chain (High scope). [7](#0-6) 

---

### Likelihood Explanation

The Peras object-diffusion mini-protocol is a public peer-to-peer channel. Any node that connects as a peer can send `PerasCert` objects. No stake, key material, or privileged access is required. The attacker only needs to know the hash of a block they want to boost (publicly observable from the chain). The attack is deterministic and requires a single message.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real validation that checks:
1. The certificate's cryptographic aggregate signature against the claimed committee members' keys.
2. That the boosted block point exists and is within the valid age window (`perasBlockMinSlots`).
3. That the round number is consistent with the current epoch/slot.
4. That the quorum threshold is met by the attesting stake.

Until real validation is in place, inbound certificates from the object-diffusion protocol should be rejected entirely (or the protocol should not be enabled in production builds).

---

### Proof of Concept

```
Attacker peer                          Victim node
     |                                      |
     |-- ObjectDiffusion: PerasCert ------->|
     |   { pcCertRound = 999,               |
     |     pcCertBoostedBlock =             |
     |       BlockPoint slot adversarialHash}|
     |                                      |
     |                         processCerts called
     |                         validatePerasCert → Right (no check)
     |                         addPerasCertAsync chainDB
     |                         PerasWeightSnapshot updated:
     |                           adversarialHash → PerasWeight 15
     |                                      |
     |                         chainSelectionForBlock triggered
     |                         preferAnchoredCandidate uses weights
     |                         adversarial fork total weight += 15
     |                         ShouldSwitch → node adopts fork
```

The root cause is at: [8](#0-7) 

called unconditionally from: [9](#0-8)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L186-213)
```haskell
preferAnchoredCandidate cfg weights ours cand
  | isEmptyPerasWeightSnapshot weights =
      assertWithMsg (precondition ours cand) $
        case (ours, cand) of
          (Empty _, Empty _) -> ShouldNotSwitch EQ
          (_, Empty _) -> ShouldNotSwitch GT
          (Empty ourAnchor, _ :> theirTip) ->
            if blockPoint theirTip /= castPoint (AF.anchorToPoint ourAnchor)
              then
                ShouldSwitch (Right $ Longer $ Comparing (AF.anchorToBlockNo ourAnchor) (At (blockNo theirTip)))
              else ShouldNotSwitch EQ
          (_ :> ourTip, _ :> theirTip) ->
            case preferCandidate
              (projectChainOrderConfig cfg)
              (selectView cfg (getHeader1 ourTip))
              (selectView cfg (getHeader1 theirTip)) of
              ShouldSwitch r -> ShouldSwitch (Right r)
              ShouldNotSwitch o -> ShouldNotSwitch o
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-68)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L174-182)
```haskell
    case NE.nonEmpty
      [ (chain, reason)
      | chain <- chains
      , ShouldSwitch reason <- [preferAnchoredCandidate bcfg weights curChain chain]
      ] of
      -- If there are no candidates, no chain selection is needed
      Nothing -> pure curChain
      Just chains' ->
        fromMaybe curChain <$> chainSelection' curChain chains'
```
