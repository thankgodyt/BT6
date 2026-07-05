### Title
Unconditional Peras Certificate Acceptance Allows Any Peer to Manipulate Chain Selection Weight — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally accepts every inbound Peras certificate without performing any cryptographic or committee-membership verification. Because the `PerasCertDiffusion` miniprotocol is wired into the node-to-node handler and accepted certificates are fed directly into chain selection, any unprivileged peer can inject a crafted certificate that boosts an arbitrary block's chain weight by `PerasWeight 15`, potentially causing the node to switch away from the honest chain.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The degenerate `instance StandardHash blk => BlockSupportsPeras blk` in `SupportsPeras.hs` implements `validatePerasCert` as:

```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params   -- always PerasWeight 15
      }
```

No committee membership check, no aggregate BLS signature verification, no VRF proof, no round-number bounds check — every certificate is accepted. [1](#0-0) 

**Production wiring — `makePerasCertPoolWriterFromChainDB` uses this stub:**

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
```

This writer is the `opwAddObjects` callback that processes every batch of certificates received from a peer. [2](#0-1) 

**Network entry point — wired into the NTN `PerasCertDiffusion` miniprotocol:**

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
```

Any peer that speaks the `PerasCertDiffusion` protocol can reach this path. [3](#0-2) 

**Chain selection impact — accepted certificates directly alter `PerasWeightSnapshot`:**

`chainSelectionForBlock` reads `getPerasWeightSnapshot` and passes it to `constructPreferableCandidates`. The `WeightedSelectView` comparison in `preferCandidate` computes `wsvTotalWeight = blockNo + weightBoostOfFragment`, so a fork whose tip block is boosted by a fake certificate gains `PerasWeight 15` — equivalent to 15 extra blocks — in the comparison. [4](#0-3) [5](#0-4) 

**`mkPerasParams` sets `perasWeight = PerasWeight 15`:** [6](#0-5) 

**`processCerts` flow — no additional guard:**

`processCerts` calls `validateCert` (the stub) and, on `Right`, immediately calls `addCert` → `ChainDB.addPerasCertAsync`. There is no secondary authorization gate. [7](#0-6) 

### Impact Explanation

An unprivileged peer can submit a `PerasCert` naming any block hash in the node's volatile DB. The certificate is accepted unconditionally, stored in the `PerasCertDB`, and its boost weight is included in the next chain-selection comparison. A fork that is up to 14 blocks shorter than the current chain can be made to appear heavier and trigger a chain switch. This constitutes a **chain-selection manipulation** attack: the attacker can steer an honest node onto a non-canonical fork without possessing any stake, keys, or operator credentials.

**Severity: High** — matches "Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is registered in the production `initiatorAndResponder` bundle and is reachable by any peer that negotiates a compatible `NodeToNodeVersion`. The attacker needs only a TCP connection to the target node and knowledge of a block hash in its volatile DB (obtainable via `ChainSync`). No keys, stake, or privileged access are required. The stub is explicitly marked `TODO` but is live in the diffusion layer today.

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies committee membership, aggregate BLS signature, VRF proofs, and round-number bounds before returning `Right`.
2. Until real validation is implemented, gate the `PerasCertDiffusion` miniprotocol behind a feature flag that is disabled by default in production builds, preventing untrusted peers from reaching `makePerasCertPoolWriterFromChainDB`.
3. Track the replacement work in the referenced issue (`https://github.com/tweag/cardano-peras/issues/120`).

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  1. Establish NTN connection, negotiate PerasCertDiffusion protocol
  │
  │  2. Send PerasCert { pcCertRound = R, pcCertBoostedBlock = <hash of fork tip> }
  │
  ▼
NodeToNode.hs hPerasCertDiffusionClient
  → objectDiffusionInbound
      → makePerasCertPoolWriterFromChainDB.opwAddObjects [cert]
          → processCerts ... (validatePerasCert mkPerasParams) ...
              validatePerasCert: returns Right unconditionally   ← BUG
          → ChainDB.addPerasCertAsync cert
              → chainSelSync (ChainSelAddPerasCert cert)
                  → getPerasWeightSnapshot  (now includes boost for fork tip)
                  → constructPreferableCandidates
                  → chainSelection: fork tip weight = blockNo + 15
                  → if fork weight > current chain weight → switchTo fork
```

A fork 14 blocks shorter than the honest chain becomes preferred after a single crafted certificate, causing the node to roll back up to 14 blocks and adopt the attacker-chosen fork.

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L61-87)
```haskell
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]

data WeightedSelectViewReasonForSwitch p
  = Heavier (Comparing PerasWeight)
  | WeightedSelectViewTiebreak (ReasonForSwitch (TiebreakerView p))

deriving instance
  Show (ReasonForSwitch (TiebreakerView p)) => Show (WeightedSelectViewReasonForSwitch p)

instance ChainOrder (TiebreakerView proto) => ChainOrder (WeightedSelectView proto) where
  type ChainOrderConfig (WeightedSelectView proto) = ChainOrderConfig (TiebreakerView proto)
  type ReasonForSwitch (WeightedSelectView proto) = WeightedSelectViewReasonForSwitch proto

  preferCandidate cfg ours cand =
    case compare (wsvTotalWeight ours) (wsvTotalWeight cand) of
      LT -> ShouldSwitch (Heavier $ Comparing (wsvTotalWeight ours) (wsvTotalWeight cand))
      EQ -> case preferCandidate cfg (wsvTiebreaker ours) (wsvTiebreaker cand) of
        ShouldSwitch r -> ShouldSwitch (WeightedSelectViewTiebreak r)
        ShouldNotSwitch o -> ShouldNotSwitch o
      GT -> ShouldNotSwitch GT
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L628-634)
```haskell
chainSelectionForBlock cdb@CDB{..} blockCache hdr punish = electric $ do
  (invalid, curChain, weights) <-
    atomically $
      (,,)
        <$> (forgetFingerprint <$> readTVar cdbInvalid)
        <*> Query.getCurrentChain cdb
        <*> (forgetFingerprint <$> Query.getPerasWeightSnapshot cdb)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```
