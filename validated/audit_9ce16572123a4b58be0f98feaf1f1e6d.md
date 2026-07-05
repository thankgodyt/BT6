### Title
`validatePerasCert` Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Chain-Selection Manipulation — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `BlockSupportsPeras` default instance's `validatePerasCert` function performs **zero validation** on inbound Peras certificates received over the network. It unconditionally returns `Right ValidatedPerasCert` for every certificate, regardless of its content. Because this function is wired directly into the production `PerasCertDiffusion` inbound path, any unprivileged peer can inject a crafted certificate that boosts an arbitrary block's chain-selection weight by `perasWeight` (currently 15) per certificate, potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass declares `validatePerasCert` as the mandatory gate for accepting inbound Peras certificates. The only concrete instance in the codebase is the degenerate catch-all instance for `StandardHash blk`:

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

This stub skips all required checks: quorum proof, cryptographic aggregate signature, committee membership, round validity, and boosted-block existence. The `PerasCert` data type carries only `pcCertRound` and `pcCertBoostedBlock` — both attacker-controlled over the wire — and neither is validated. [2](#0-1) 

The production inbound path in `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` directly as the validation callback to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [3](#0-2) 

`processCerts` calls this function on every new certificate received from a peer, and on success immediately adds the result to the ChainDB via `ChainDB.addPerasCertAsync`: [4](#0-3) 

The ChainDB's `PerasCertDB` stores the accepted certificate and exposes it through `implGetWeightSnapshot`, which builds a `PerasWeightSnapshot` mapping each boosted block point to its accumulated `PerasWeight`: [5](#0-4) 

This snapshot is consumed by `preferAnchoredCandidate` → `weightedSelectView`, where `wsvTotalWeight = blockNo + weightBoost` determines which chain is preferred: [6](#0-5) 

The `PerasCertDiffusion` mini-protocol is wired into the node-to-node handler stack and is reachable by any unprivileged peer: [7](#0-6) 

---

### Impact Explanation

An attacker controlling any peer connection can:

1. Craft a `PerasCert` with `pcCertBoostedBlock` pointing to any block on an adversarial fork and `pcCertRound` set to any previously-unseen round number.
2. Send it over the `PerasCertDiffusion` channel. `validatePerasCert` returns `Right` unconditionally.
3. The certificate is stored and contributes `perasWeight = 15` to that block's chain-selection weight.
4. Because `mkPerasWeightSnapshot` accumulates weights for the same point across multiple certificates, the attacker can send certificates for distinct round numbers (the `PerasRoundNo` space is `Word64`) to stack boosts on the same block.
5. `preferAnchoredCandidate` will then prefer the adversarially-boosted fork over the honest chain once its `wsvTotalWeight` exceeds the honest chain's.

This is a **High** impact chain-selection bug: an unprivileged peer can make an honest node permanently switch to a non-canonical chain without any stake, key compromise, or operator action.

---

### Likelihood Explanation

The `PerasCertDiffusion` inbound handler is active in the production node-to-node stack. Any peer that can establish a connection can send Peras certificates. The attack requires only the ability to send well-formed CBOR-encoded `PerasCert` messages, which is trivially achievable. No special privileges, keys, or stake are required.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:

1. **Aggregate cryptographic signature** — the certificate must carry a valid aggregate signature from a quorum of committee members for the claimed round and boosted block.
2. **Committee membership and quorum** — the signing set must represent sufficient stake (≥ `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`) drawn from the correct epoch's stake distribution.
3. **Round validity** — `pcCertRound` must correspond to a valid, non-expired Peras round relative to the current chain tip.
4. **Boosted block existence** — `pcCertBoostedBlock` must refer to a block that is actually present in the node's chain fragment and satisfies `perasBlockMinSlots`.

Until the real implementation is ready, the stub should at minimum return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), to prevent the inbound path from being exploited.

---

### Proof of Concept

**Entry point:** `PerasCertDiffusion` mini-protocol, node-to-node, no authentication required.

**Sequence:**

1. Attacker connects to a victim node as a peer.
2. Attacker sends a `PerasCert` message encoding:
   - `pcCertRound = PerasRoundNo 999999` (any unseen round)
   - `pcCertBoostedBlock = BlockPoint slotN hashOfAdversarialBlock`
3. `objectDiffusionInbound` → `makePerasCertPoolWriterFromChainDB` → `processCerts` calls `validatePerasCert mkPerasParams cert`.
4. `validatePerasCert` returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = PerasWeight 15}` unconditionally. [8](#0-7) 
5. `ChainDB.addPerasCertAsync` stores the certificate; `implGetWeightSnapshot` now returns a snapshot with `hashOfAdversarialBlock → PerasWeight 15`.
6. Repeat with `pcCertRound = 999998, 999997, …` to accumulate weight. After `N` certificates, the adversarial block has weight boost `N × 15`.
7. `preferAnchoredCandidate` computes `wsvTotalWeight` for the adversarial fork as `blockNo + N×15`, which eventually exceeds the honest chain's `blockNo`, triggering a chain switch. [9](#0-8)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Util/AnchoredFragment.hs (L204-210)
```haskell
  | otherwise =
      case AF.intersect ours cand of
        Nothing -> error "precondition violated: fragments must intersect"
        Just (_oursPrefix, _candPrefix, oursSuffix, candSuffix) ->
          case preferCandidate
            (projectChainOrderConfig cfg)
            (weightedSelectView cfg weights oursSuffix)
```
