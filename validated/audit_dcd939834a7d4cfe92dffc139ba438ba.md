### Title
Unconditional Peras Certificate Acceptance Enables Unprivileged Chain-Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` function is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. Any unprivileged peer connected via the Peras certificate diffusion mini-protocol can inject arbitrary crafted `PerasCert` objects that are accepted, stored, and used to boost attacker-chosen blocks in chain selection. This is a direct analog to the external report's authorization bypass: a guard that is supposed to reject invalid inputs instead always passes them through.

---

### Finding Description

**Root cause — `validatePerasCert` always returns `Right`:** [1](#0-0) 

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

No signature, no committee membership check, no quorum check, no round-number bounds check — every certificate is unconditionally accepted and assigned the full `perasWeight`.

**Attacker-controlled entry path:**

The Peras certificate diffusion inbound handler is wired unconditionally in `NodeToNode.hs`: [2](#0-1) 

It calls `objectDiffusionInbound` with `makePerasCertPoolWriterFromChainDB`, which calls `processCerts` with `validatePerasCert mkPerasParams` as the validator: [3](#0-2) 

`processCerts` filters only for round-number deduplication, then calls the validator: [4](#0-3) 

Because `validatePerasCert` always returns `Right`, every new-round certificate passes and is forwarded to `ChainDB.addPerasCertAsync`, which updates the `PerasWeightSnapshot`.

**Chain selection impact:**

The `PerasWeightSnapshot` is consumed directly in chain selection. `weightBoostOfFragment` sums the boost for every block on a candidate fragment: [5](#0-4) 

`WeightedSelectView.preferCandidate` compares `wsvTotalWeight = blockNo + weightBoost`: [6](#0-5) 

An attacker who injects a certificate pointing `pcCertBoostedBlock` at a block on an adversarial fork adds `perasWeight` to that fork's total weight, potentially making it preferred over the honest chain.

**Exploit flow:**

1. Attacker connects to a target node as an ordinary peer (no privilege required).
2. Attacker sends a `PerasCert` with `pcCertRound = R` (any round not yet in the DB) and `pcCertBoostedBlock = <point on adversarial fork>`.
3. `processCerts` passes the cert to `validatePerasCert`, which returns `Right` unconditionally.
4. The cert is stored; `PerasWeightSnapshot` is updated to boost the adversarial block.
5. On the next chain selection event, `constructPreferableCandidates` computes `WeightedSelectView` using the inflated weight snapshot.
6. If the boost is large enough, the node switches to the adversarial fork.

The one-cert-per-round deduplication (`Set.member roundNo alreadyInDb`) does not mitigate this: the attacker simply uses a fresh round number for each target block they wish to boost.

---

### Impact Explanation

**Severity: High** — Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

A node with Peras enabled can be made to switch to an adversarial fork by any connected peer, with no stake, no keys, and no cryptographic material required. The attacker needs only to send a well-formed CBOR-encoded `PerasCert` message over the Peras certificate diffusion mini-protocol. Because the weight boost is additive and unbounded (one cert per round, many rounds available), the attacker can accumulate enough weight to override the honest chain's block-number advantage.

---

### Likelihood Explanation

The Peras certificate diffusion protocol is unconditionally wired up in the production `NodeToNode` handler. Any peer that negotiates a node-to-node connection can send Peras certificate messages. The exploit requires no special knowledge beyond the CBOR wire format of `PerasCert` (two fields: a round number and a block point), both of which are fully specified in the serialisation instance: [7](#0-6) 

The only precondition is that Peras is enabled on the target node. The CHANGELOG notes Peras is "disabled by default," but the validation stub is present in production code and will be active on any node where Peras is turned on (including private testnets and future mainnet deployments).

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's aggregate BLS signature against the claimed committee members' public keys.
2. That the claimed voters constitute a quorum (total stake ≥ `perasQuorumStakeThreshold + safetyMargin`).
3. That each claimed voter was a legitimate committee member for the stated round (VRF eligibility or persistent membership, as appropriate).
4. That `pcCertBoostedBlock` refers to a block that actually exists on a known chain and is within the valid boosting window for round `pcCertRound`.

Until the real implementation is in place, the cert diffusion inbound handler should be disabled or should reject all inbound certificates rather than accepting them unconditionally.

---

### Proof of Concept

Deterministic reasoning (no running node required):

1. Construct a `PerasCert blk` with `pcCertRound = PerasRoundNo 9999` and `pcCertBoostedBlock = <point on adversarial fork B>`.
2. CBOR-encode it per the `Serialise` instance (2-element list: round number, block point).
3. Send it over the Peras cert diffusion channel to a Peras-enabled node.
4. `processCerts` checks `Set.member 9999 alreadyInDb` → `False` (fresh round).
5. `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert{vpcCertBoost = perasWeight mkPerasParams}` (unconditionally).
6. `ChainDB.addPerasCertAsync` stores the cert; `PerasWeightSnapshot` now maps `<point on B>` to `perasWeight`.
7. Next chain selection: `weightBoostOfFragment` adds `perasWeight` to fork B's total weight.
8. If `perasWeight > (blockNo(honest tip) - blockNo(B tip))`, `preferCandidate` returns `ShouldSwitch`, and the node adopts fork B. [8](#0-7) [4](#0-3) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L400-409)
```haskell
instance Serialise (HeaderHash blk) => Serialise (PerasCert blk) where
  encode PerasCert{pcCertRound, pcCertBoostedBlock} =
    encodeListLen 2
      <> encode pcCertRound
      <> encode pcCertBoostedBlock
  decode = do
    decodeListLenOf 2
    pcCertRound <- decode
    pcCertBoostedBlock <- decode
    pure $ PerasCert{pcCertRound, pcCertBoostedBlock}
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-384)
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
            controlMessageSTM
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L253-267)
```haskell
weightBoostOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
weightBoostOfFragment weightSnap frag
  | Map.null $ getPerasWeightSnapshot weightSnap =
      mempty
  | otherwise =
      -- TODO: think about whether this could be done in sublinear complexity
      -- see https://github.com/IntersectMBO/ouroboros-consensus/pull/1613
      foldMap
        (weightBoostOfPoint weightSnap . castPoint . blockPoint)
        (AF.toOldestFirst frag)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-87)
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
