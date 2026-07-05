### Title
Stub `validatePerasCert` unconditionally accepts any peer-supplied Peras certificate, enabling unauthorized chain-selection weight manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The sole `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that always returns `Right` without performing any cryptographic or structural validation. Any unprivileged peer reachable via the Peras certificate diffusion mini-protocol can inject a crafted `PerasCert` that boosts an arbitrary volatile block's chain-selection weight. Because `addPerasCertAsync` is documented to trigger a fork switch when the boosted chain becomes weightier, this lets an unprivileged peer manipulate chain selection on an honest node.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub**

The `BlockSupportsPeras` class declares `validatePerasCert` as the mandatory gate before a received certificate is stored and used in chain selection. The only instance in the codebase is the catch-all `instance StandardHash blk => BlockSupportsPeras blk` at line 320. Its `validatePerasCert` body unconditionally returns `Right` for every input, assigning the full configured Peras weight boost to any certificate regardless of its content: [1](#0-0) 

No cryptographic signature check, no committee-membership check, no quorum check, and no round-validity check is performed.

**Inbound production path calls this stub directly**

`makePerasCertPoolWriterFromChainDB` in `PerasCert.hs` wires `validatePerasCert mkPerasParams` as the validation callback passed to `processCerts`: [2](#0-1) 

`processCerts` (lines 164–185) calls this function on every received cert and, if it returns `Right`, immediately passes the cert to `ChainDB.addPerasCertAsync`. The `addPerasCertAsync` API contract states: *"If this leads to a fork to be weightier than our current selection, this will trigger a fork switch."* [3](#0-2) 

**The handler is wired into the production node-to-node diffusion layer**

`hPerasCertDiffusionClient` in `NodeToNode.hs` is reachable by any peer that connects via the standard node-to-node protocol: [4](#0-3) 

**End-to-end exploit path**

1. Attacker connects to a victim node as a normal peer and also serves a competing fork containing block B at some volatile slot.
2. Attacker sends a crafted `PerasCert{pcCertRound=R, pcCertBoostedBlock=B}` via the Peras cert diffusion protocol.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → always returns `Right ValidatedPerasCert{vpcCert=cert, vpcCertBoost=perasWeight params}`.
4. The cert is added to the `PerasCertDB`; the `PerasWeightSnapshot` is updated with the boost for block B.
5. `addPerasCertAsync` triggers chain selection; `preferAnchoredCandidate` now sees the attacker's fork containing B as having extra weight.
6. If the attacker's fork is otherwise valid (valid headers, valid blocks), the node switches to it.

The only existing guard is a "too old" check that ignores certs whose boosted block is already immutable: [5](#0-4) 

This does not protect against certs boosting blocks in the volatile window (the last `k` blocks).

### Impact Explanation

**High.** An unprivileged peer can inject a crafted Peras certificate that boosts an arbitrary volatile block's chain-selection weight, bypassing all intended Peras authorization (committee membership, quorum, cryptographic signatures). Because `addPerasCertAsync` is documented to trigger a fork switch when the boosted chain becomes weightier, this directly enables an honest node to prefer a non-canonical or adversarial chain beyond the intended security assumptions. This falls squarely within the allowed impact scope: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

### Likelihood Explanation

**High.** The attack requires only a standard peer connection and the ability to send a crafted cert via the object diffusion protocol. No privileged access, no key material, and no stake is required. The Peras cert diffusion handler is wired into the production node-to-node layer and is reachable by any connecting peer.

### Recommendation

Implement actual certificate validation in `validatePerasCert` before the Peras certificate diffusion protocol is active in production. At minimum, validation must check:
- Cryptographic aggregate signatures from committee members
- Committee membership and quorum threshold against the current epoch's stake distribution
- Round validity relative to the current epoch
- That the boosted block point is a known, valid block

Until proper validation is implemented, the Peras certificate diffusion protocol should be disabled at the protocol-version negotiation level, or `validatePerasCert` should reject all certificates with an explicit error rather than silently accepting them.

### Proof of Concept

```
1. Connect to a victim node as a peer via the node-to-node protocol.
2. Negotiate a protocol version that includes the Peras cert diffusion mini-protocol.
3. Send a PerasCert message via objectDiffusionInbound with:
     pcCertRound  = <any round not yet in the victim's PerasCertDB>
     pcCertBoostedBlock = <Point of a block on a competing fork in the victim's VolatileDB>
4. processCerts calls validatePerasCert mkPerasParams cert
   → returns Right (ValidatedPerasCert cert (perasWeight mkPerasParams))
   → no PerasCertInboundException is thrown
5. ChainDB.addPerasCertAsync is called with the crafted cert.
6. The PerasWeightSnapshot is updated; chain selection is triggered.
7. If the competing fork is otherwise valid, the node switches to it.
``` [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
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

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/ChainDB/Model.hs (L467-472)
```haskell
addPerasCert cfg cert m
  | pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m) =
      (PerasCertIgnoredTooOld, m)
  | otherwise =
      let (certRes, perasCertModel') = PerasCertDBModel.addCert (perasCertModel m) cert
       in (PerasCertProcessed certRes, chainSelection cfg m{perasCertModel = perasCertModel'})
```
