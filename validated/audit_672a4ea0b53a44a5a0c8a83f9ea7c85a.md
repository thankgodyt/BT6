### Title
Peras Certificate Verification Bypass: `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every certificate it receives, performing zero authorization or cryptographic checks. Any unprivileged peer connected via the `PerasCertDiffusion` mini-protocol can inject an arbitrary crafted `PerasCert` that will be accepted, stored, and used to apply a Peras weight boost to any block of the attacker's choosing, directly influencing chain selection.

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must verify a Peras certificate before it is stored and used to boost a block's chain-selection weight. The sole production instance (a "degenerate instance for all blks") implements this gate as an unconditional pass-through:

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

No committee membership check, no aggregate signature verification, no round-number plausibility check, and no boosted-block existence check are performed. The certificate is immediately wrapped in `ValidatedPerasCert` and returned as valid.

This stub is wired directly into the production network handler. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the sole validator for all inbound certificates:

```haskell
opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [2](#0-1) 

`processCerts` only skips certificates whose round number is already in the database; all others are passed to `validateCert`. Because `validatePerasCert` always returns `Right`, every new certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [3](#0-2) 

This handler is registered for every peer connection in the node-to-node protocol stack:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

Once a `ValidatedPerasCert` is stored, it contributes a `vpcCertBoost = perasWeight params` weight to the `PerasWeightSnapshot`, which is consulted during chain selection to prefer chains with certified blocks: [5](#0-4) 

The `ChainDB` API exposes `addPerasCertAsync` which, on success, can trigger a fork switch if the boosted chain becomes heavier: [6](#0-5) 

### Impact Explanation

An unprivileged peer can forge a `PerasCert` naming any `(pcCertRound, pcCertBoostedBlock)` pair. Because `validatePerasCert` performs no checks, the forged certificate is accepted as `ValidatedPerasCert` with a full `perasWeight` boost. This lets the attacker:

1. **Boost a minority-chain block** to make the victim node's chain-selection logic prefer a non-canonical fork, causing the node to switch away from the honest chain.
2. **Inject a certificate for a future round** to pre-empt legitimate committee certificates and lock in an attacker-chosen block as the certified winner of that round.
3. **Suppress legitimate certificates** by pre-filling a round's slot in the `PerasCertDB` (one cert per round is stored), preventing a real committee certificate for that round from being accepted.

This is a bypass of Peras certificate/vote authorization checks that enables unauthorized certificate acceptance and chain-selection manipulation by any reachable peer.

### Likelihood Explanation

The `PerasCertDiffusion` mini-protocol is open to all connected peers. No stake, no key material, and no special privilege is required — only a network connection. The attacker needs only to craft a valid CBOR-encoded `PerasCert` structure (two fields: a round number and a block point) and send it over the protocol. The `PerasCert` serialization format is fully public: [7](#0-6) 

The stub is the only instance in the codebase and is compiled into production binaries.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate BLS signature over `(electionId, candidate)` against the aggregated public keys of the claimed committee members.
2. Checks that each claimed voter is a registered stake pool with positive stake in the epoch's pool distribution.
3. Verifies that the total weight of the signers meets the quorum threshold.
4. Validates that `pcCertRound` falls within the expected window relative to the current chain tip.
5. Validates that `pcCertBoostedBlock` refers to a block that actually exists in the node's chain fragment.

Until a real implementation is available, the inbound handler should reject all certificates (return `Left` unconditionally) rather than accept all of them.

### Proof of Concept

An attacker peer performs the following steps:

1. Connect to a victim node via the standard node-to-node protocol.
2. Construct a `PerasCert` targeting a minority-chain block `B_attacker` at round `R`:
   ```
   PerasCert { pcCertRound = R, pcCertBoostedBlock = Point B_attacker }
   ```
3. Encode it as CBOR (2-element list: round number, block point) per the public serialization instance.
4. Send it via the `PerasCertDiffusion` mini-protocol.
5. The victim node calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert cert (perasWeight mkPerasParams))` unconditionally.
6. `processCerts` adds the cert to `ChainDB` via `addPerasCertAsync`.
7. The `PerasWeightSnapshot` is updated: block `B_attacker` now carries a `perasWeight` boost.
8. Chain selection re-runs; if the boosted weight tips the balance, the node switches to the attacker's fork. [1](#0-0) [8](#0-7) [4](#0-3)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-180)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/API.hs (L60-67)
```haskell
  , getWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Return the Peras weights in order compare the current selection against
  -- potential candidate chains, namely the weights for blocks not older than
  -- the current immutable tip. It might contain weights for even older blocks
  -- if they have not yet been garbage-collected.
  --
  -- The 'Fingerprint' is updated every time a new certificate is added, but it
  -- stays the same when certificates are garbage-collected.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
