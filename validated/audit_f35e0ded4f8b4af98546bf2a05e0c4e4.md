### Title
Unconditional `validatePerasCert` Acceptance Bypasses Peras Certificate Authorization — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. This is wired directly into the production `makePerasCertPoolWriterFromChainDB` handler, which is registered as the live `hPerasCertDiffusionClient` in the node-to-node protocol stack. Any unprivileged peer can therefore inject arbitrary Peras certificates that are accepted, stored in the ChainDB, and used to trigger chain-selection side-effects — bypassing the committee authorization that is supposed to gate certificate acceptance.

### Finding Description

**Root cause — unconditional `Right` in `validatePerasCert`:**

The catch-all `instance StandardHash blk => BlockSupportsPeras blk` provides the following implementation:

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
``` [1](#0-0) 

Every certificate, regardless of its content or origin, is wrapped in `ValidatedPerasCert` and returned as `Right`. No committee membership check, no aggregate-signature verification, no round-number sanity check is performed.

**Production wiring — `makePerasCertPoolWriterFromChainDB`:**

Both the cert-DB-level and ChainDB-level pool writers pass `validatePerasCert mkPerasParams` as the validation callback:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

**Live handler registration in `NodeToNode.hs`:**

`makePerasCertPoolWriterFromChainDB` is registered as the inbound handler for the `PerasCertDiffusion` miniprotocol in the production node-to-node application bundle:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

**`processCerts` accepts the `Right` result and stores it:**

`processCerts` partitions validation results; when all results are `Right` (which is always the case here), it calls `addCert` for each, which in the ChainDB path calls `addPerasCertAsync` — triggering asynchronous chain-selection side-effects. [5](#0-4) 

**Analog to the external report:**

The external report describes `_msgSender()` acting as a "trusted forwarder" that lets one account impersonate any role, bypassing `onlyPrizePool` / `onlyOwnerOrListener`. Here, `validatePerasCert` acts as an unconditional forwarder: it is the sole authorization gate between a peer-supplied certificate and the ChainDB, yet it always grants passage regardless of the certificate's claimed issuer or cryptographic proof.

### Impact Explanation

An unprivileged peer can craft a `PerasCert` for any `(round, block)` pair and send it over the `PerasCertDiffusion` miniprotocol. The certificate will be:

1. Accepted by `validatePerasCert` (always `Right`).
2. Stored in the ChainDB's `PerasCertDB`.
3. Used to trigger `addPerasCertAsync`, which feeds into chain selection.

`ValidatedPerasCert` carries `vpcCertBoost = perasWeight params` — the Peras weight boost applied to the certified block during chain selection. An attacker can therefore boost an arbitrary (potentially adversarial) block, causing honest nodes to prefer a non-canonical chain. This is a **Critical** bypass of Peras certificate checks enabling unauthorized certificate acceptance and chain-selection manipulation. [6](#0-5) 

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is registered in the production node-to-node bundle and is reachable by any peer that establishes a connection. No privileged access, key material, or stake is required. The attacker only needs to send a well-formed CBOR-encoded `PerasCert` message. The `PerasCert` type contains only a `PerasRoundNo` and a `Point blk` (block hash + slot), both of which are public information. [7](#0-6) [8](#0-7) 

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:
- The certificate's aggregate BLS signature against the declared committee members' keys.
- That the declared voters constitute a quorum of the stake-weighted committee for the given round.
- That the certified block's slot falls within the valid range for the given round.

Until real validation is implemented, the `PerasCertDiffusion` inbound handler should be disabled or should reject all inbound certificates rather than accepting them unconditionally. The `TODO` comment at the call site in `makePerasCertPoolWriterFromChainDB` should be treated as a security-blocking item, not a deferred cleanup task. [9](#0-8) 

### Proof of Concept

1. Connect to a production Cardano node (or a private-testnet node) as a peer with the `PerasCertDiffusion` miniprotocol enabled.
2. Construct a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to a block on an adversarial fork.
3. CBOR-encode the certificate and send it as an `ObjectDiffusion` inbound message.
4. Observe via tracing that `addPerasCertAsync` is called and the certificate is stored in the ChainDB.
5. Observe that chain selection subsequently applies `vpcCertBoost` (the Peras weight) to the adversarial block, potentially causing the node to switch to the adversarial chain.

The `PerasCert` serialization format is:

```haskell
encode PerasCert{pcCertRound, pcCertBoostedBlock} =
  encodeListLen 2 <> encode pcCertRound <> encode pcCertBoostedBlock
``` [10](#0-9) 

No cryptographic material is required to construct a valid wire-format certificate.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-219)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks

data ValidatedPerasVote blk = ValidatedPerasVote
  { vpvVote :: !(PerasVote blk)
  , vpvVoteStake :: !PerasVoteStake
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L1259-1263)
```haskell
        , perasCertDiffusionProtocol =
            ( InitiatorAndResponderProtocol
                (MiniProtocolCb (\initiatorCtx -> aPerasCertDiffusionClient version initiatorCtx))
                (MiniProtocolCb (\responderCtx -> aPerasCertDiffusionServer version responderCtx))
            )
```
