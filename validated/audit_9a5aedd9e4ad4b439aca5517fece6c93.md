### Title
`validatePerasCert` Unconditionally Returns `Right`, Bypassing All Peras Certificate Validation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance's `validatePerasCert` implementation always returns `Right` (success) regardless of the certificate's content. Because this instance covers all block types and is wired directly into the production `PerasCertDiffusion` mini-protocol handler, any unprivileged peer can inject arbitrary Peras certificates that are unconditionally accepted and forwarded to the `ChainDB`, bypassing the entire certificate validation gate.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate for accepting inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The sole production instance — a catch-all covering every `StandardHash blk` — implements this function as:

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

There is no conditional branch, no signature check, no round-number check, no committee membership check — the function unconditionally wraps any input certificate in `Right ValidatedPerasCert`. This is the exact structural analog of the Cairo handler that always `return true`.

The inbound processing pipeline in `processCerts` is designed to reject the entire batch and disconnect from the peer when *any* certificate fails validation:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) -> mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _)            -> throw (PerasCertValidationError errs)
``` [2](#0-1) 

Because `validatePerasCert` never produces a `Left`, the error branch is permanently dead. Every certificate from every peer reaches `addCert`, which in the production path calls `ChainDB.addPerasCertAsync`: [3](#0-2) 

This pool writer is wired directly into the live `hPerasCertDiffusionClient` handler in `NodeToNode.hs`:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
  objectDiffusionInbound
    ...
    (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
    ...
``` [4](#0-3) 

This mini-protocol is active as of `NodeToNodeV_16`, as confirmed by the changelog: [5](#0-4) 

---

### Impact Explanation

An unprivileged peer connected via `NodeToNodeV_16` can send a batch of crafted `PerasCert` objects with arbitrary `pcCertRound` and `pcCertBoostedBlock` fields. Because `validatePerasCert` always returns `Right`, every such certificate is accepted as a `ValidatedPerasCert` and injected into the `ChainDB` via `addPerasCertAsync`. Peras certificates carry a `vpcCertBoost` weight that influences chain selection — a boosted block is preferred over an unboosted one of equal or lesser length. An attacker can therefore cause an honest node to prefer a non-canonical chain by injecting certificates that boost an adversarial fork, breaking the chain-selection invariant that only legitimately quorum-certified blocks receive a boost.

This matches the allowed impact scope: **bypass of Peras certificate checks that enables unauthorized certificate acceptance**, and **chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**.

---

### Likelihood Explanation

The attack requires only a standard node-to-node connection at `NodeToNodeV_16`. No keys, no stake, no admin access are needed. The attacker simply sends well-formed CBOR-encoded `PerasCert` objects with fabricated fields over the `PerasCertDiffusion` mini-protocol. The code path is unconditional and has no secondary guard.

---

### Recommendation

Replace the stub `validatePerasCert` body with real validation logic before the `PerasCertDiffusion` mini-protocol is enabled on any network where Peras is active. At minimum, the implementation must verify:

1. The certificate's BLS aggregate signature against the claimed committee members.
2. That the signers constitute a valid quorum for the claimed round.
3. That the boosted block point is a known, valid block on a plausible chain.

Until real validation is implemented, the `hPerasCertDiffusionClient` handler should either be disabled or gated behind a feature flag that is off by default on production networks.

---

### Proof of Concept

1. Connect to a target node at `NodeToNodeV_16`.
2. Initiate the `PerasCertDiffusion` (ObjectDiffusion) mini-protocol as the outbound (server) side.
3. Send a `MsgObjects` message containing a `PerasCert` with:
   - `pcCertRound` set to the current Peras round.
   - `pcCertBoostedBlock` pointing to an adversarial fork tip.
4. Observe that `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight mkPerasParams}` without any check.
5. The certificate is stored in the `PerasCertDB` via `ChainDB.addPerasCertAsync`.
6. Chain selection now treats the adversarial fork tip as boosted, potentially switching the node's selected chain to the attacker-controlled fork.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L168-185)
```haskell
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

**File:** changelog.d/20250918_104810_thomas.bagrel_object_diffusion.md (L23-29)
```markdown
- Added support for `NodeToNodeV_16`
- Rely on a new version of `ouroboros-network` with support for ObjectDiffusion mini-protocol
- Modify `Ouroboros.Consensus{.Node,.Node.Tracer,.Network.NodeToNode}` to wire-in PerasCertDiffusion similarly to other mini-protocols (e.g. TX-submission)
- Add modules `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion{.Inbound,.Outbound}` with implementations of the ObjectDiffusion protocol (quite similar/inspired from TX-submission, except that client = inbound, server = outbound)
- Add module `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.API` defining `ObjectPool{Reader,Writer}` interfaces, through which ObjectDiffusion accesses/stores the objects to send/that have been received.
- Add modules `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.PerasCert` and `Ouroboros.Consensus.MiniProtocol.ObjectDiffusion.ObjectPool.PerasCert` containing definitions specific to `PerasCert` diffusion through the ObjectDiffusion mini-protocol 
- Modify `Ouroboros.Consensus.Node.Serialisation` to add CBOR serialisation (`SerialiseNodeToNode`) for `Point blk`, `Tip blk`, and `PerasCert blk`
```
