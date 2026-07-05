### Title
Unconditional `validatePerasCert` Acceptance Allows Any Peer to Inject Arbitrary Peras Certificates and Manipulate Chain Selection - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every inbound certificate, performing no cryptographic or semantic validation. Because this stub is wired directly into the production Peras certificate diffusion inbound path, any unprivileged peer can inject a crafted `PerasCert` pointing to an arbitrary block, causing the receiving node to apply a full Peras chain-selection boost to that block without any quorum of votes ever having been cast.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must be passed before a certificate received from a peer is stored and used in chain selection. The universal default instance (applied to all blocks via `instance StandardHash blk => BlockSupportsPeras blk`) implements this gate as a no-op stub:

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

Every field of the certificate — the claimed round number, the claimed boosted block, and any cryptographic proof of quorum — is accepted without inspection. The returned `ValidatedPerasCert` carries the full `perasWeight` boost regardless of certificate content.

This stub is called directly in the production inbound certificate pool writer:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` filters only for round-number deduplication (already-seen certificates are skipped), then calls `validateCert` on each new certificate. Because `validatePerasCert` always returns `Right`, every novel round number passes:

```haskell
processCerts systemTime alreadyInDbSTM validateCert addCert certs = do
  alreadyInDb <- atomically alreadyInDbSTM
  let certsNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasCertRound) certs
  now <- systemTimeCurrent systemTime
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    ([], validatedCerts) ->
      mapM_ (addCert . WithArrivalTime now) validatedCerts
    (errs, _) ->
      throw (PerasCertValidationError errs)
``` [3](#0-2) 

The accepted certificate is then forwarded to `ChainDB.addPerasCertAsync`, which triggers chain selection with the injected boost. The inbound handler is wired into the production node-to-node stack:

```haskell
hPerasCertDiffusionClient = \version controlMessageSTM peer ->
  objectDiffusionInbound
    ...
    (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
    ...
``` [4](#0-3) 

**Structural parallel to the external report.** In YoloV2, the whitelist checks the token *address* but not the token *type*, so a user can claim ERC721 type for an ERC20 address and bypass the actual token transfer, receiving free entries. Here, `processCerts` checks the certificate *round number* (for deduplication) but not the certificate's *cryptographic validity*, so a peer can claim any round number for any block and bypass the actual quorum requirement, receiving a free chain-selection boost.

---

### Impact Explanation

In Peras, a `ValidatedPerasCert` carries a `vpcCertBoost` weight that is added to the chain weight of the certified block during chain selection. A node that accepts a forged certificate for block `B` will prefer any chain whose tip descends from `B` over an equally-long honest chain, because the boost makes `B`'s subtree appear heavier. An attacker who controls even a single peer connection can therefore:

1. Inject a certificate for any block on a minority fork, causing the victim node to switch to that fork.
2. Inject a certificate for a block that does not exist on any chain, causing the node to hold a dangling boost that may interfere with future chain selection.
3. Repeat with a fresh round number for each injection (since deduplication is per-round), continuously steering the victim's chain selection.

This constitutes a **bypass of Peras certificate/vote verification** that enables unauthorized certificate acceptance and chain-selection manipulation by an unprivileged peer — matching the "Critical: Bypass of certificate/vote verification checks" and "High: Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact categories.

---

### Likelihood Explanation

The attack requires only a standard peer connection over the Peras certificate diffusion mini-protocol, which is open to any node-to-node peer. No keys, stake, or privileged access are needed. The attacker constructs a `PerasCert` CBOR payload with an arbitrary `pcCertRound` and `pcCertBoostedBlock`, sends it over the diffusion channel, and the victim node accepts it unconditionally. The attack is repeatable for every unused round number.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:

1. **Quorum proof**: the certificate must carry (or be derivable from) a set of votes whose aggregate stake exceeds the quorum threshold, each vote bearing a valid cryptographic signature from an eligible committee member.
2. **Round consistency**: the certified round number must be consistent with the current chain state (not in the past beyond the cooldown window, not in the far future).
3. **Boosted block existence**: `pcCertBoostedBlock` must refer to a block that is on a known chain fragment.

Until the real implementation is ready, the stub should at minimum return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that the inbound path is safely closed rather than unconditionally open. [5](#0-4) 

---

### Proof of Concept

**Attacker-controlled entry path:**

1. Peer connects to victim node; the `hPerasCertDiffusionClient` handler is instantiated.
2. Peer sends a single-element batch containing a crafted `PerasCert`:
   - `pcCertRound = 42` (any round not yet seen by the victim)
   - `pcCertBoostedBlock = <point of attacker's preferred block>`
3. `objectDiffusionInbound` delivers the batch to `makePerasCertPoolWriterFromChainDB`.
4. `opwAddObjects` calls `processCerts ... (validatePerasCert mkPerasParams) ...`.
5. `validatePerasCert` returns `Right ValidatedPerasCert { vpcCert = crafted, vpcCertBoost = perasWeight params }` — no error.
6. `ChainDB.addPerasCertAsync` stores the certificate and triggers chain selection.
7. Chain selection now treats the attacker's block as boosted by `perasWeight`, potentially switching the victim's selected chain.

**No stake, no keys, no quorum votes required.** [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-109)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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
