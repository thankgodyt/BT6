### Title
Unconditional Acceptance of Any Peras Certificate from Unprivileged Peers Bypasses All Vote/Quorum Validation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance — which is the **only** production instance, applied universally via `instance StandardHash blk => BlockSupportsPeras blk` — implements `validatePerasCert` as an unconditional stub that returns `Right` for every certificate it receives, performing zero cryptographic, quorum, or voter-eligibility checks. Any unprivileged peer connected via the Peras certificate diffusion mini-protocol can send a crafted `PerasCert` claiming to boost any block, and the node will accept it, add it to the ChainDB, and apply its chain-selection boost weight. This is the direct analog of the reported "Missing Sender Validation" class: the identity and legitimacy of the certificate submitter are never verified.

### Finding Description

**Root cause — `validatePerasCert` stub:**

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

This is not a dead-code path. It is the live production implementation for all block types. The `TODO` comment and linked issue confirm the validation is intentionally deferred but the code is already wired into the live network stack.

**Attacker-controlled entry path:**

1. A peer connects via the Peras certificate diffusion mini-protocol (`hPerasCertDiffusionClient` in `NodeToNode.hs`).
2. The handler calls `makePerasCertPoolWriterFromChainDB`, which passes `validatePerasCert mkPerasParams` as the validator to `processCerts`.
3. `processCerts` calls `validateCert` on each inbound certificate. Because `validatePerasCert` always returns `Right`, every certificate passes.
4. Each "validated" certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync`. [2](#0-1) [3](#0-2) 

The diffusion handler in `NodeToNode.hs` wires this directly into the live node: [4](#0-3) 

**What is missing:** A real `validatePerasCert` must verify (a) that the certificate carries a valid aggregate BLS signature over the claimed quorum of eligible voters, (b) that the voters were actually elected to the committee for that round, and (c) that the quorum threshold was met. None of these checks exist. The `PerasCert` data type itself carries only `pcCertRound` and `pcCertBoostedBlock` — no signature field — so even if the validator tried to check a signature, there is nothing to check in the current wire format. [5](#0-4) 

### Impact Explanation

The Peras protocol's security property is that a certificate, once accepted, boosts the referenced block by `perasWeight` in chain selection, making it significantly harder to roll back. An attacker who can inject a fake certificate boosting an adversarial block causes honest nodes to treat that block as if it had received a legitimate quorum of committee votes. This directly enables:

- **Chain selection manipulation**: the node will prefer the adversarially boosted chain over the honest canonical chain, because the boosted chain's `SelectView` is inflated by `perasWeight`.
- **Rollback resistance for adversarial blocks**: once a fake cert is accepted, the honest node's chain-selection logic treats the adversarial block as "certified," making it resistant to being displaced even by a longer honest chain (depending on Peras parameters).

This matches the **High** impact category: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

### Likelihood Explanation

The Peras certificate diffusion mini-protocol is a standard node-to-node protocol, reachable by any peer that can establish a connection. No keys, stake, or operator access are required. The attacker only needs to:
1. Connect to a target node as a peer.
2. Send a `PerasCert` with `pcCertBoostedBlock` pointing to any block they wish to boost.

The `processCerts` deduplication check (skipping certs whose round is already in the DB) only prevents re-injection of the same round number, not injection of a cert for a new round. An attacker can inject one fake cert per Peras round indefinitely.

### Recommendation

1. **Implement real `validatePerasCert`**: verify the aggregate BLS signature over the claimed voter set, check each voter's committee eligibility for the given round using the epoch nonce and stake distribution, and confirm the quorum threshold is met. The `EveryoneVotes` and `WFALS` committee implementations in `Committee/EveryoneVotes.hs` and `Committee/WFALS.hs` already provide the correct `verifyCert` primitives that should be called here.
2. **Add a signature field to `PerasCert`**: the current wire format carries no aggregate signature, making cryptographic verification structurally impossible. The `PerasCert` data type must be extended before validation can be meaningful.
3. **Do not deploy the Peras certificate diffusion mini-protocol** in any environment where untrusted peers can connect until both of the above are resolved.

### Proof of Concept

**Attacker steps (private testnet):**

1. Run a node with the Peras certificate diffusion protocol enabled.
2. Connect as a peer and send a `PerasCert` message with:
   - `pcCertRound = <any round not yet in the DB>`
   - `pcCertBoostedBlock = <Point of an adversarial block>`
3. Observe that `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams })` unconditionally.
4. The certificate is forwarded to `ChainDB.addPerasCertAsync` and stored.
5. Chain selection now treats the adversarial block as boosted by `perasWeight`, causing the node to prefer the adversarial chain over the honest canonical chain. [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
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
