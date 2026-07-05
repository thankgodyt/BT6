### Title
Peras Certificate Diffusion Accepts Any Peer-Supplied Certificate Without Cryptographic Verification - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic or structural checks. Because this stub is wired directly into the live `PerasCertDiffusion` inbound handler, any unprivileged peer can inject an arbitrary `PerasCert` — for any round number and any block point — and the receiving node will accept it, store it in the `ChainDB`, and apply its weight boost during chain selection. This is a direct analog to the ERC721 deposit-frontrunning bug: just as any caller could invoke `addCollateral` and claim ownership of someone else's NFT, any peer can claim the authority of a legitimate Peras committee and redirect chain selection weight to a block of their choosing.

### Finding Description

**Root cause — stub `validatePerasCert` that always succeeds:** [1](#0-0) 

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

This is the **only** `BlockSupportsPeras` instance in the codebase — a catch-all degenerate instance for all `StandardHash blk` blocks: [2](#0-1) 

No signature, no committee membership check, no round-number bounds check, no boosted-block validity check is performed. Every field of the incoming `PerasCert` is trusted verbatim.

**Attacker-controlled entry path — production wiring in `NodeToNode.hs`:** [3](#0-2) 

The `hPerasCertDiffusionClient` handler calls `makePerasCertPoolWriterFromChainDB`, which passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`: [4](#0-3) 

**`processCerts` accepts the batch when all certs pass validation:** [5](#0-4) 

Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken, and every peer-supplied certificate is timestamped and forwarded to `ChainDB.addPerasCertAsync`.

**Contrast with the vote path:** The vote inbound handler at least attempts to look up the voter in a stake distribution (even though it currently uses an empty one): [6](#0-5) 

The certificate path has no equivalent guard at all.

### Impact Explanation

Peras certificates provide a weight boost (`perasWeight`) to the block they reference during chain selection. A node that has accepted a forged certificate for block `B` will treat `B` as heavier than an equally-long competing chain that lacks a certificate. An unprivileged peer can therefore:

1. Craft a `PerasCert` pointing to any block point and any round number.
2. Send it over the `PerasCertDiffusion` mini-protocol.
3. The receiving node stores it and applies its boost in chain selection.
4. The node may switch to, or refuse to abandon, a non-canonical chain that the attacker has boosted.

This is a **High** chain-selection integrity failure: an unprivileged peer can make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions of the Peras protocol.

### Likelihood Explanation

The attack requires only a standard node-to-node connection — no keys, no stake, no privileged access. Any peer that can establish a `NodeToNodeV_16`+ connection and speak the `ObjectDiffusion` mini-protocol can exploit this. The `PerasCertDiffusion` handler is unconditionally wired in `NodeToNode.hs` for all nodes that support the relevant protocol version.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:
1. Verifies the aggregate committee signature over `(roundNo, boostedBlock)`.
2. Checks that the signing committee members are registered and eligible for the claimed round.
3. Verifies the round number is within the acceptable window relative to the current chain tip.
4. Rejects any certificate whose boosted block is not a known, valid block point.

Until the full Peras committee plumbing is in place, the certificate inbound handler should either be disabled (not wired) or should reject all inbound certificates rather than accept them all.

### Proof of Concept

1. Start a node with `NodeToNodeV_16` support (Peras cert diffusion enabled).
2. Connect a malicious peer that speaks the `ObjectDiffusion` protocol.
3. The peer sends a `PerasCert { pcCertRound = R, pcCertBoostedBlock = P }` where `P` is the point of any block on a minority fork.
4. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right (ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams })`.
5. The certificate is stored in the `ChainDB` via `addPerasCertAsync`.
6. Chain selection now treats the minority-fork block at `P` as having a Peras weight boost equal to `perasWeight`, potentially causing the honest node to switch to or retain the minority fork. [7](#0-6) [8](#0-7) [3](#0-2)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-321)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-371)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasValidationErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right
          ValidatedPerasVote
            { vpvVote = vote
            , vpvVoteStake = stake
            }
    | otherwise =
        Left PerasValidationErr
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-174)
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
```
