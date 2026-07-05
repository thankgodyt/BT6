### Title
`validatePerasCert` Stub Unconditionally Accepts Any Peer-Supplied Peras Certificate, Enabling Unauthorized Chain Selection Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as a stub that unconditionally returns `Right` for every certificate it receives, performing no cryptographic or structural verification whatsoever. Because the production `PerasCertDiffusion` inbound handler calls this stub directly before inserting certificates into the ChainDB, any unprivileged peer can inject an arbitrary fake Peras certificate that will be accepted, stored, and used to boost a block's chain-selection weight, potentially causing the node to switch to a non-canonical fork.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub:**

The `BlockSupportsPeras` class declares `validatePerasCert` as the gate that must verify a certificate before it is trusted. The only concrete instance in the codebase is the universal stub:

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

This always returns `Right`, wrapping the raw peer-supplied `PerasCert` in a `ValidatedPerasCert` with a non-zero `vpcCertBoost`. No BLS aggregate signature check, no committee membership check, no quorum threshold check, and no round-number sanity check is performed.

**Contrast with vote validation:** `validatePerasVote` at least performs a stake-distribution lookup and returns `Left` when the voter is absent. Additionally, the vote inbound handler in `NodeToNode.hs` is wired with an empty stake distribution (`pure (PerasVoteStakeDistr mempty)`), so all peer-supplied votes are rejected in practice. No equivalent guard exists for certificates. [2](#0-1) [3](#0-2) 

**Inbound path — peer cert reaches `processCerts` with the stub as validator:**

`makePerasCertPoolWriterFromChainDB` is wired as the inbound handler for the `PerasCertDiffusion` mini-protocol in `NodeToNode.hs`:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
      ...
``` [4](#0-3) 

Inside `makePerasCertPoolWriterFromChainDB`, `processCerts` is called with `validatePerasCert mkPerasParams` as the validation function and `ChainDB.addPerasCertAsync chainDB` as the sink:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  -- TODO replace when actual plumbing is in place
  (validatePerasCert mkPerasParams)
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [5](#0-4) 

`processCerts` calls `validateCert` on each new certificate and, if all pass (which they always do), forwards them to `addCert`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [6](#0-5) 

**Chain selection side-effect:**

`ChainDB.addPerasCertAsync` enqueues the certificate for processing by `chainSelSync`. The handler for `ChainSelAddPerasCert` adds the cert to the `PerasCertDB` and then calls `chainSelectionForBlock` for the boosted block, potentially switching the node to a different fork:

```haskell
-- Trigger chain selection for the boosted block.
lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [7](#0-6) 

The `ValidatedPerasCert` carries a `vpcCertBoost` equal to `perasWeight params`, which is added to the weight of the boosted block's chain fragment during chain selection. A candidate chain that would otherwise lose the selection can win once its tip block is boosted by a fake certificate. [8](#0-7) 

---

### Impact Explanation

**Classification:** High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain beyond the intended security assumptions.

A peer with a network connection can craft a `PerasCert` naming any block hash and any round number. Because `validatePerasCert` never rejects anything, the certificate is stored in the `PerasCertDB` and triggers `chainSelectionForBlock` for the named block. If that block is the tip of a competing fork, the fork gains `perasWeight` additional weight and may become the node's preferred chain. The node then rolls back its current selection and adopts the attacker's fork, accepting blocks that would otherwise be non-canonical. This is a direct consensus safety failure: an honest node's chain selection is manipulated by a single unauthenticated network message.

---

### Likelihood Explanation

The `PerasCertDiffusion` mini-protocol is enabled unconditionally in the production `NodeToNode` handler setup. Any peer that can establish a node-to-node connection — which requires no credentials — can send a `PerasCert` message. The attacker needs only to know (or guess) the hash of a block on a competing fork, which is public information available via `ChainSync`. No stake, no keys, and no privileged access are required.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with real cryptographic and structural validation before the Peras certificate diffusion protocol is enabled in production. At minimum, the validation must:

1. Verify the BLS aggregate signature against the claimed committee members' public keys.
2. Confirm that the claimed voters are registered members of the correct Peras committee for the given round (using the epoch stake distribution and committee selection algorithm).
3. Confirm that the aggregate stake of the claimed voters meets the quorum threshold defined in `PerasCfg`.
4. Confirm that `pcCertRound` and `pcCertBoostedBlock` are internally consistent (the boosted block's slot falls within the correct Peras round window).

As an immediate mitigation (analogous to the empty-stake-distribution guard already applied to votes), the certificate inbound handler should be wired with a validation function that rejects all certificates until the real validation logic is in place, rather than accepting all of them.

---

### Proof of Concept

**Setup:** A private testnet with two nodes, A (honest) and B (attacker). Both nodes have received blocks up to slot S. There is a competing fork F whose tip block T is in node B's VolatileDB but not on node A's current chain.

**Steps:**

1. Attacker (node B) connects to node A via the node-to-node `PerasCertDiffusion` mini-protocol.
2. Attacker sends a single `PerasCert` message:
   ```
   PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <Point of T> }
   ```
   The message requires no signature, no committee proof, and no VRF output — the `PerasCert` data type contains only a round number and a block point. [9](#0-8) 
3. Node A's `processCerts` calls `validatePerasCert mkPerasParams` on the received cert. The stub returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight mkPerasParams }` unconditionally.
4. The cert is forwarded to `ChainDB.addPerasCertAsync`. The background chain-selection thread processes `ChainSelAddPerasCert`, adds the cert to `PerasCertDB`, and calls `chainSelectionForBlock` for block T.
5. Fork F, now boosted by `perasWeight`, outweighs node A's current chain. Node A rolls back and adopts fork F as its new preferred chain.

**Expected outcome without the bug:** Step 3 returns `Left PerasValidationErr` because the certificate carries no valid aggregate BLS signature from a quorum of registered committee members. Node A disconnects from the attacker peer.

**Actual outcome with the bug:** Node A accepts the fake certificate and switches to the attacker's fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-210)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L363-371)
```haskell
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-409)
```haskell
            ( makePerasVotePoolWriterFromChainDB
                systemTime
                -- TODO: when actual plumbing for Peras is ready, we will have to
                -- extract the committee selection data from the chainDB to pass
                -- it here, instead of relying on an empty the stake distribution.
                --
                -- Note that the empty stake distribution will cause all votes to
                -- be considered invalid.
                (pure (PerasVoteStakeDistr mempty))
                getChainDB
            )
            version
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L529-532)
```haskell
    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```
