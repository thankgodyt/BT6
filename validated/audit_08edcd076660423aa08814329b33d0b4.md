### Title
Peras Certificate and Vote Validation Bypass Allows Any Peer to Inject Unauthorized Certificates and Forge Votes — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `BlockSupportsPeras` instance unconditionally accepts every inbound Peras certificate (`validatePerasCert` always returns `Right`) and validates votes solely by checking whether the claimed voter ID appears in the stake distribution, with no cryptographic signature field or proof in the `PerasVote` type. Any unprivileged peer connected via the live `hPerasCertDiffusionClient` / `hPerasVoteDiffusionClient` mini-protocol handlers can inject arbitrary certificates or forge votes on behalf of any registered stake pool, bypassing all authorization checks.

---

### Finding Description

**Root cause 1 — `validatePerasCert` is a no-op:**

The sole `BlockSupportsPeras` instance (the catch-all `instance StandardHash blk => BlockSupportsPeras blk`) implements `validatePerasCert` as an unconditional `Right`:

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

No signature, quorum, or committee membership check is performed. Every certificate, regardless of origin or content, is accepted as `ValidatedPerasCert`.

**Root cause 2 — `PerasVote` carries no signature; `validatePerasVote` only checks stake-distribution membership:**

The `PerasVote` data type contains only a round number, a block point, and a voter ID — no cryptographic proof of authorship:

```haskell
data PerasVote blk = PerasVote
    { pvVoteRound   :: PerasRoundNo
    , pvVoteBlock   :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
``` [2](#0-1) 

`validatePerasVote` then accepts any vote whose `pvVoteVoterId` appears in the stake distribution, assigning it the full stake of that pool:

```haskell
validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [3](#0-2) 

**Attacker-controlled entry path — live network handlers:**

Both the cert and vote diffusion inbound handlers are wired up in the production `NodeToNode` application:

```haskell
, hPerasCertDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound ...
    (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
    ...
, hPerasVoteDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound ...
    ( makePerasVotePoolWriterFromChainDB
        systemTime
        (pure (PerasVoteStakeDistr mempty))   -- empty distr → all votes rejected
        getChainDB
    )
``` [4](#0-3) 

For **certificates**, the writer calls `validatePerasCert` (always `Right`) and then `ChainDB.addPerasVoteWithAsyncCertHandling` / the cert equivalent, storing the attacker-supplied cert in the ChainDB. [5](#0-4) 

For **votes**, the current deployment passes `PerasVoteStakeDistr mempty` (empty map), so `lookupPerasVoteStake` always returns `Nothing` and all votes are rejected — this accidentally mitigates the vote-forgery path today. However, once the TODO is resolved and a real stake distribution is wired in, any peer will be able to forge votes for any pool with no signature check, because the `PerasVote` type has no signature field.

The cert path has **no such accidental mitigation**: `validatePerasCert` ignores the stake distribution entirely and always succeeds.

**`processVotes` / cert writer flow:** [6](#0-5) 

Valid (attacker-crafted) certs pass straight through to `ChainDB.addPerasVoteWithAsyncCertHandling`, which triggers chain-selection side-effects.

---

### Impact Explanation

**Certificate path (currently exploitable):** Any peer can send a `PerasCert { pcCertRound = r, pcCertBoostedBlock = p }` for an arbitrary block point `p`. `validatePerasCert` returns `Right` unconditionally. The cert is stored in the ChainDB and used by the Peras chain-selection logic to boost the attacker-chosen block, potentially causing an honest node to prefer a non-canonical or adversarially-selected chain over the honest chain. This is a **Critical** bypass of Peras certificate checks enabling unauthorized certificate acceptance and a **High** chain-selection bug.

**Vote path (latent, triggered when stake distribution is plumbed in):** Once the `TODO` at line 400–406 of `NodeToNode.hs` is resolved, any peer can forge votes on behalf of any registered stake pool (full stake weight, no signature required), manufacture artificial quorum for an attacker-chosen block, and cause a certificate to be forged and stored — same chain-selection impact as above.

---

### Likelihood Explanation

The cert diffusion handler is live and reachable by any connected peer without any privilege. Crafting a `PerasCert` CBOR payload requires only knowledge of the serialization format (public). The attacker needs no keys, no stake, and no special role — only a standard node-to-node connection. The vote-forgery path requires waiting for the stake-distribution plumbing to be completed, but the structural defect (no signature field) is already present.

---

### Recommendation

1. **`validatePerasCert`**: Implement real certificate validation — verify the aggregate BLS/committee signature over `(pcCertRound, pcCertBoostedBlock)` against the committee's public keys and quorum threshold before returning `Right`. Remove the unconditional `Right` stub.

2. **`PerasVote` / `validatePerasVote`**: Add a cryptographic signature field to `PerasVote` (analogous to `WFALSPersistentVote`'s `sig` field in the WFALS committee implementation). `validatePerasVote` must verify this signature against the pool's registered vote-verification key before accepting the vote.

3. Until both fixes are in place, consider gating the cert and vote diffusion mini-protocols behind a feature flag that is disabled by default, so the unauthenticated handlers are not reachable on production nodes.

---

### Proof of Concept

**Certificate injection (currently exploitable):**

1. Connect to a target node via the node-to-node protocol.
2. Negotiate the `PerasCertDiffusion` mini-protocol.
3. Send a CBOR-encoded `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <attacker-chosen block point>`.
4. The node's `hPerasCertDiffusionClient` handler calls `makePerasCertPoolWriterFromChainDB`, which calls `validatePerasCert`.
5. `validatePerasCert` returns `Right (ValidatedPerasCert { vpcCert = <attacker cert>, vpcCertBoost = perasWeight params })` unconditionally.
6. The cert is stored in the ChainDB and the Peras chain-selection logic boosts the attacker-chosen block.
7. The node may switch to or prefer a chain ending at the attacker-chosen block, diverging from the honest chain.

**Expected outcome:** The node accepts the forged certificate and applies the Peras boost to an attacker-controlled block point, demonstrating a complete bypass of Peras certificate authorization — the direct analog of the `_increase`-without-`onlyIfApproved` vulnerability in the external report. [7](#0-6) [8](#0-7)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-410)
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
      , hPerasCertDiffusionServer = \version peer ->
          objectDiffusionOutbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionOutboundTracer tracers))
            (perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters)
            (makePerasCertPoolReaderFromChainDB $ getChainDB)
            version
      , hPerasVoteDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasVoteDiffusionInboundTracer tracers))
            ( perasVoteDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 50 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
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
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-152)
```haskell
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
    , opwHasObject = do
        voteIds <- ChainDB.getPerasVoteIds chainDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-201)
```haskell
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```
