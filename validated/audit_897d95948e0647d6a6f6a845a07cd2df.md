### Title
Peras Certificate and Vote Signature Verification Bypass Enables Unauthorized Chain-Weight Manipulation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance in `SupportsPeras.hs` provides stub implementations of `validatePerasCert` and `validatePerasVote` that skip all cryptographic and semantic checks. `validatePerasCert` unconditionally returns `Right` for every certificate, and `validatePerasVote` only checks stake-distribution membership without verifying the vote signature. Both functions are wired into the live inbound-object pipeline and chain-selection path, so an unprivileged peer can inject crafted Peras certificates or impersonated votes that are accepted as valid, manipulating chain weight and potentially causing an honest node to prefer a non-canonical chain.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the `BlockSupportsPeras` typeclass defines two validation entry points:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)

validatePerasVote ::
  PerasCfg blk ->
  PerasVoteStakeDistr ->
  PerasVote blk ->
  Either (PerasValidationErr blk) (ValidatedPerasVote blk)
```

The universal instance (marked `-- TODO: degenerate instance for all blks to get things to compile`) implements these as:

**`validatePerasCert`** — always succeeds, performing zero checks:
```haskell
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

**`validatePerasVote`** — only checks stake-distribution membership, never verifies the vote signature:
```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The `PerasVote` data type carries only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId` — no cryptographic signature field at all in this instance. Any peer can therefore construct a `PerasVote` claiming to be any registered pool ID and it will pass validation.

These stubs are not isolated to tests. They are the **only** `BlockSupportsPeras` instance in the production codebase (the `{-# OVERLAPPABLE #-}` / universal instance covers all `StandardHash blk`), and they are called directly in the live inbound-object pipeline:

- `makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB` in `ObjectPool/PerasVote.hs` call `validatePerasVote mkPerasParams sd vote` on every inbound vote received from a peer.
- The `PerasCert` object pool calls `validatePerasCert` on every inbound certificate.
- Accepted `ValidatedPerasCert` objects are forwarded to `addPerasCertAsync` → `chainSelSync` (`ChainSel.hs`) → `chainSelectionForBlock`, which can trigger a fork switch to the boosted block's chain.
- Accepted `ValidatedPerasVote` objects accumulate in the `PerasVoteDB`; once quorum is reached, a certificate is automatically forged and submitted to the same chain-selection path via `addPerasVoteWithAsyncCertHandling`.

The analog to the external report is exact: just as `_withdraw` checked `caller` and `receiver` but omitted the `_owner` (the actual token holder), `validatePerasCert` checks none of the certificate's fields, and `validatePerasVote` checks the voter's stake-distribution membership but omits the cryptographic ownership proof (the vote signature). The "owner" check — i.e., proof that the claimed voter actually signed the vote — is entirely absent.

---

### Impact Explanation

An unprivileged peer can:

1. **Forge a certificate for any block**: Craft a `PerasCert { pcCertRound = r, pcCertBoostedBlock = p }` for any round `r` and any block point `p` in the node's VolatileDB. `validatePerasCert` returns `Right` unconditionally. The certificate is stored in `PerasCertDB` and triggers `chainSelectionForBlock` for the boosted block. Because Peras weight (`vpcCertBoost = perasWeight params`) is added to that block's chain, the node may switch to a non-canonical fork that it would otherwise not prefer.

2. **Impersonate any registered stake pool to cast votes**: Craft `PerasVote` messages claiming to be any pool ID present in the current `PerasVoteStakeDistr`. `validatePerasVote` accepts them because it only calls `lookupPerasVoteStake` (a map lookup on the voter ID) and never checks a signature. By sending enough such votes targeting the same block, the attacker can manufacture a quorum, causing the node to auto-forge a certificate and trigger chain selection for an attacker-chosen block.

Both paths lead to **unauthorized Peras certificate acceptance and chain-weight manipulation**, which is a bypass of Peras voting/certificate checks enabling an honest node to prefer a non-canonical chain — matching the "Critical/High" impact categories in the allowed scope.

---

### Likelihood Explanation

The inbound vote and certificate handlers are reachable by any peer connected via the Peras object-diffusion mini-protocol. No special privileges, keys, or stake are required. The attacker only needs to know a valid pool ID from the public stake distribution (which is on-chain public data) to pass the sole remaining check in `validatePerasVote`. The attack is therefore trivially executable by any network peer once the Peras mini-protocol is active.

---

### Recommendation

1. **`validatePerasCert`**: Implement full certificate validation — verify the aggregate BLS signature over `(electionId, candidate)` using the aggregated vote-verification keys of the claimed voters, verify each voter's eligibility (stake threshold, committee membership), and verify any VRF outputs for non-persistent members. The `implVerifyCert` functions in `Committee/EveryoneVotes.hs` and `Committee/WFALS.hs` show the correct pattern.

2. **`validatePerasVote`**: Add a cryptographic signature field to the `PerasVote` data type in this instance and verify it against the pool's registered vote-verification key before accepting the vote. Membership in the stake distribution is a necessary but not sufficient condition.

3. Remove or gate the universal `instance StandardHash blk => BlockSupportsPeras blk` so it cannot silently become the active instance for production block types once a real Cardano-era instance is added.

---

### Proof of Concept

**Certificate injection (no keys required):**

```
-- Attacker connects via Peras cert mini-protocol and sends:
PerasCert
  { pcCertRound      = <any round number>
  , pcCertBoostedBlock = <point of a block in the target node's VolatileDB>
  }
```

`validatePerasCert` returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally. [1](#0-0) 

The accepted cert is forwarded to `addPerasCertAsync` and then `chainSelSync`, which calls `chainSelectionForBlock` for the boosted block, potentially switching the node's preferred chain. [2](#0-1) 

**Vote impersonation (only a known pool ID required):**

```
-- Attacker sends N votes, each claiming to be a different registered pool:
PerasVote
  { pvVoteRound  = <target round>
  , pvVoteBlock  = <target block point>
  , pvVoteVoterId = PerasVoterId <any KeyHash StakePool from the public stake distr>
  }
```

`validatePerasVote` calls only `lookupPerasVoteStake vote stakeDistr` — a map lookup on `pvVoteVoterId` — and returns `Right` if the pool ID is present. [3](#0-2) 

Once enough such votes accumulate to exceed the quorum threshold, `addPerasVoteWithAsyncCertHandling` auto-forges a certificate and submits it to chain selection. [4](#0-3) 

The inbound vote validation call site in the live pipeline: [5](#0-4)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L481-532)
```haskell
-- Process a Peras certificate by adding it to the PerasCertDB and potentially
-- performing chain selection if a candidate is now better than our selection.
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-117)
```haskell
makePerasVotePoolWriterFromVoteDB systemTime getStakeDistrSTM perasVoteDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L130-152)
```haskell
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
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
