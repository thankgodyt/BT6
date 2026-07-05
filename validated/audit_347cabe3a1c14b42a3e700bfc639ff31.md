### Title
Peras Certificate and Vote Validation Stubs Accept Any Peer-Supplied Input Without Cryptographic Verification — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default implementations of `validatePerasCert` and `validatePerasVote` in `BlockSupportsPeras` are acknowledged stubs that perform no cryptographic verification. `validatePerasCert` unconditionally returns `Right` for every certificate it receives, and `validatePerasVote` only checks stake-distribution membership without verifying the vote's cryptographic signature. An unprivileged peer can therefore submit a crafted Peras certificate or vote that is accepted as valid, causing the node to apply an illegitimate Peras weight boost to an attacker-chosen block and manipulate chain selection.

---

### Finding Description

The `BlockSupportsPeras` type class in `SupportsPeras.hs` provides default method implementations that are explicitly marked as stubs pending full implementation (tracked under `https://github.com/tweag/cardano-peras/issues/120`).

**`validatePerasCert` — unconditional acceptance:**

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

Every `PerasCert` supplied by any caller is wrapped in `Right` and returned as a `ValidatedPerasCert` with a full weight boost. No signature, no committee membership check, no round-number bounds check. [1](#0-0) 

**`validatePerasVote` — signature-free acceptance:**

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
-- see https://github.com/tweag/cardano-peras/issues/120
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
```

The only check is whether the claimed voter ID appears in the stake distribution. No cryptographic signature over the vote body is verified. Any peer that knows a valid voter ID (all pool IDs are public on-chain) can forge a vote for that voter. [2](#0-1) 

**`implAddVote` — acknowledged missing validation:**

The `PerasVoteDB` implementation carries an explicit TODO confirming that the validation layer inside the DB is also absent:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote :: ...
``` [3](#0-2) 

**Inbound diffusion pipeline — the reachable entry point:**

Peras votes received from peers are processed by `processVotes` in `ObjectPool/PerasVote.hs`. It calls the `validateVote` callback, which in the production `NodeToNode.hs` handler is wired to `validatePerasVote` with the current stake distribution. If any vote passes, it is timestamped and forwarded to `ChainDB.addPerasVoteWithAsyncCertHandling`. [4](#0-3) 

The `NodeToNode.hs` handler currently passes `pure (PerasVoteStakeDistr mempty)` as the stake distribution, which incidentally blocks the vote path today (no voter ID matches an empty map). However, this is itself a placeholder:

```haskell
-- TODO: when actual plumbing for Peras is ready, we will have to
-- extract the committee selection data from the chainDB to pass
-- it here, instead of relying on an empty the stake distribution.
--
-- Note that the empty stake distribution will cause all votes to
-- be considered invalid.
(pure (PerasVoteStakeDistr mempty))
``` [5](#0-4) 

Once the real stake distribution is plumbed in (the intended next step), `validatePerasVote` will accept any vote whose voter ID appears in the distribution — without verifying the signature — and `validatePerasCert` will accept every certificate unconditionally regardless.

The `addPerasCertAsync` path in `ChainDB` accepts a `ValidatedPerasCert` and triggers chain selection re-evaluation with the Peras weight boost applied. [6](#0-5) 

---

### Impact Explanation

Peras certificates apply a weight boost to a specific block, directly influencing chain selection. A node that accepts a forged certificate for an attacker-chosen block will compute a higher weight for the chain containing that block and may switch to it, abandoning the honest canonical chain. This is a chain-selection manipulation bug: an unprivileged peer can make an honest node prefer a non-canonical or adversarially-chosen chain beyond the intended security assumptions of the Peras protocol.

The `validatePerasCert` stub is the most severe path because it requires no knowledge of any key or stake — it accepts every certificate unconditionally. The `validatePerasVote` stub becomes equally severe once the real stake distribution is connected, because any peer knowing a pool's public ID (universally public) can forge votes for that pool.

---

### Likelihood Explanation

The vulnerability is latent but on the direct activation path: the only thing preventing exploitation today is the temporary `mempty` stake distribution placeholder for votes, and the cert path has no such guard at all. The moment the Peras plumbing is completed as intended (connecting the real committee/stake data), both paths become immediately exploitable by any peer that can open a Peras diffusion connection — no keys, no stake, no special privilege required.

---

### Recommendation

1. **`validatePerasCert`**: Implement full certificate verification before the Peras diffusion handler is connected to real data. At minimum, verify the aggregate BLS/committee signature over the certificate body using the committee's public keys derived from the current ledger state. Return `Left` for any certificate that fails.

2. **`validatePerasVote`**: Extend validation to verify the cryptographic signature on the vote body (using the voter's registered verification key from the ledger) in addition to the stake-distribution membership check.

3. **`implAddVote`**: Resolve the tracked TODO (issue #120) before enabling the real stake distribution in the diffusion handler. Consider whether a second validation layer inside the DB is needed as a defence-in-depth measure.

4. **Deployment gate**: Do not replace `pure (PerasVoteStakeDistr mempty)` with the real stake distribution until items 1–3 are complete and tested.

---

### Proof of Concept

With the real stake distribution connected (the intended next step), an attacker peer can:

1. Observe any pool ID `pid` from the on-chain stake distribution (public information).
2. Construct a `PerasCert` for an arbitrary block `B` at round `r`:
   ```
   PerasCert { pcCertRound = r, pcCertBoostedBlock = pointOf(B) }
   ```
3. Send it via the Peras cert diffusion mini-protocol to the target node.
4. `validatePerasCert` returns `Right (ValidatedPerasCert { vpcCert = ..., vpcCertBoost = perasWeight params })` unconditionally.
5. `addPerasCertAsync` inserts the cert; chain selection re-runs with `B` boosted.
6. If `B` is on a fork, the node switches to that fork.

For votes: construct `PerasVote { pvVoteRound = r, pvVoteBlock = pointOf(B), pvVoteVoterId = pid }` for enough distinct `pid` values to exceed the quorum threshold. Each passes `validatePerasVote` (stake-distribution membership only), accumulates in `PerasVoteDB`, and triggers `forgePerasCert` once quorum is reached — again with no signature ever checked. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-371)
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

  forgePerasCert ::
    PerasCfg blk ->
    ValidatedPerasVotesWithQuorum blk ->
    Either (PerasForgeErr blk) (ValidatedPerasCert blk)

  -- | Extract a Peras certificate optionally stored in a block.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  getPerasCertInBlock ::
    blk ->
    Maybe (PerasCert blk)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-246)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
implAddVote ::
  ( IOLike m
  , StandardHash blk
  , Typeable blk
  ) =>
  PerasCfg blk ->
  PerasVoteDbEnv m blk ->
  WithArrivalTime (ValidatedPerasVote blk) ->
  STM m (m (AddPerasVoteResult blk))
implAddVote perasCfg PerasVoteDbEnv{pvdeTracer, pvdeState} vote = do
  let voteId = getPerasVoteId vote
  addPerasVoteRes <- do
    WithFingerprint pvds fp <- readTVar pvdeState
    (res, pvds') <- addOrIgnoreVote pvds voteId
    writeTVar pvdeState (WithFingerprint pvds' (succ fp))
    pure res
  pure $ do
    traceWith pvdeTracer (AddVote voteId vote addPerasVoteRes)
    return addPerasVoteRes
 where
  addOrIgnoreVote pvds voteId
    -- Vote is already in the DB => ignore it
    | Set.member voteId (pvdsVoteIds pvds) = voteAlreadyInDB pvds
    -- New vote => try to add it to the DB
    | otherwise = tryAddVote pvds voteId

  voteAlreadyInDB pvds = pure (PerasVoteAlreadyInDB, pvds)

  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
        -- because quorum was not reached yet, or because this vote was
        -- cast upon a target that had already won so a certificate was
        -- forged in a previous step.
        Right (VoteDidntGenerateNewCert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteButDidntGenerateNewCert, pvsRoundVoteStates')
        -- Adding the vote led to more than one winner => internal error
        Left (RoundVoteStateLoserAboveQuorum winnerState loserState) ->
          throwSTM $
            MultipleWinnersInRound
              (getPerasVoteRound vote)
              ( ExistingPerasRoundWinner
                  ( getPerasVoteBlock winnerState
                  , ptvsTotalStake winnerState
                  )
              )
              ( BlockedPerasRoundWinner
                  ( getPerasVoteBlock loserState
                  , ptvsTotalStake loserState
                  )
              )
        -- Reached quorum but failed to forge a certificate
        Left (RoundVoteStateForgingCertError forgeErr) ->
          throwSTM $
            ForgingCertError forgeErr

    pure
      ( addPerasVoteRes
      , PerasVoteDbState
          { pvdsVoteIds = pvsVoteIds'
          , pvdsRoundVoteStates = pvsRoundVoteStates'
          , pvdsVotesByTicket = pvsVotesByTicket'
          , pvdsLastTicketNo = pvsLastTicketNo'
          }
      )
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L121-152)
```haskell
-- of them (see 'ChainDB.addPerasVoteWithAsyncCertHandling').
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-408)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```
