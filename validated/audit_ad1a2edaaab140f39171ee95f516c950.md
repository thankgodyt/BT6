### Title
Missing Cryptographic Signature Verification in `validatePerasVote` Allows Any Peer to Impersonate Any Registered Stake Pool Voter — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production `validatePerasVote` implementation in `SupportsPeras.hs` accepts a Peras vote as valid solely by looking up the self-reported `pvVoteVoterId` in the stake distribution. The `PerasVote` data type carries no cryptographic signature field, and no ownership proof is verified. Any unprivileged peer connected via the Peras vote diffusion miniprotocol can craft a `PerasVote` claiming to be any registered stake pool, and the node will accept it with that pool's full stake weight. By impersonating enough voters, an attacker can manufacture a quorum certificate for an arbitrary block, causing honest nodes to boost a non-canonical chain.

---

### Finding Description

**Root cause — missing identity verification in `validatePerasVote`**

The `PerasVote` associated data type defined in the degenerate `BlockSupportsPeras` instance contains only three fields: round number, target block, and a self-reported voter identity (`pvVoteVoterId`):

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- self-reported, no signature
  }
``` [1](#0-0) 

There is no `pvSignature` field. The validation function then accepts the vote if and only if the self-reported voter ID is present in the stake distribution:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`lookupPerasVoteStake` simply does a `Map.lookup` on `pvVoteVoterId`: [3](#0-2) 

No cryptographic proof that the sender controls the private key for `pvVoteVoterId` is ever requested or checked. This is the direct analog of the NFT `_debitFrom` bug: the function trusts a caller-supplied identity field (`pvVoteVoterId` / `_from`) without verifying the caller actually owns that identity.

**Contrast with the complete V1 vote type**

The separately defined `V1.PerasVote` (used in the WFALS committee path) does carry a `pvSignature` field and is verified via `implVerifyVote` / `verifyVoteSignature`. The production `BlockSupportsPeras` instance is a placeholder that omits this entirely: [4](#0-3) [5](#0-4) 

**Attacker-controlled entry path**

The Peras vote diffusion inbound handler in `NodeToNode.hs` wires `makePerasVotePoolWriterFromChainDB` directly into the peer-facing miniprotocol:

```haskell
, hPerasVoteDiffusionClient = \version controlMessageSTM peer ->
    objectDiffusionInbound
      ...
      ( makePerasVotePoolWriterFromChainDB
          systemTime
          (pure (PerasVoteStakeDistr mempty))   -- TODO placeholder
          getChainDB
      )
``` [6](#0-5) 

`makePerasVotePoolWriterFromChainDB` calls `processVotes`, which calls `validatePerasVote` on every inbound vote: [7](#0-6) 

`processVotes` accepts the entire batch if all votes pass `validatePerasVote`, then stores them in the `PerasVoteDB`: [8](#0-7) 

**Current partial mitigation and why it does not fix the root cause**

The current production wiring passes `pure (PerasVoteStakeDistr mempty)` as the stake distribution. Because the map is empty, `lookupPerasVoteStake` always returns `Nothing`, and every vote is currently rejected. The code comment explicitly acknowledges this is a temporary placeholder:

> "Note that the empty stake distribution will cause all votes to be considered invalid." [9](#0-8) 

The moment the TODO is resolved and a real stake distribution is plumbed in — which is the stated intent — the vulnerability becomes immediately and fully exploitable with zero additional preconditions. The root cause (no signature field, no ownership check) is in the production code today.

---

### Impact Explanation

**High — Bypass of vote authorization enabling unauthorized certificate acceptance and chain boosting.**

Once a real stake distribution is connected (the explicitly planned next step), any unprivileged peer can:

1. Enumerate registered stake pool key hashes from the public ledger state.
2. Craft `PerasVote` messages claiming to be each of those pools.
3. Submit them via the open Peras vote diffusion miniprotocol.
4. Accumulate enough impersonated stake weight to exceed the quorum threshold.
5. Trigger `updatePerasRoundVoteStates` to forge a `PerasCert` boosting an arbitrary block.

The resulting certificate causes honest nodes to apply a `perasWeight` boost to a block of the attacker's choosing during chain selection, potentially making a non-canonical or adversarial chain preferred over the honest chain. This is a direct bypass of vote authorization and certificate verification, matching the "High — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain" impact category.

---

### Likelihood Explanation

**High.** The entry path is the standard Peras vote diffusion miniprotocol, reachable by any peer without credentials. The exploit requires only constructing a valid CBOR-encoded `PerasVote` with a known voter ID — no cryptographic material is needed. The only current barrier is the empty stake distribution placeholder, which is explicitly scheduled for removal. No preconditions beyond network connectivity are required.

---

### Recommendation

1. **Add a cryptographic signature field to `PerasVote blk`** (analogous to `pvSignature` in `V1.PerasVote`) before connecting a real stake distribution.
2. **Extend `validatePerasVote`** to verify that the signature in the vote is valid under the public key associated with `pvVoteVoterId` in the stake distribution, following the pattern of `implVerifyVote` in `WFALS.hs` which calls `verifyVoteSignature` against the voter's registered public key.
3. **Do not replace `pure (PerasVoteStakeDistr mempty)`** with a real stake distribution until steps 1 and 2 are complete, as doing so in the current state immediately opens the impersonation attack.

---

### Proof of Concept

On a private testnet with Peras vote diffusion enabled and a non-empty stake distribution plumbed in:

```
-- Attacker knows pool key hash P1 is registered with stake S1 > quorum_threshold
-- Attacker constructs:
vote = PerasVote
  { pvVoteRound   = currentRound
  , pvVoteBlock   = adversarialBlockPoint
  , pvVoteVoterId = PerasVoterId P1   -- impersonated; no signature required
  }

-- Attacker sends vote via PerasVoteDiffusion miniprotocol to target node.
-- processVotes calls validatePerasVote mkPerasParams realStakeDistr vote
-- lookupPerasVoteStake finds P1 -> S1 in the map
-- Returns Right (ValidatedPerasVote vote S1)
-- If S1 >= quorum threshold, updatePerasRoundVoteStates forges a PerasCert
-- boosting adversarialBlockPoint, causing chain selection to prefer it.
```

The attacker needs no private key for P1. The `PerasVote` data type has no signature field, so there is nothing to forge. The only check performed — `Map.lookup pvVoteVoterId stakeDistr` — passes trivially for any known registered pool ID.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L196-203)
```haskell
lookupPerasVoteStake ::
  PerasVote blk ->
  PerasVoteStakeDistr ->
  Maybe PerasVoteStake
lookupPerasVoteStake vote distr =
  Map.lookup
    (pvVoteVoterId vote)
    (unPerasVoteStakeDistr distr)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
    deriving stock (Generic, Eq, Ord, Show)
    deriving anyclass NoThunks
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Vote/V1.hs (L36-50)
```haskell
data PerasVote
  = PerasVote
  { pvRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pvBoostedBlock :: !PerasBoostedBlock
  -- ^ Vote message, i.e., the hash of the block being voted for
  , pvSeatIndex :: !PerasSeatIndex
  -- ^ Seat index assigned to the committee member (identifies the voter)
  , pvEligibilityProof :: !PerasVoteEligibilityProof
  -- ^ Proof of eligibility for voting, depending on the type of membership to
  -- the committee (persistent vs non-persistent)
  , pvSignature :: !(VoteSignature PerasBLSCrypto)
  -- ^ BLS signature on the hash of the election identifier and vote message
  }
  deriving (Show, Eq)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L337-350)
```haskell
implVerifyVote committee = \case
  WFALSPersistentVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , isPersistentMember seatIndex committee -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        checkVoteSignature voterVerificationKey electionId candidate sig
        pure $
          WFALSPersistentMember
            seatIndex
            voterStake
    | otherwise -> do
        Left (NotAPersistentMember seatIndex)
```

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L391-410)
```haskell
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
