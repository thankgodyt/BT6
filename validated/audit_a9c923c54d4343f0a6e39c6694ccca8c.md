### Title
Missing Cryptographic Signature in `PerasVote` and No Signature Verification in `validatePerasVote` Allows Unauthorized Vote Acceptance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `PerasVote` data type carries no cryptographic signature field, and the `validatePerasVote` implementation only checks whether the claimed voter ID (`pvVoteVoterId`) is present in the stake distribution. No proof that the stake pool operator actually authorized the vote is required or verified. An unprivileged peer can forge a `PerasVote` for any stake pool operator by simply setting `pvVoteVoterId` to the target pool's key hash. When enough such forged votes reach quorum, a fraudulent Peras certificate is generated and stored in the `ChainDB`, boosting an attacker-chosen block in chain selection.

---

### Finding Description

The `PerasVote` data type is defined as:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound  :: PerasRoundNo
  , pvVoteBlock  :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- only a KeyHash, no signature
  }
``` [1](#0-0) 

There is no `VoteSignature` field. The production `validatePerasVote` implementation (the degenerate instance used for all blocks) is:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [2](#0-1) 

`lookupPerasVoteStake` only performs a `Map.lookup` on `pvVoteVoterId` in the stake distribution map — it checks **identity** (is this voter ID known?) but not **authorization** (did this voter actually sign this vote?). [3](#0-2) 

This is the direct analog to the external report: the code checks if the "address" matches a known entity (operator address check), but never verifies that the entity actually signed the message (missing `is_signer` check).

The `BlockSupportsPeras` class interface itself declares `validatePerasVote` as the required validation entry point, and the TODO comment explicitly acknowledges the implementation is incomplete: [4](#0-3) 

---

### Impact Explanation

When the Peras vote diffusion plumbing is completed (the `NodeToNode.hs` handler currently passes `pure (PerasVoteStakeDistr mempty)` as a temporary placeholder, explicitly noted as a TODO), a real stake distribution will be supplied. At that point, any unprivileged peer can:

1. Construct a `PerasVote` with `pvVoteVoterId` set to any known stake pool's `KeyHash` (all key hashes are public on-chain).
2. Send it over the Peras vote diffusion mini-protocol.
3. `processVotes` calls `validatePerasVote`, which passes because the voter ID is in the stake distribution.
4. The forged vote is stored in the `PerasVoteDB` / `ChainDB`.
5. If enough forged votes accumulate to reach quorum, `updatePerasRoundVoteStates` triggers `forgePerasCert`, producing a fraudulent `ValidatedPerasCert` that boosts an attacker-chosen block.

This constitutes a **bypass of Peras vote authorization** enabling unauthorized certificate acceptance and chain selection manipulation. [5](#0-4) [6](#0-5) [7](#0-6) 

---

### Likelihood Explanation

The attack path is fully wired end-to-end in production code. The only current barrier is the hardcoded `pure (PerasVoteStakeDistr mempty)` placeholder, which the codebase explicitly marks as a TODO to replace with real committee selection data. Once that substitution is made (a planned, necessary step for Peras to function), the vulnerability becomes immediately exploitable by any peer that can establish a node-to-node connection. No key material, admin access, or stake majority is required — only knowledge of any stake pool's public `KeyHash`, which is universally available on-chain. [8](#0-7) 

---

### Recommendation

1. **Add a `VoteSignature` field to `PerasVote`**: The data type must carry a cryptographic signature over `(pvVoteRound, pvVoteBlock)` produced with the stake pool's signing key.

2. **Verify the signature in `validatePerasVote`**: After confirming the voter ID is in the stake distribution (to retrieve the corresponding verification key), verify the signature using the pool's public key — analogous to how `implVerifyVote` in `WFALS.hs` and `EveryoneVotes.hs` call `verifyVoteSignature` / `checkVoteSignature`.

3. **Use the existing `CryptoSupportsVoteSigning` interface**: The `verifyVoteSignature` primitive is already defined and tested in `Ouroboros.Consensus.Committee.Crypto`. The `PerasVote` validation should use the same pattern. [9](#0-8) 

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Unprivileged peer
  → hPerasVoteDiffusionClient (NodeToNode.hs:391)
  → objectDiffusionInbound → processVotes (ObjectPool/PerasVote.hs:178)
  → validatePerasVote mkPerasParams stakeDistr craftedVote (line 141)
  → lookupPerasVoteStake craftedVote stakeDistr  ← only identity check, no sig
  → Right (ValidatedPerasVote craftedVote knownStake)
  → addVote → PerasVoteDB.addVote → updatePerasRoundVoteStates
  → (on quorum) forgePerasCert → AddedPerasVoteAndGeneratedNewCert fraudulentCert
  → ChainDB.addPerasVoteWithAsyncCertHandling stores fraudulent cert
  → chain selection boosted toward attacker-chosen block
```

**Crafted vote (no signing key needed):**
```haskell
craftedVote = PerasVote
  { pvVoteRound  = targetRound          -- any current round
  , pvVoteBlock  = attackerChosenBlock  -- block attacker wants boosted
  , pvVoteVoterId = knownPoolKeyHash    -- any public KeyHash from the ledger
  }
```

Since `PerasVote` has no signature field, there is nothing to forge — the attacker simply sets `pvVoteVoterId` to a known pool's key hash and the vote passes `validatePerasVote` unchanged. [1](#0-0) [2](#0-1) [10](#0-9)

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L398-410)
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
            controlMessageSTM
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L134-148)
```haskell
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L170-201)
```haskell
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L207-212)
```haskell
    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
        -- Added vote but did not generate a new certificate, either
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
