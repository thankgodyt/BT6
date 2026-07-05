### Title
Peras Certificate and Vote Validation Bypass via Incomplete Cryptographic Checks — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default implementations of `validatePerasCert` and `validatePerasVote` in the `BlockSupportsPeras` typeclass perform critically incomplete validation. `validatePerasCert` accepts every certificate unconditionally. `validatePerasVote` checks only that the voter ID exists in the stake distribution but never verifies the vote signature. This is the direct consensus analog of the `transferFrom()` blacklisting bypass: the "from" party (the actual cryptographic author of the vote or certificate) is never authenticated, so any unprivileged peer can inject forged votes and certificates attributed to legitimate pools.

---

### Finding Description

The `BlockSupportsPeras` typeclass in `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` provides default implementations for both `validatePerasCert` and `validatePerasVote`.

**`validatePerasCert` — zero validation:**

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

Every certificate, regardless of content or cryptographic validity, is unconditionally accepted and assigned a full `perasWeight` boost. [1](#0-0) 

**`validatePerasVote` — membership check only, no signature verification:**

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

The only check performed is `lookupPerasVoteStake`: does the `pvVoteVoterId` field of the incoming vote appear in the stake distribution map? No signature over the vote content is verified, no round-number bounds are checked, and no VRF eligibility proof is validated. [2](#0-1) 

These defaults are the implementations actually invoked in the production inbound-vote pipeline. Both `makePerasVotePoolWriterFromChainDB` and `makePerasVotePoolWriterFromVoteDB` call `validatePerasVote mkPerasParams sd vote` directly:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [3](#0-2) [4](#0-3) 

The `processVotes` function that drives this pipeline accepts the entire batch if all votes pass `validatePerasVote`, then stores them via `addVote`: [5](#0-4) 

The `PerasVote` wire type carries a `pvVoteVoterId` (a `KeyHash StakePool`) that is attacker-controlled and is the sole field consulted during validation: [6](#0-5) 

The `lookupPerasVoteStake` helper simply performs a `Map.lookup` on that field — no cryptographic material is examined: [7](#0-6) 

**Analog mapping to the `transferFrom()` bug:**

| `transferFrom()` | Peras vote/cert validation |
|---|---|
| Check `msg.sender` (spender) | Check that the vote arrives over a connected peer session |
| Check `to` (recipient) | Check that the target block hash is syntactically present |
| **Missing: check `from` (token owner)** | **Missing: verify the cryptographic signature of the actual voter** |

In both cases the "source" party — the entity whose authority is being exercised — is never authenticated.

---

### Impact Explanation

**Critical — Bypass of Peras certificate/vote checks enabling unauthorized certificate acceptance and chain-selection manipulation.**

Accepted Peras certificates carry a `perasWeight` boost that directly influences chain selection via `ValidatedPerasCert.vpcCertBoost`: [8](#0-7) 

An attacker who can inject forged certificates (trivially, since `validatePerasCert` returns `Right` for everything) can make an honest node assign a Peras boost to an arbitrary block, causing it to prefer a non-canonical or adversary-controlled chain. An attacker who can inject forged votes attributed to high-stake pools can accumulate quorum stake without possessing any pool signing key, then trigger certificate forging internally: [9](#0-8) 

This satisfies the "High/Critical — chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact criterion.

---

### Likelihood Explanation

**High.** The attack requires only:
1. A TCP connection to the target node's Peras vote mini-protocol endpoint (unprivileged peer).
2. Knowledge of any pool ID present in the current stake distribution (publicly available on-chain).
3. Crafting a `PerasVote` or `PerasCert` CBOR message with that pool ID and an arbitrary vote target.

No key material, stake majority, or operator access is needed. The stake distribution is public, the wire format is specified, and the validation gate is a single map lookup.

---

### Recommendation

1. **`validatePerasCert`**: Implement full certificate validation — verify the aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregated public keys of the claimed voters, and confirm that the claimed voter set reaches quorum under the current committee.

2. **`validatePerasVote`**: After the stake-distribution membership check, verify the vote signature using the pool's registered BLS vote-verification key (analogous to the `notBlacklisted(from)` fix: add the missing check on the "from" party). For non-persistent members, also verify the VRF eligibility proof. The full logic already exists in `implVerifyVote` in `Ouroboros.Consensus.Committee.WFALS` and `Ouroboros.Consensus.Committee.EveryoneVotes` — the default implementation should delegate to the appropriate committee scheme rather than stub out. [10](#0-9) [11](#0-10) 

3. Remove or gate the stub defaults behind a compile-time flag so they cannot silently become the production path.

---

### Proof of Concept

**Forged vote injection (bypasses `validatePerasVote`):**

1. Attacker connects to a node's Peras vote object-diffusion mini-protocol.
2. Attacker reads the current `PerasVoteStakeDistr` (publicly derivable from the ledger state) and picks any pool ID `P` with high stake.
3. Attacker crafts a CBOR-encoded `PerasVote` with `pvVoteVoterId = P`, `pvVoteRound = currentRound`, `pvVoteBlock = <attacker-chosen block hash>`, and an arbitrary/empty signature field.
4. Attacker sends the vote to the node via `processVotes`.
5. `validatePerasVote` calls `lookupPerasVoteStake` → finds `P` in the map → returns `Right ValidatedPerasVote{vpvVoteStake = <P's stake>}`. No signature check occurs.
6. The vote is stored with full stake weight. If the attacker repeats for enough pools to exceed the quorum threshold, `updatePerasRoundVoteStates` triggers `VoteGeneratedNewCert` and a forged certificate is stored.

**Forged certificate injection (bypasses `validatePerasCert`):**

1. Attacker connects and sends a CBOR-encoded `PerasCert` with `pcCertBoostedBlock = <attacker-chosen block>` and `pcCertRound = currentRound`.
2. `validatePerasCert` returns `Right ValidatedPerasCert{vpcCertBoost = perasWeight params}` unconditionally.
3. The node's chain selection now treats the attacker-chosen block as having a full Peras boost, potentially switching to a non-canonical chain. [12](#0-11)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-210)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L331-334)
```haskell
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
    }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-111)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L141-141)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L178-200)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-210)
```haskell
  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L327-392)
```haskell
implVerifyVote ::
  forall crypto.
  ( CryptoSupportsVoteSigning crypto
  , CryptoSupportsVRF crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Vote crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (EligibilityWitness crypto WFALS)
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
  WFALSNonPersistentVote seatIndex electionId message vrfOutput sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee)
    , not (isPersistentMember seatIndex committee) -> do
        let voterVoteVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVoteVerificationKey
            electionId
            message
            sig
        let voterVRFVerificationKey =
              getVRFVerificationKey (Proxy @crypto) voterPublicKey
        let vrfContext =
              VRFVerifyContext voterVRFVerificationKey vrfOutput
        void $ bimap InvalidVoterEligibilityProof id $ do
          evalVRF
            vrfContext
            ( mkVRFElectionInput
                @crypto
                (epochNonce committee)
                electionId
            )
        let numSeats =
              localSortitionNumSeats
                (nonPersistentCommitteeSize committee)
                (totalNonPersistentStake committee)
                voterStake
                (normalizeVRFOutput vrfOutput)
        case nonZero numSeats of
          Nothing ->
            Left (ZeroNonPersistentSeats seatIndex)
          Just nonZeroNumSeats ->
            pure $
              WFALSNonPersistentMember
                seatIndex
                voterStake
                vrfOutput
                nonZeroNumSeats
    | otherwise ->
        Left (NotANonPersistentMember seatIndex)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L211-232)
```haskell
implVerifyVote committee = \case
  EveryoneVotesVote seatIndex electionId candidate sig
    | Just (_, voterPublicKey, voterStake, _) <-
        getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
        let voterVerificationKey =
              getVoteVerificationKey (Proxy @crypto) voterPublicKey
        bimap InvalidVoteSignature id $ do
          verifyVoteSignature
            voterVerificationKey
            electionId
            candidate
            sig
        case nonZero voterStake of
          Nothing ->
            Left (PoolHasNoStake seatIndex)
          Just nonZeroVoterStake ->
            pure $
              EveryoneVotesMember
                seatIndex
                nonZeroVoterStake
    | otherwise ->
        Left (MissingSeatIndex seatIndex)
```
