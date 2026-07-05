### Title
Peras Certificate Accepted Without Cryptographic or Semantic Verification in Default `validatePerasCert` — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The default implementation of `validatePerasCert` in the `BlockSupportsPeras` class unconditionally accepts any Peras certificate without verifying its aggregate BLS signature, round number, or boosted block validity. This is the direct analog of the Chainlink `latestRoundData()` staleness bug: just as `getPrice()` consumes oracle data without checking `answeredInRound >= roundId` or `updatedAt`, `validatePerasCert` consumes a peer-supplied certificate without checking any of its validity fields. An unprivileged peer can send a crafted certificate that is accepted and stored, influencing Peras-based chain selection.

---

### Finding Description

In `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, the `BlockSupportsPeras` typeclass provides a default method implementation for `validatePerasCert`:

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

The function takes a raw `PerasCert` from a peer and immediately wraps it in `ValidatedPerasCert` — the type that signals to the rest of the system that the certificate has been validated. No checks are performed:

- **No aggregate BLS signature verification** — the `pcSignature` field of the certificate is never passed to `verifyAggregateVoteSignature` or any equivalent.
- **No round number validation** — `pcCertRound` is not checked against the current chain state or any window constraint.
- **No boosted block validation** — `pcCertBoostedBlock` is not checked to be a known, reachable block.

The same pattern applies to `validatePerasVote`, which only checks stake lookup but skips cryptographic signature verification:

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

The `ValidatedPerasCert` wrapper is the trust boundary: downstream code in `PerasCertDB`, `PerasVoteDB`, and chain selection (`preferAnchoredCandidate` with `emptyPerasWeightSnapshot`) all treat a `ValidatedPerasCert` as having passed all required checks. Because the default implementation grants this status unconditionally, the trust boundary is hollow.

The `BlockSupportsPeras` class is defined in production source (not a test file), and the explicit TODO comment with a linked issue (`tweag/cardano-peras#120`) confirms this is the current live default, not a stub confined to tests.

---

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate/vote verification enabling unauthorized certificate acceptance.**

A crafted certificate accepted via the default `validatePerasCert` is stored in `PerasCertDB` and used by the Peras chain selection logic to boost a block's weight. Because Peras certificates add a `PerasWeight` boost to a block's chain density score, an attacker who can inject accepted certificates for an arbitrary block can cause an honest node to prefer a non-canonical or adversarially-chosen chain over the honest chain. This directly undermines the chain selection safety guarantee that Peras is designed to strengthen.

The `validatePerasVote` gap compounds this: votes that reach quorum in `PerasVoteDB` trigger certificate forging via `updatePerasRoundVoteStates`. If vote signatures are not verified, an attacker can forge quorum from a single connection.

---

### Likelihood Explanation

**Likelihood: High** (conditional on Peras being active on the node).

The entry path requires only a network connection to the target node. Peras votes and certificates are exchanged over the existing mini-protocol infrastructure. No privileged access, key material, or stake majority is required. The attacker constructs a `PerasCert` with an arbitrary `pcCertRound`, `pcCertBoostedBlock`, and a zeroed or random `pcSignature`, and submits it. The default `validatePerasCert` accepts it unconditionally. The only precondition is that Peras is enabled on the target node.

---

### Recommendation

Replace the default stub with a full implementation that:

1. **Verifies the aggregate BLS signature** by calling `verifyAggregateVoteSignature` (as done in `implVerifyCert` in `EveryoneVotes` and `WFALS`) against the committee's aggregate public key derived from the current ledger state.
2. **Validates `pcCertRound`** against the current Peras round and the certificate expiry window (`perasCertMaxRounds`).
3. **Validates `pcCertBoostedBlock`** as a point reachable within the current volatile chain.

Until this is implemented, the `validatePerasCert` default should either `throwError` unconditionally (forcing all block types to provide a real implementation) or be removed from the default method set entirely.

---

### Proof of Concept

1. Connect to a Cardano node with Peras enabled.
2. Construct a `PerasCert` (or its wire-format equivalent) with:
   - `pcCertRound` set to the current Peras round number (obtainable from chain tip metadata),
   - `pcCertBoostedBlock` set to any block point on an adversarial fork,
   - `pcSignature` set to a zeroed or random aggregate BLS signature.
3. Submit the certificate via the Peras certificate mini-protocol.
4. The node calls `validatePerasCert params cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` without inspecting the signature.
5. The certificate is stored in `PerasCertDB` and the adversarial block receives a `PerasWeight` boost in chain selection, causing the node to prefer the adversarial fork over the honest chain. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L338-349)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L202-211)
```haskell
  tryAddVote pvds voteId = do
    let pvsVoteIds' = Set.insert voteId (pvdsVoteIds pvds)
        pvsLastTicketNo' = succ (pvdsLastTicketNo pvds)
        pvsVotesByTicket' = Map.insert pvsLastTicketNo' vote (pvdsVotesByTicket pvds)

    (addPerasVoteRes, pvsRoundVoteStates') <-
      case updatePerasRoundVoteStates vote perasCfg (pvdsRoundVoteStates pvds) of
        -- Added vote and reached a quorum, forging a new certificate
        Right (VoteGeneratedNewCert cert, pvsRoundVoteStates') ->
          pure (AddedPerasVoteAndGeneratedNewCert cert, pvsRoundVoteStates')
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L293-337)
```haskell
implVerifyCert ::
  forall crypto.
  CryptoSupportsAggregateVoteSigning crypto =>
  VotingCommittee crypto EveryoneVotes ->
  Cert crypto EveryoneVotes ->
  Either
    (VotingCommitteeError crypto EveryoneVotes)
    (NE [EligibilityWitness crypto EveryoneVotes])
implVerifyCert committee = \case
  EveryoneVotesCert electionId candidate voters aggSig -> do
    -- Traverse the list of voters in ascending seat index order, collecting:
    -- 1. their membership status
    -- 2. their vote verification keys (to verify the aggregate vote signature)
    (members, voteVerificationKeys) <-
      fmap munzip . flip traverse (NESet.toAscList voters) $ \case
        seatIndex
          | Just (_, voterPublicKey, voterStake, _) <-
              getCandidateIfSeatWithinBounds seatIndex (extWFAStakeDistr committee) -> do
              let voterVerificationKey =
                    getVoteVerificationKey (Proxy @crypto) voterPublicKey
              case nonZero voterStake of
                Nothing ->
                  Left (PoolHasNoStake seatIndex)
                Just nonZeroVoterStake ->
                  pure
                    ( EveryoneVotesMember
                        seatIndex
                        nonZeroVoterStake
                    , voterVerificationKey
                    )
          | otherwise ->
              Left (MissingSeatIndex seatIndex)
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $ do
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ChainSync/Client.hs (L1838-1845)
```haskell
      shouldSwitch $
        preferAnchoredCandidate
          (configBlock cfg)
          -- TODO: remove this entire check, see https://github.com/tweag/cardano-peras/issues/64
          emptyPerasWeightSnapshot
          ourFrag
          theirFrag =
        pure ()
```
