### Title
Hardcoded Peras Protocol Parameters in `mkPerasParams` Used in Production Vote Validation and Certificate Forging Enable Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs`)

---

### Summary

`mkPerasParams` in `Ouroboros.Consensus.Peras.Params` hardcodes all Peras protocol parameters — including the quorum stake threshold (`3/4`), the safety margin (`2/100`), and the certificate chain-selection boost weight (`15`) — as compile-time constants. These values are used directly in production code paths that validate inbound votes from unprivileged peers and forge certificates that influence chain selection. If the finalized Peras CIP or a specific deployment mandates different parameter values, the hardcoded constants will silently produce wrong quorum decisions and wrong chain-selection boosts, allowing an adversary to forge certificates with insufficient stake or to cause honest nodes to prefer a non-canonical chain.

---

### Finding Description

`mkPerasParams` is a zero-argument function that returns a fully hardcoded `PerasParams` bundle: [1](#0-0) 

The function's own comment acknowledges the values are tentative:

> "Many of these parameters are provided with sensible default values for now, waiting for a final decision (in a future stage of the project) on the exact values to use." [2](#0-1) 

The struct-level comment also notes:

> "NOTE: in the future this will depend on a concrete 'BlockConfig'." [3](#0-2) 

Despite being explicitly provisional, `mkPerasParams` is wired directly into two production code paths:

**1. ChainDB initialization** — the `PerasVoteDB` is initialized with the hardcoded config: [4](#0-3) 

**2. Inbound vote validation from peers** — both the direct-VoteDB writer and the ChainDB writer call `validatePerasVote mkPerasParams`: [5](#0-4) [6](#0-5) 

The security-critical parameters that are hardcoded are:

| Parameter | Hardcoded value | Security role |
|---|---|---|
| `perasQuorumStakeThreshold` | `3/4` | Minimum stake fraction to forge a certificate |
| `perasQuorumStakeThresholdSafetyMargin` | `2/100` | Safety margin on top of quorum |
| `perasWeight` | `15` | Chain-selection boost granted to a certified block |
| `perasIgnoranceRounds` | `487` | Governs VR-2A: when nodes may exit cooldown and resume voting |
| `perasCooldownRounds` | `1928` | Governs VR-2B: cooldown period length |

The quorum check that uses these values is `stakeAboveThreshold`: [7](#0-6) 

This is called by `votesReachQuorum`, which is the gate for certificate forging: [8](#0-7) 

The forged certificate carries the hardcoded `perasWeight` as its boost: [9](#0-8) 

The boost is then applied in chain selection via `totalWeightOfFragment`: [10](#0-9) 

---

### Impact Explanation

**Impact: High — chain selection bug enabling non-canonical chain preference.**

If the finalized Peras CIP or a specific network deployment requires a quorum threshold higher than the hardcoded `3/4 + 2/100 = 77%` (e.g., `4/5 = 80%`), an adversary controlling between 77% and 80% of the voting committee stake can send votes that satisfy the hardcoded threshold but not the actual protocol requirement. The node will:

1. Accept the votes as valid (wrong quorum check).
2. Forge a certificate for the adversary's block.
3. Apply a chain-selection boost of `perasWeight = 15` to that block.

A boost of 15 means the adversary's chain is treated as if it were 15 blocks longer than it actually is. Honest nodes will then prefer the adversary's shorter but "boosted" chain over a longer honest chain, constituting a chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain.

Conversely, if the actual protocol requires a lower threshold or a different weight, legitimate certificates may be rejected or the boost may be miscalibrated, breaking the Peras fast-finality guarantee and weakening chain security.

The `perasIgnoranceRounds` and `perasCooldownRounds` being wrong would additionally cause nodes to vote too early (weakening safety) or too late (weakening liveness) after a cooldown period, as these govern VR-2A and VR-2B: [11](#0-10) [12](#0-11) 

---

### Likelihood Explanation

**Likelihood: Medium.**

The code itself documents that the values are provisional and will change. The Peras CIP (CIP-0140) is still evolving, and the referenced GitHub issues (`tweag/cardano-peras#97`, `#88`, `#99`) confirm that the exact values are not yet finalized. Any deployment of Peras with parameters that differ from the hardcoded values — whether due to CIP revision, network-specific tuning, or governance — will silently use the wrong constants. There is no runtime mechanism to override them without a code change and redeployment.

---

### Recommendation

1. **Remove `mkPerasParams` from all production code paths.** The `pvdbaPerasCfg` field in `PerasVoteDbArgs` and the `validatePerasVote` call sites should receive `PerasParams` from the node's `BlockConfig` or genesis configuration, not from a hardcoded default.

2. **Add `PerasParams` to the genesis/configuration layer** (analogous to how `SecurityParam`, slot length, and epoch size are read from genesis files) so that parameters can be updated via governance or network configuration without a code change.

3. **Add a runtime invariant check** that validates `perasQuorumStakeThreshold > 1/2` and `perasWeight > 0` at node startup, to catch misconfiguration early.

4. **Until the above is done**, at minimum add a compile-time or startup assertion that the hardcoded values match the values specified in the deployed CIP version, and document clearly which CIP revision the constants correspond to.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Unprivileged peer
  → sends PerasVote messages via ObjectDiffusion mini-protocol
  → makePerasVotePoolWriterFromChainDB (PerasVote.hs:131)
  → processVotes (PerasVote.hs:178)
  → validatePerasVote mkPerasParams sd vote  ← hardcoded params used here
  → ChainDB.addPerasVoteWithAsyncCertHandling
  → PerasVoteDB.addVote
  → updatePerasRoundVoteStates
  → votesReachQuorum cfg votes
  → stakeAboveThreshold cfg totalVoteStake  ← checks against hardcoded 3/4 + 2/100
  → certificate forged with hardcoded perasWeight = 15
  → chain selection boost applied
```

**Concrete scenario:**

Suppose the finalized Peras CIP requires `perasQuorumStakeThreshold = 4/5` (80%). An adversary controls 78% of the voting committee stake. They send votes for their own block. The node checks `0.78 >= 0.75 + 0.02 = 0.77` — **true** under the hardcoded threshold — and forges a certificate boosting the adversary's block by 15. Honest nodes now treat the adversary's chain as having 15 extra blocks of weight and switch to it, even though it is shorter than the honest chain and the adversary never legitimately reached quorum. [7](#0-6) [13](#0-12) [6](#0-5) [4](#0-3)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L136-177)
```haskell
-- NOTE: in the future this will depend on a concrete 'BlockConfig'.
mkPerasParams :: PerasParams
mkPerasParams =
  -- Many of these parameters are provided with sensible default values for now,
  -- waiting for a final decision (in a future stage of the project) on the
  -- exact values to use. See https://github.com/tweag/cardano-peras/issues/97.
  --
  -- We set tentatively T_heal to 2B/asc = 600 slots, as the CIP suggests a
  -- bigO(B/asc) for that value so that sufficiently many blocks are produced to
  -- overcome an adversarially boosted block.
  --
  -- We also set tentatively perasCertArrivalThreshold (= X in the formal spec)
  -- to 30 slots (it must be strictly smaller than perasRoundLength)
  -- See https://github.com/tweag/cardano-peras/issues/88 and
  -- https://github.com/tweag/cardano-peras/issues/99 for more information on
  -- this parameter.
  --
  -- We also have T_cp = 129_600 and T_cq = 43_200 as per the design document
  PerasParams
    { -- ceil(T_heal + T_cq) / perasRoundLength) as per the design document
      perasIgnoranceRounds =
        PerasIgnoranceRounds 487
    , -- ceil(T_heal + T_cq + T_cp) / perasRoundLength) + 1 as per the design document
      perasCooldownRounds =
        PerasCooldownRounds 1928
    , -- must be between 30 and 900 as per the design document
      perasBlockMinSlots =
        PerasBlockMinSlots 90
    , -- equal to perasIgnoranceRounds as per the design document
      perasCertMaxRounds =
        PerasCertMaxRounds 487
    , perasCertArrivalThreshold =
        PerasCertArrivalThreshold 30
    , perasRoundLength =
        PerasRoundLength 90
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/Args.hs (L229-233)
```haskell
      , cdbPerasVoteDbArgs =
          PerasVoteDB.PerasVoteDbArgs
            { PerasVoteDB.pvdbaTracer = PerasVoteDB.pvdbaTracer (cdbPerasVoteDbArgs defArgs)
            , PerasVoteDB.pvdbaPerasCfg = mkPerasParams
            }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L110-113)
```haskell
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L140-142)
```haskell
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-174)
```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)

```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L242-270)
```haskell
votesReachQuorum ::
  StandardHash blk =>
  PerasCfg blk ->
  [ValidatedPerasVote blk] ->
  Maybe (ValidatedPerasVotesWithQuorum blk)
votesReachQuorum cfg votes =
  case votes of
    -- We need at least one vote to determine who these votes are for, so we
    -- can't vacuously reach a quorum, even if the quorum threshold is 0.
    [] -> Nothing
    -- If we have at least one vote, we must check that all votes are for the
    -- same target, and that their total stake of is above the quorum threshold.
    (v0 : vs)
      | not (allVotesMatchTarget v0 vs) ->
          Nothing
      | not votesHaveEnoughStake ->
          Nothing
      | otherwise ->
          Just
            ValidatedPerasVotesWithQuorum
              { vpvqTarget = getPerasVoteTarget v0
              , vpvqVotes = v0 :| vs
              , vpvqPerasCfg = cfg
              }
 where
  totalVoteStake =
    mconcat (vpvVoteStake <$> votes)
  votesHaveEnoughStake =
    stakeAboveThreshold cfg totalVoteStake
```

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/PerasVoteDB/Model.hs (L252-260)
```haskell
  freshCert =
    ValidatedPerasCert
      { vpcCert =
          PerasCert
            { pcCertRound = getPerasVoteRound vote
            , pcCertBoostedBlock = getPerasVoteBlock vote
            }
      , vpcCertBoost = perasWeight (params model)
      }
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Weight.hs (L307-317)
```haskell
totalWeightOfFragment ::
  forall blk h.
  (StandardHash blk, HasHeader h, HeaderHash blk ~ HeaderHash h) =>
  PerasWeightSnapshot blk ->
  AnchoredFragment h ->
  PerasWeight
totalWeightOfFragment weightSnap frag =
  weightLength <> weightBoost
 where
  weightLength = PerasWeight $ fromIntegral $ AF.length frag
  weightBoost = weightBoostOfFragment weightSnap frag
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L192-218)
```haskell
perasVR2A ::
  HasPerasCertRound cert =>
  PerasVotingView cert ->
  Pred PerasVotingRule
perasVR2A
  PerasVotingView
    { perasParams
    , currRoundNo
    , latestCertSeen
    } =
    VR2A := vr2a
   where
    vr2a =
      case latestCertSeen of
        -- We have seen a certificate ==> check its round number
        NotOrigin cert ->
          getPerasCertRound (lcsCert cert) + _R :<=: currRoundNo
        -- We have never seen a certificate ==> check if we are recovering from
        -- an initial cooldown after having initially failed to reach a quorum
        Origin ->
          _R :<=: currRoundNo

    _R =
      PerasRoundNo $
        unPerasIgnoranceRounds $
          perasIgnoranceRounds $
            perasParams
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Voting/Rules.hs (L225-265)
```haskell
perasVR2B ::
  HasPerasCertRound cert =>
  PerasVotingView cert ->
  Pred PerasVotingRule
perasVR2B
  PerasVotingView
    { perasParams
    , currRoundNo
    , latestCertOnChain
    } =
    VR2B c := vr2b
   where
    vr2b =
      case latestCertOnChain of
        -- There is a certificate on chain ==> we must check its round number
        NotOrigin cert ->
          -- The certificate comes from a round older than the current one
          (currRoundNo :>: getPerasCertRound (lcocCert cert))
            -- The certificate round is c⋅K rounds away from the current one
            :/\: ( (currRoundNo `rmod` _K)
                     :==: (getPerasCertRound (lcocCert cert) `rmod` _K)
                 )
        -- There is no certificate on chain ==> check if we are recovering
        -- from an initial cooldown after having initially failed to
        -- reach a quorum during bootstrapping.
        --
        -- NOTE: '_K - 1' here is treating the 'Origin' certificate as being
        -- from round -1.
        Origin ->
          currRoundNo `rmod` _K :==: _K - 1

    rmod = onPerasRoundNo mod
    rquot = onPerasRoundNo quot

    c = currRoundNo `rquot` _K

    _K =
      PerasRoundNo $
        unPerasCooldownRounds $
          perasCooldownRounds $
            perasParams
```
