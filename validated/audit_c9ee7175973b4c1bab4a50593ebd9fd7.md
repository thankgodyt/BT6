### Title
Unconditional Certificate Acceptance in Degenerate `validatePerasCert` Instance Enables Fake Peras Weight Boost via Network - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance, which is the only active instance for all block types in the repository, implements `validatePerasCert` to unconditionally return `Right` for every certificate it receives, with no cryptographic signature check whatsoever. Because the `PerasCertDiffusion` mini-protocol is fully wired up in the node-to-node handler stack, any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block as `pcCertBoostedBlock`. The node will accept it as a `ValidatedPerasCert`, add it to the ChainDB, and apply the full Peras weight boost to that block during chain selection, potentially causing the node to prefer a non-canonical chain.

---

### Finding Description

**Root cause — `validatePerasCert` accepts all certificates unconditionally:** [1](#0-0) 

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

This is the **universal degenerate instance** that applies to every block type: [2](#0-1) 

The `PerasCert` data type in this instance carries only a round number and a block point — no signature field exists: [3](#0-2) 

There is therefore nothing to verify even if the function attempted to. Every certificate received from the network is wrapped into a `ValidatedPerasCert` carrying the full `perasWeight params` boost and returned as `Right`.

**Attacker-controlled entry path — `PerasCertDiffusion` mini-protocol:**

The `hPerasCertDiffusionClient` handler in the node-to-node handler stack is fully wired up and calls `makePerasCertPoolWriterFromChainDB`, which validates incoming certificates before adding them to the ChainDB: [4](#0-3) 

The `addPerasCertAsync` ChainDB API entry point accepts a `ValidatedPerasCert` and triggers chain selection re-evaluation: [5](#0-4) 

Because `validatePerasCert` always returns `Right`, every certificate sent by any peer becomes a `ValidatedPerasCert` and is stored in the ChainDB, where it contributes a weight boost to the named block.

**Chain selection impact — `getPerasWeightSnapshot`:**

The ChainDB exposes a `PerasWeightSnapshot` representing Peras weight boosts for all blocks newer than the immutable tip, which is consumed by chain selection: [6](#0-5) 

An injected fake certificate boosts the attacker's chosen block by `perasWeight params`, which can be enough to make the node's chain selection prefer a non-canonical fork.

**Analogous pattern in `validatePerasVote`:**

The same degenerate instance also omits signature verification in `validatePerasVote`, checking only stake-distribution membership: [7](#0-6) 

The production vote-diffusion handler currently passes an empty stake distribution (`PerasVoteStakeDistr mempty`), so all votes are rejected today: [8](#0-7) 

However, once the actual stake distribution is plumbed in (as the TODO comment anticipates), any peer will be able to forge votes for any voter ID in the distribution without providing a valid signature, because `validatePerasVote` performs no cryptographic check.

**Contrast with the properly implemented committee-level verification:**

The `WFALS` and `EveryoneVotes` committee implementations do perform full signature and VRF verification in `implVerifyVote` and `implVerifyCert`: [9](#0-8) [10](#0-9) 

These committee-level checks are never reached for the degenerate `BlockSupportsPeras` instance because `validatePerasCert` short-circuits before any committee logic is invoked.

---

### Impact Explanation

**Severity: High** — Chain selection manipulation via certificate verification bypass.

An unprivileged peer connected via the `PerasCertDiffusion` mini-protocol can send a `PerasCert` naming any block as `pcCertBoostedBlock`. The node accepts it unconditionally, stores it, and applies the full Peras weight boost to that block. If the boosted block is on a minority fork, the node's chain selection may switch to that fork, causing the node to diverge from the canonical chain. This directly violates the Peras protocol's security guarantee that only blocks certified by a legitimate quorum of stake-weighted committee members receive a weight boost.

---

### Likelihood Explanation

**High.** The `PerasCertDiffusion` mini-protocol is fully wired up and reachable by any peer that establishes a node-to-node connection. No special privileges, keys, or stake are required. The attacker only needs to connect and send a well-formed CBOR-encoded `PerasCert` message. The degenerate instance is the only active `BlockSupportsPeras` instance in the repository.

---

### Recommendation

1. **Immediate**: Gate the `PerasCertDiffusion` inbound handler so that it rejects all certificates until a proper `validatePerasCert` implementation with cryptographic signature verification is in place, rather than using the unconditional `Right` placeholder.
2. **Short-term**: Implement `validatePerasCert` to call `verifyCert` from the `CryptoSupportsVotingCommittee` typeclass (as already implemented in `WFALS.implVerifyCert` and `EveryoneVotes.implVerifyCert`) before producing a `ValidatedPerasCert`.
3. **Parallel**: Apply the same fix to `validatePerasVote` before the actual stake distribution is plumbed into the vote-diffusion handler, to prevent the analogous vote-forgery attack from becoming exploitable at that point.

---

### Proof of Concept

1. Attacker establishes a node-to-node connection to an honest Cardano node running this code.
2. Attacker sends a `PerasCertDiffusion` message containing a `PerasCert` with:
   - `pcCertRound` = any round number
   - `pcCertBoostedBlock` = the `Point` of a block on a minority fork the attacker wants to promote
3. The node's `hPerasCertDiffusionClient` handler calls `makePerasCertPoolWriterFromChainDB`, which calls `validatePerasCert` on the received cert.
4. `validatePerasCert` (degenerate instance, lines 353–358 of `SupportsPeras.hs`) returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = perasWeight params}` without any signature check.
5. The `ValidatedPerasCert` is passed to `ChainDB.addPerasCertAsync`.
6. The ChainDB stores the certificate and updates the `PerasWeightSnapshot`, adding `perasWeight params` to the minority-fork block's chain weight.
7. Chain selection re-evaluates and, if the boosted weight exceeds the canonical chain's weight, the node switches to the attacker's preferred fork.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L430-432)
```haskell
  , getPerasWeightSnapshot :: STM m (WithFingerprint (PerasWeightSnapshot blk))
  -- ^ Get the 'PerasWeightSnapshot', representing the Peras weight boosts for
  -- all blocks newer than the current immutable tip.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
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
