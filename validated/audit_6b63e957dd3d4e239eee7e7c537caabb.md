### Title
Missing Cryptographic Signature Verification in `validatePerasCert` Allows Unauthorized Peras Certificate Acceptance and Chain Selection Manipulation - (File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs)

---

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural validation. This is the production instance wired into the `PerasCertDiffusion` mini-protocol handler for all block types. Any unprivileged peer can send a crafted `PerasCert` claiming to boost an arbitrary block, and the node will accept it, store it, and apply its weight boost during chain selection — without ever verifying that the certificate was legitimately produced by a quorum of eligible committee members.

---

### Finding Description

**Root cause — identity check without authorization check (exact analog of the Phantasia pattern):**

The `validatePerasCert` function in the default `BlockSupportsPeras` instance is:

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

It accepts every certificate unconditionally and assigns it the full protocol boost weight. No signature, no quorum proof, no committee membership check is performed. [1](#0-0) 

This is the **only** `BlockSupportsPeras` instance in the codebase. The comment "degenerate instance for all blks to get things to compile" confirms it is a placeholder that has been wired into production paths without a concrete override. [2](#0-1) 

**Attacker-controlled entry path:**

`makePerasCertPoolWriterFromChainDB` is wired directly into the `hPerasCertDiffusionClient` handler in `NodeToNode.hs`. It passes `validatePerasCert mkPerasParams` as the validation function to `processCerts`:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { ...
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
``` [3](#0-2) 

`processCerts` calls `validateCert` on each inbound certificate. Because `validatePerasCert` always returns `Right`, every certificate passes. Valid certificates are then timestamped and added to the ChainDB via `addPerasCertAsync`: [4](#0-3) 

The `NodeToNode.hs` wiring confirms this is the live production handler for inbound Peras certificate diffusion: [5](#0-4) 

**Secondary issue — `validatePerasVote` checks identity but not authorization:**

`validatePerasVote` only checks that the `pvVoteVoterId` is present in the stake distribution, but the `PerasVote` data type carries no cryptographic signature field at all:

```haskell
data PerasVote blk = PerasVote
  { pvVoteRound   :: PerasRoundNo
  , pvVoteBlock   :: Point blk
  , pvVoteVoterId :: PerasVoterId   -- no signature
  }
``` [6](#0-5) 

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [7](#0-6) 

This is the direct structural analog of the Phantasia bug: the code checks that the claimed identity (`pvVoteVoterId`) exists in a registry (the stake distribution), but never verifies that the sender actually controls that identity (no signature). However, the production `NodeToNode.hs` wiring currently passes an empty stake distribution (`pure (PerasVoteStakeDistr mempty)`), which causes all votes to be rejected in practice — partially mitigating this specific path for now. [8](#0-7) 

---

### Impact Explanation

**Impact: High — Chain selection manipulation via unauthorized Peras certificate acceptance.**

A Peras certificate boosts the chain-selection weight of the block it references (`vpcCertBoost = perasWeight params`). By injecting a crafted certificate that references a block on a minority fork, an unprivileged peer causes the receiving node to assign extra weight to that fork. If the boost is large enough relative to the honest chain's length advantage, the node will switch to the attacker-chosen fork. This violates the chain-selection security assumption that only legitimately quorum-certified blocks receive a weight boost.

The `validatePerasCert` path is not mitigated by any other guard: the certificate is accepted, stored, and applied to chain selection without any further check.

---

### Likelihood Explanation

**Likelihood: High.**

The attack requires only a standard peer-to-peer connection via the `PerasCertDiffusion` mini-protocol. No keys, no stake, no privileged access are needed. The attacker constructs a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock`, sends it, and the node accepts it unconditionally. The code path is fully wired in production (`NodeToNode.hs` → `makePerasCertPoolWriterFromChainDB` → `processCerts` → `validatePerasCert`).

---

### Recommendation

1. **`validatePerasCert`**: Implement actual certificate validation — verify the aggregate BLS/committee signature over the claimed `(electionId, candidate)` pair against the registered committee keys for the relevant epoch. Until a real implementation exists, the function must not return `Right` unconditionally; it should return `Left` (reject all) as a safe default.

2. **`validatePerasVote`**: Add a cryptographic signature field to `PerasVote` and verify it in `validatePerasVote` against the public key registered for `pvVoteVoterId` in the stake distribution, analogous to how `implVerifyVote` in `EveryoneVotes.hs` calls `verifyVoteSignature`. [9](#0-8) 

3. Track the linked issue (`cardano-peras/issues/120`) to ensure these TODOs are resolved before Peras certificate diffusion is enabled on a network with real stake.

---

### Proof of Concept

```
Attacker node  ──[PerasCertDiffusion]──►  Honest node
                                              │
                                         processCerts
                                              │
                                    validatePerasCert mkPerasParams
                                    (always returns Right)
                                              │
                                    addPerasCertAsync chainDB
                                              │
                                    PerasWeightSnapshot updated:
                                    attacker-chosen block gets
                                    +perasWeight boost
                                              │
                                    Chain selection re-runs:
                                    node may switch to
                                    attacker-chosen fork
```

1. Attacker opens a connection to an honest node and speaks the `PerasCertDiffusion` protocol.
2. Attacker sends `PerasCert { pcCertRound = R, pcCertBoostedBlock = <minority fork tip> }`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }`.
4. `addPerasCertAsync` stores the certificate; the `PerasWeightSnapshot` is updated.
5. Chain selection re-evaluates: the minority fork now has extra weight equal to `perasWeight params`.
6. If the boost exceeds the honest chain's length advantage, the node switches forks.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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
