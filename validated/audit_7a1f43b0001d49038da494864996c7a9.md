### Title
Peras Certificate Verification Bypass: `validatePerasCert` Unconditionally Accepts Any Inbound Certificate Without Cryptographic Checks - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` — it accepts every inbound Peras certificate from every peer without performing any cryptographic verification. Any unprivileged peer can inject a crafted `PerasCert` that claims to boost an arbitrary block, and the node will store it as valid and apply its chain-selection weight boost.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the gate that must authenticate a Peras certificate before it is stored and used to influence chain selection. The degenerate instance that covers all block types (including production Cardano blocks) implements this gate as a stub that always succeeds:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  ...
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

This stub is wired directly into the production inbound-certificate processing pipeline. `makePerasCertPoolWriterFromChainDB` (and its `CertDB` variant) call `processCerts` with `validatePerasCert mkPerasParams` as the validation callback:

```haskell
processCerts
  systemTime
  (ChainDB.getPerasCertIds chainDB)
  (validatePerasCert mkPerasParams)   -- always returns Right
  (void . ChainDB.addPerasCertAsync chainDB)
  certs
``` [2](#0-1) 

`processCerts` partitions the results of `validateCert` and only throws on `Left`; since `validatePerasCert` never produces `Left`, every certificate in every inbound batch is accepted and forwarded to `addCert`: [3](#0-2) 

The same pattern applies to `validatePerasVote`: the degenerate instance only checks whether the voter ID appears in the stake distribution map — it performs no cryptographic signature verification over the vote content, because the stub `PerasVote` data type carries no signature field at all: [4](#0-3) 

The `BlockSupportsPeras` class contract requires that `validatePerasCert` authenticate the aggregate BLS signature over the certificate's boosted-block claim and verify committee eligibility. The `EveryoneVotes` and `WFALS` committee implementations in the same repository demonstrate what real verification looks like — they call `verifyAggregateVoteSignature` and check seat-index bounds: [5](#0-4) 

None of that logic is invoked by the degenerate instance used in production.

---

### Impact Explanation

Peras certificates carry a `vpcCertBoost` weight that is added to a block's chain-selection score. A node that stores a forged certificate for a non-canonical block will treat that block as heavier than it actually is, potentially switching away from the honest chain. Because `validatePerasCert` never rejects, an attacker who can reach the Peras certificate diffusion mini-protocol endpoint can:

1. Forge a `PerasCert` claiming to boost any block at any round number.
2. Have it stored unconditionally in the `PerasCertDB` / `ChainDB`.
3. Cause the victim node to apply an illegitimate weight boost during chain selection, preferring a non-canonical or adversarially-controlled chain.

This is a **bypass of Peras certificate/vote authorization** that lets an unprivileged peer make an honest node prefer a non-canonical chain — matching the "High" impact tier: *bypass of certificate checks that enables unauthorized certificate acceptance* and *chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain*.

---

### Likelihood Explanation

The vulnerability is reachable by any peer that can establish a connection and send Peras certificate objects via the object-diffusion mini-protocol. No special privileges, keys, or stake are required. The code is in the production codebase and the `makePerasCertPoolWriterFromChainDB` path is the intended production wiring. The only mitigating factor is that Peras is not yet activated on mainnet; however, the code is present and the pipeline is live in the codebase being audited.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that:
1. Verifies the aggregate BLS signature over `(roundNo, boostedBlock)` against the aggregate verification key derived from the committee members listed in the certificate.
2. Checks that each listed voter is a registered committee member with non-zero stake for the relevant epoch.
3. Confirms the certificate's round number falls within the current or recent Peras window.

Until the real implementation is in place, the degenerate instance should return `Left PerasValidationErr` (reject all) rather than `Right` (accept all), so that the stub fails closed rather than open.

---

### Proof of Concept

```
Attacker (unprivileged peer)
  │
  │  Peras cert diffusion mini-protocol
  │  sends: PerasCert { pcCertRound = R, pcCertBoostedBlock = <adversarial block> }
  ▼
makePerasCertPoolWriterFromChainDB
  └─► processCerts ... (validatePerasCert mkPerasParams) ...
        └─► validatePerasCert mkPerasParams cert
              = Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight mkPerasParams }
                                          ^^^ no signature check, no committee check
        └─► addCert (WithArrivalTime now validatedCert)
              └─► ChainDB.addPerasCertAsync chainDB
                    └─► cert stored; chain selection applies weight boost to adversarial block
```

The attacker needs only a network connection. No keys, no stake, no prior authentication. The forged certificate is indistinguishable from a legitimate one because `validatePerasCert` performs zero checks. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L96-137)
```haskell
makePerasCertPoolWriterFromCertDB systemTime perasCertDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
    , opwHasObject = do
        certIds <- PerasCertDB.getCertIds perasCertDB
        pure $ \roundNo -> Set.member roundNo certIds
    }

-- | Create a pool writer from the 'ChainDB'. This properly handles any needed
-- chain selection side-effects.
makePerasCertPoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  ChainDB m blk ->
  ObjectPoolWriter PerasRoundNo (PerasCert blk) m
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L164-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/EveryoneVotes.hs (L301-337)
```haskell
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
