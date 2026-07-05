### Title
Peras Vote and Certificate Signature Verification Bypass via Stub `BlockSupportsPeras` Instance - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The production inbound handlers for Peras votes and certificates received from peers invoke `validatePerasVote` and `validatePerasCert` through a universal stub `BlockSupportsPeras` instance that performs no cryptographic signature verification whatsoever. An unprivileged peer can craft and submit arbitrary Peras certificates for any round and any block, which will be unconditionally accepted and applied to chain selection, allowing the peer to boost a non-canonical chain by the full Peras weight.

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasVote` and `validatePerasCert` as the mandatory verification gates for inbound Peras votes and certificates. A universal instance is provided for all `StandardHash blk` types with an explicit `TODO` comment:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

Within this instance, `validatePerasCert` unconditionally returns `Right` for every certificate it receives, performing zero validation:

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
``` [2](#0-1) 

Similarly, `validatePerasVote` only checks that the voter's key appears in the stake distribution map, but never verifies the BLS vote signature, the round number binding, or any epoch-nonce context:

```haskell
  validatePerasVote _params stakeDistr vote
    | Just stake <- lookupPerasVoteStake vote stakeDistr =
        Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
    | otherwise =
        Left PerasValidationErr
``` [3](#0-2) 

The stub `PerasVote blk` data type in this instance carries no signature field at all (`pvVoteRound`, `pvVoteBlock`, `pvVoteVoterId` only), so there is nothing to cryptographically bind the vote to a specific round or epoch nonce: [4](#0-3) 

These stub implementations are directly invoked by the production inbound miniprotocol handlers. `makePerasVotePoolWriterFromChainDB` calls `validatePerasVote mkPerasParams sd vote` for every vote received from a peer: [5](#0-4) 

`makePerasCertPoolWriterFromChainDB` calls `validatePerasCert mkPerasParams` for every certificate received from a peer: [6](#0-5) 

The `processCerts` function then timestamps and stores every certificate that passes this non-validation: [7](#0-6) 

The analog to the external report's vulnerability class is direct: the external report describes a nonce used as a salt (not a sequential counter) so that old signatures can be replayed across different contexts. Here, the situation is more severe — there is no nonce/round binding check and no signature verification at all. A vote or certificate signed for round R with epoch nonce N can be replayed for any round with any epoch nonce, because the `PerasVote blk` type carries no signature and `validatePerasCert` performs no checks. The `hashVoteSignature` function in `BLS.hs` does bind round number and boosted block into the BLS signature hash (providing the correct replay protection design), but this protection is entirely bypassed because the production code path never calls it: [8](#0-7) 

### Impact Explanation

**Impact: Critical.** An unprivileged peer can submit a crafted `PerasCert` for any `pcCertRound` and any `pcCertBoostedBlock` (including a block on a non-canonical fork). The certificate will be unconditionally accepted and stored. The Peras chain selection logic then applies a `perasWeight = 15` boost to the boosted block's chain. This allows a peer with no stake and no valid BLS key to make an honest node prefer a non-canonical or adversarially-chosen chain, constituting a bypass of Peras certificate/vote signature validation that enables unauthorized certificate acceptance and chain selection manipulation.

### Likelihood Explanation

**Likelihood: High.** The attack requires only a TCP connection to a node running the Peras object diffusion miniprotocol. No keys, stake, or privileged access are needed. The attacker simply sends a well-formed CBOR-encoded `PerasCert` with a chosen round number and block point. The code path is unconditional and has no guards beyond a duplicate-round check.

### Recommendation

1. The universal stub `BlockSupportsPeras` instance must not be used in production inbound handlers. The `makePerasVotePoolWriterFromChainDB` and `makePerasCertPoolWriterFromChainDB` functions must be wired to a concrete, cryptographically complete instance (such as the WFALS-based `implVerifyVote` in `Ouroboros.Consensus.Committee.WFALS`) before the Peras miniprotocol is enabled on any network.
2. `validatePerasCert` must verify the aggregate BLS signature over the quorum of votes that produced the certificate, bound to the specific `pcCertRound` and `pcCertBoostedBlock`.
3. `validatePerasVote` must verify the individual BLS vote signature using `verifyVoteSignature` (already implemented in `PerasBLSCrypto`), binding the round number and epoch nonce as done in `hashVoteSignature` and `hashVRFInput`.
4. The `PerasVote blk` data type in the production instance must include a `pvSignature` field (as already done in `Ouroboros.Consensus.Peras.Vote.V1.PerasVote`).

### Proof of Concept

On a private testnet with the Peras object diffusion miniprotocol enabled:

1. Connect to a target node as a peer.
2. Construct a CBOR-encoded `PerasCert` with `pcCertRound = N` (any round) and `pcCertBoostedBlock = Point` pointing to a block on a minority fork.
3. Send it via the cert diffusion miniprotocol.
4. The target node's `processCerts` → `validatePerasCert mkPerasParams` path accepts it unconditionally (returns `Right`) and stores it in the `PerasCertDB`.
5. Chain selection now applies `perasWeight = 15` boost to the minority fork's block, potentially causing the node to switch to the adversary's preferred chain.

No BLS key material, no stake, and no valid quorum of votes are required at any step.

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L131-148)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L113-137)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L88-115)
```haskell
hashVoteSignature ::
  ElectionId PerasBLSCrypto ->
  VoteCandidate PerasBLSCrypto ->
  Hash HASH (SigDSIGN BLS12381MinSigDSIGN)
hashVoteSignature roundNo boostedBlock =
  Hash.castHash
    . Hash.hashWith id
    . runByteBuilder (8 + 8 + 32)
    $ roundNoBytes
      <> boostedBlockSlotBytes
      <> boostedBlockHashBytes
 where
  roundNoBytes =
    BS.word64BE
      . unPerasRoundNo
      $ roundNo
  boostedBlockSlotBytes =
    BS.word64BE
      . unSlotNo
      . bytes32RealPointSlot
      . unPerasBoostedBlock
      $ boostedBlock
  boostedBlockHashBytes =
    BS.byteStringCopy
      . BS.fromShort
      . bytes32RealPointHash
      . unPerasBoostedBlock
      $ boostedBlock
```
