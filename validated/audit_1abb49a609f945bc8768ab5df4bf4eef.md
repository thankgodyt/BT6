### Title
Peras Certificate and Vote Validation Unconditionally Accepts Any Input Without Cryptographic Verification — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The universal `BlockSupportsPeras` instance's `validatePerasCert` method unconditionally returns `Right` (success) for every certificate it receives, performing zero cryptographic checks. The companion `validatePerasVote` method only checks stake-distribution membership and never verifies the vote's cryptographic signature. Because this universal instance is the only implementation in the codebase, any unprivileged peer can inject arbitrary Peras certificates and forge votes attributed to any staked pool, directly manipulating Peras-weighted chain selection.

### Finding Description

`SupportsPeras.hs` declares the `BlockSupportsPeras` typeclass and provides a single universal instance (`instance StandardHash blk => BlockSupportsPeras blk`) that is the only implementation in the repository.

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

Every certificate, regardless of content or origin, is wrapped in `ValidatedPerasCert` and assigned the full `perasWeight` boost. No quorum check, no aggregate-signature check, no round-number sanity check is performed. [1](#0-0) 

**`validatePerasVote` — signature never verified:**

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

The only guard is `lookupPerasVoteStake`, which checks whether the claimed `PerasVoterId` (a `KeyHash StakePool`) appears in the stake distribution map. The cryptographic signature that proves the vote was actually produced by the holder of that pool's private key is never checked. [2](#0-1) 

The `lookupPerasVoteStake` helper only performs a `Map.lookup` on the voter ID: [3](#0-2) 

The `processVotes` inbound handler in the Peras vote object-diffusion layer calls the injected `validateVote` callback for every batch of votes received from a peer. If any vote fails, the whole batch is rejected and the peer is disconnected. But because `validatePerasVote` only checks stake-map membership, a peer that knows the `KeyHash` of any staked pool (public information on-chain) can pass this check without possessing the pool's signing key. [4](#0-3) 

The `forgePerasCert` method in the same universal instance also constructs a `ValidatedPerasCert` without any verification, meaning a node can be made to forge and propagate a certificate for an arbitrary block: [5](#0-4) 

The comment at the instance head explicitly acknowledges this is a placeholder:

> `-- TODO: degenerate instance for all blks to get things to compile`
> `-- see https://github.com/tweag/cardano-peras/issues/73` [6](#0-5) 

No overriding instance for Cardano blocks exists anywhere in the repository; a grep for `validatePerasCert` and `validatePerasVote` returns only the definition site.

### Impact Explanation

Peras certificates boost blocks during chain selection. A `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` that is added to the chain-selection score of the boosted block. Because `validatePerasCert` always succeeds and always assigns the full `perasWeight`, an adversary can:

1. **Forge a certificate for any block** — including a minority or adversarial fork — and have every honest node accept it as valid, causing them to prefer that fork over the canonical chain.
2. **Forge votes attributed to any staked pool** — accumulating enough `PerasVoteStake` to satisfy `votesReachQuorum`, then triggering `forgePerasCert` on an honest node to produce a certificate for an adversarial block.

Both paths lead to **chain-selection manipulation**: honest nodes are made to prefer a non-canonical chain, violating the common-prefix and chain-quality properties that Peras is designed to strengthen.

This matches the allowed impact: *"Critical. Bypass of … PBFT/Praos/TPraos/Peras voting or certificate checks … that enables unauthorized … vote, or certificate acceptance"* and *"High. Chain selection … bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain."*

### Likelihood Explanation

The entry path is the Peras vote object-diffusion mini-protocol, reachable by any peer that can open a connection to the node. The only information an attacker needs is the `KeyHash StakePool` of a staked pool, which is public on-chain data. No key material, no stake majority, and no operator compromise is required. The Peras extension is actively being wired into the node (the `processVotes` handler and the `PerasVoteInboundException` disconnect logic are already in place), so this code is on the path to production deployment.

### Recommendation

1. **Implement real cryptographic verification in `validatePerasCert`**: verify the aggregate BLS vote signature (using `linearizeAndVerifyVRFs` / `verifyAggregateVoteSignature` already present in `BLS.hs` and `Peras/Crypto/BLS.hs`) against the claimed quorum of voters, and check that the round number and boosted block are consistent with the current chain state. [7](#0-6) 

2. **Implement real cryptographic verification in `validatePerasVote`**: call `verifyVoteSignature` (already defined in `Peras/Crypto/BLS.hs`) to confirm the vote was signed by the holder of the pool's private key before accepting it. [8](#0-7) 

3. **Do not ship the universal stub instance to production**: gate the Peras code paths behind a compile-time or runtime flag until the real implementations are in place, or replace the universal instance with a type-level error that forces each concrete block type to provide its own verified implementation.

### Proof of Concept

An unprivileged peer executes the following steps against a target node running the Peras vote diffusion protocol:

1. Observe the on-chain stake distribution to obtain the `KeyHash StakePool` of any pool with positive stake (e.g., pool `P` with stake `s`).
2. Construct a `PerasVote` with `pvVoteVoterId = PerasVoterId (keyHashOf P)`, `pvVoteRound = currentRound`, and `pvVoteBlock = adversarialForkTip`. No signing key for `P` is needed.
3. Send a batch of such forged votes (one per staked pool, all pointing at the adversarial fork) to the target node via the Peras vote mini-protocol. `processVotes` calls `validatePerasVote` for each; every call succeeds because `lookupPerasVoteStake` finds the pool in the distribution.
4. The accumulated `PerasVoteStake` satisfies `votesReachQuorum`; the node calls `forgePerasCert`, which calls `validatePerasCert` — which unconditionally returns `Right` — and produces a `ValidatedPerasCert` boosting the adversarial fork.
5. The certificate is included in the next block the node forges, propagating the boost to all peers and causing the network to prefer the adversarial fork over the canonical chain. [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L350-385)
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

  -- TODO: perform actual validation against all
  -- possible 'PerasForgeErr' variants
  -- see https://github.com/tweag/cardano-peras/issues/120
  forgePerasCert params votes =
    return $
      ValidatedPerasCert
        { vpcCert =
            PerasCert
              { pcCertRound = pvtRoundNo (vpvqTarget votes)
              , pcCertBoostedBlock = pvtBlock (vpvqTarget votes)
              }
        , vpcCertBoost = perasWeight params
        }
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/Crypto/BLS.hs (L378-425)
```haskell
linearizeAndVerifyVRFs ::
  SignableRepresentation msg =>
  NE [PublicKey VRF] ->
  msg ->
  NE [Signature VRF] ->
  Either String ()
linearizeAndVerifyVRFs keys@(firstKey :| restKeys) msg sigs = do
  when (any (/= publicKeyScope firstKey) (fmap publicKeyScope restKeys)) $
    Left "Cannot aggregate public keys with different scopes"

  when (length sigs /= length keys) $
    Left "Number of signatures must match number of public keys"

  let scalars =
        NonEmpty.map
          (fromIntegral . signatureNatural)
          sigs

  let linearizedKeyPoint =
        blsMSM
          . NonEmpty.toList
          . NonEmpty.zip scalars
          . NonEmpty.map (\(PublicKey (VerKeyBLS12381 p) _) -> p)
          $ keys

  let linearizedSigPoint =
        blsMSM
          . NonEmpty.toList
          . NonEmpty.zip scalars
          . NonEmpty.map (\(Signature (SigBLS12381 p)) -> p)
          $ sigs

  when (blsIsInf linearizedKeyPoint) $
    Left "Resulting key point is at infinity, cannot linearize"

  when (blsIsInf linearizedSigPoint) $
    Left "Resulting signature point is at infinity, cannot linearize"

  let linearizedKey =
        PublicKey
          (VerKeyBLS12381 linearizedKeyPoint)
          (publicKeyScope firstKey)

  let linearizedSig =
        Signature
          (SigBLS12381 linearizedSigPoint)

  verifyWithRole @VRF linearizedKey msg linearizedSig
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L162-170)
```haskell
  verifyVoteSignature
    pk
    roundNo
    boostedBlock
    (PerasBLSCryptoVoteSignature sig) =
      BLS.verifyWithRole @SIGN
        pk
        (hashVoteSignature roundNo boostedBlock)
        sig
```
