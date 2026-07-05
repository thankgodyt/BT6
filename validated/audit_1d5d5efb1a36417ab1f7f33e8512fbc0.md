### Title
Peras Certificate Validation Stub Unconditionally Accepts All Peer-Supplied Certificates - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The `validatePerasCert` method in the `BlockSupportsPeras` typeclass instance is a stub that unconditionally returns `Right` for every certificate it receives, performing zero validation. Any certificate injected by an unprivileged peer over the ObjectDiffusion mini-protocol is accepted, timestamped, and stored in the `PerasCertDB` with a full chain-selection boost weight. This is the direct analog of the NftPort "signature without expiration" bug: just as that contract accepted any previously-issued signature forever with no time bound, this code accepts any certificate forever with no cryptographic, round-number, or staleness check.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gatekeeper before any certificate is stored or used for chain selection. The universal instance for all block types is:

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
``` [1](#0-0) 

This stub is wired directly into the network-facing inbound certificate processing path. `makePerasCertPoolWriterFromChainDB` passes `validatePerasCert mkPerasParams` as the validation callback to `processCerts`: [2](#0-1) 

`processCerts` calls this callback on every new certificate received from a peer, and if it returns `Right` (which it always does), the certificate is immediately stored in the `PerasCertDB`: [3](#0-2) 

The missing checks that `validatePerasCert` should enforce include:
- **Cryptographic signature verification** of the aggregate BLS vote signature over the `(electionId, candidate)` pair
- **Round-number bounds**: the certificate's `pcCertRound` must fall within a valid window relative to the current chain tip (analogous to the KES period window `c₀ ≤ kp < c₀ + MaxKESEvo`)
- **Voter eligibility**: each voter in the certificate must be a legitimate committee member for that round
- **Quorum threshold**: the aggregate stake of the signers must exceed the quorum threshold

The same pattern applies to `validatePerasVote`, which also carries a TODO stub and only checks stake-distribution membership without verifying the vote's cryptographic signature or round-number validity: [4](#0-3) 

---

### Impact Explanation

**High. Chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain.**

A `ValidatedPerasCert` carries a `vpcCertBoost` weight equal to `perasWeight params`. This boost is used directly in chain selection to prefer the boosted block over competing chains. Because `validatePerasCert` always succeeds, a malicious peer can:

1. Craft a `PerasCert` with an arbitrary `pcCertRound` and `pcCertBoostedBlock` pointing to any block (including one on an adversarial fork).
2. Send it over the ObjectDiffusion mini-protocol.
3. The node stores it with full boost weight.
4. Chain selection now prefers the adversarially-chosen block, causing the honest node to diverge from the canonical chain.

Additionally, a certificate with a far-future `pcCertRound` would be accepted and stored permanently (no expiration check), exactly mirroring the "lifetime license" problem in the NftPort report.

---

### Likelihood Explanation

**High.** The entry path is the standard peer-to-peer ObjectDiffusion protocol, reachable by any node that connects to the victim. No special privileges, keys, or stake are required. The stub is the active production code path (not gated behind a feature flag), and the TODO comment confirms it is intentionally incomplete rather than accidentally missing.

---

### Recommendation

Implement `validatePerasCert` with the full set of checks required by the Peras protocol (CIP-0140):

1. **Cryptographic**: verify the aggregate BLS signature over `(electionId, candidate)` using the aggregated public keys of the claimed voters, as already implemented in `implVerifyCert` in `WFALS.hs`.
2. **Round-number bounds**: reject certificates whose `pcCertRound` is outside the valid window relative to the current chain tip (e.g., more than `_A` rounds old or in the future).
3. **Voter eligibility**: verify each voter is a legitimate committee member for the claimed round using the epoch's stake distribution and VRF outputs.
4. **Quorum**: verify the aggregate stake of the signers exceeds the quorum threshold.

The same applies to `validatePerasVote`: add cryptographic signature verification and round-number staleness checks before accepting votes from peers.

---

### Proof of Concept

**Attacker-controlled entry path:**

```
Peer → ObjectDiffusion mini-protocol
     → makePerasCertPoolWriterFromChainDB (PerasCert.hs:118)
     → processCerts (PerasCert.hs:164)
     → validatePerasCert mkPerasParams cert  ← always returns Right
     → addCert (stored in PerasCertDB with full boost weight)
     → chain selection prefers adversarially-chosen block
```

**Crafted certificate:**
```haskell
-- Attacker sends this over the wire:
PerasCert
  { pcCertRound      = 999999  -- far-future round, no expiration check
  , pcCertBoostedBlock = adversarialForkTip  -- any block hash
  }
-- validatePerasCert returns Right unconditionally:
-- Right (ValidatedPerasCert { vpcCert = ..., vpcCertBoost = perasWeight params })
```

The certificate is stored and its boost is applied to `adversarialForkTip` in chain selection, causing the honest node to prefer the adversarial fork. No cryptographic material, stake, or operator access is required. [5](#0-4) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-358)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)

  validatePerasVote ::
    PerasCfg blk ->
    PerasVoteStakeDistr ->
    PerasVote blk ->
    Either (PerasValidationErr blk) (ValidatedPerasVote blk)

  forgePerasCert ::
    PerasCfg blk ->
    ValidatedPerasVotesWithQuorum blk ->
    Either (PerasForgeErr blk) (ValidatedPerasCert blk)

  -- | Extract a Peras certificate optionally stored in a block.
  --
  -- Returns 'Nothing' if the block does not contain a Peras certificate, or
  -- if the block is from an era that does not support Peras certificates.
  getPerasCertInBlock ::
    blk ->
    Maybe (PerasCert blk)

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
