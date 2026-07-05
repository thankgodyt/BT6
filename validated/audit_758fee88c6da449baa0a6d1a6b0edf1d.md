### Title
`validatePerasCert` Unconditionally Returns Success, Bypassing All Peras Certificate Validation - (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance implements `validatePerasCert` as an unconditional `Right` (success), performing zero cryptographic or protocol validation. Any certificate received from an unprivileged peer over the object-diffusion mini-protocol is accepted and stored, then fed into chain selection with a weight boost. This is a direct analog to the Liquity "redeem without redemptions" bug: a function that is supposed to gate an operation on a validity check instead silently succeeds for all inputs, allowing the operation to proceed with no actual verification.

---

### Finding Description

The `BlockSupportsPeras` type class declares `validatePerasCert` as the mandatory gate for accepting inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The single universal instance (covering all block types) implements this as:

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

This function unconditionally wraps any input certificate in `Right`, assigning it the full protocol weight (`perasWeight params = 15` by default), regardless of the certificate's round number, boosted block, committee membership, or cryptographic signatures. [2](#0-1) 

This stub is wired directly into the production inbound-certificate processing path. Both `makePerasCertPoolWriterFromChainDB` and `makePerasCertPoolWriterFromCertDB` pass `(validatePerasCert mkPerasParams)` as the validation callback to `processCerts`: [3](#0-2) 

`processCerts` is designed to reject the entire batch and disconnect from the peer if any certificate fails validation. But since `validatePerasCert` never returns `Left`, the rejection branch (`throw (PerasCertValidationError errs)`) is unreachable: [4](#0-3) 

Every certificate that is not already in the database is unconditionally accepted and forwarded to `ChainDB.addPerasCertAsync`, which triggers chain selection with the boosted block. [5](#0-4) 

---

### Impact Explanation

A Peras certificate causes the node to assign a weight boost of `perasWeight` (15 slots-worth of chain weight) to the boosted block during chain selection. An adversary who injects a crafted certificate pointing to an arbitrary block on a minority fork can cause an honest node to prefer that fork over the canonical chain. This is a **chain selection bug triggered by an unprivileged peer**: the node will switch to a non-canonical, adversarially chosen chain without any stake majority or key compromise. This falls squarely within the "High" impact category: a chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable by any peer that connects to the node. No authentication, stake ownership, or key material is required to send a `PerasCert` message. An attacker only needs to craft a `PerasCert` with a `pcCertBoostedBlock` pointing to a block on a fork they wish to promote. The likelihood is **High** once the Peras protocol is active on a live network, as the attack requires only a network connection and knowledge of the wire format.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that checks, at minimum:
1. The certificate's round number is within the valid window relative to the current chain tip.
2. The boosted block exists and is within the volatile window.
3. The committee membership proof and cryptographic signature over the certificate are valid.
4. The certificate is not from a round already finalized (immutable).

Until the full cryptographic validation is implemented, the function should return `Left PerasValidationErr` by default (fail-closed) rather than `Right` (fail-open), so that no inbound certificate is accepted without a deliberate decision to accept it.

Additionally, add a property-based test asserting that `validatePerasCert` rejects certificates with invalid round numbers, unknown boosted blocks, or malformed committee proofs.

---

### Proof of Concept

1. Connect to a node running this code via the object-diffusion mini-protocol for Peras certificates.
2. Send a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point on a minority fork>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 })`.
4. The certificate is stored via `ChainDB.addPerasCertAsync`.
5. Chain selection runs with the minority fork's tip now carrying a weight boost of 15.
6. If the minority fork's boosted weight exceeds the canonical chain's weight, the node switches to the minority fork.

The root cause is at: [6](#0-5)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-172)
```haskell
    , perasWeight =
        PerasWeight 15
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L121-133)
```haskell
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
