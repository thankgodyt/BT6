### Title
`validatePerasCert` Unconditionally Accepts All Inbound Peras Certificates — Bypass of Certificate Validation Enabling Chain Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The `BlockSupportsPeras` type class declares `validatePerasCert` as the security gate for all inbound Peras certificates received from peers. The production inbound path (`makePerasCertPoolWriterFromChainDB`) calls `processCerts` with this function as the validator. However, the universal instance implementation of `validatePerasCert` unconditionally returns `Right` for every certificate, performing zero cryptographic or semantic checks. Any unprivileged peer can inject an arbitrary `PerasCert` that will be accepted, stored, and used to boost an attacker-chosen block in chain selection.

### Finding Description

The `BlockSupportsPeras` class defines `validatePerasCert` as the mandatory validation entry point:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The universal instance — which is the only instance in the codebase and therefore the one used in production — implements it as an unconditional stub:

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

No check is performed on:
- Cryptographic signature of the certificate
- Whether the certificate was formed from a quorum of valid, eligible votes
- Whether the boosted block (`pcCertBoostedBlock`) exists or is on any valid chain
- Whether the round number is within any valid range
- Whether the issuing committee members were actually eligible

The production inbound path in `makePerasCertPoolWriterFromChainDB` passes this stub directly as the `validateCert` argument to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` calls `validateCert` on every inbound certificate and only rejects a batch if the function returns `Left`. Since `validatePerasCert` always returns `Right`, every certificate from every peer is accepted unconditionally: [3](#0-2) 

The accepted certificate is then stored in the `PerasCertDB` and propagated to chain selection, where it applies a boost of `perasWeight` (default: 15) to the attacker-specified block.

The structural parallel to the reported `PausableUpgradeable` issue is exact: the validation framework is declared (`validatePerasCert` exists, `processCerts` calls it, `PerasCertValidationErr` exists, the rejection path exists), but the implementation is a stub that always succeeds — giving a false sense of security while providing no actual protection.

### Impact Explanation

An unprivileged peer can craft a `PerasCert` pointing `pcCertBoostedBlock` at any block of its choice. The certificate will be accepted, stored, and applied as a chain-selection weight boost of `perasWeight = 15` to that block. Since Peras chain selection uses these boosts to prefer chains, an attacker can cause an honest node to prefer a non-canonical or adversarially chosen chain fragment over the honest chain, directly undermining chain selection integrity.

**Impact category:** Critical — Bypass of Peras certificate validation that enables unauthorized certificate acceptance and chain selection manipulation by an unprivileged peer.

### Likelihood Explanation

The attack requires only that the Peras object diffusion miniprotocol is active and that the attacker can connect as a peer (no privileged access required). The attacker constructs a `PerasCert` with an arbitrary `pcCertBoostedBlock` and sends it. The validation call always returns `Right`, so the certificate is stored and applied. The likelihood is high whenever Peras is enabled on a running node.

### Recommendation

Implement actual cryptographic and semantic validation inside `validatePerasCert` before the Peras object diffusion miniprotocol is enabled in production. At minimum, the implementation must:

1. Verify the cryptographic signature(s) on the certificate against the eligible committee members for the claimed round.
2. Verify that the boosted block exists and is on a known chain fragment.
3. Verify that the round number is within the valid acceptance window.
4. Verify that the certificate was formed from a quorum of eligible, stake-weighted votes.

Until a real implementation is in place, the production inbound path (`makePerasCertPoolWriterFromChainDB`) must not be wired to live peers, or must gate certificate acceptance behind a feature flag that is disabled by default. [4](#0-3) 

### Proof of Concept

1. Connect to a node as an unprivileged peer via the Peras object diffusion miniprotocol.
2. Construct a `PerasCert` with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of target block>`.
3. Send the certificate to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{vpcCert = cert, vpcCertBoost = PerasWeight 15}` unconditionally.
5. The certificate is stored in the `PerasCertDB` via `ChainDB.addPerasCertAsync`.
6. Chain selection now applies a weight boost of 15 to the attacker-chosen block, potentially causing the node to prefer a non-canonical chain. [5](#0-4)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L278-297)
```haskell
class
  ( Show (PerasCfg blk)
  , NoThunks (PerasCert blk)
  ) =>
  BlockSupportsPeras blk
  where
  type PerasCfg blk

  data PerasCert blk

  data PerasVote blk

  data PerasValidationErr blk

  data PerasForgeErr blk

  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-133)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-185)
```haskell
processCerts ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set PerasRoundNo) ->
  (PerasCert blk -> Either (PerasValidationErr blk) (ValidatedPerasCert blk)) ->
  (WithArrivalTime (ValidatedPerasCert blk) -> m ()) ->
  [PerasCert blk] ->
  m ()
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
