### Title
Peras Certificate Validation Unconditionally Accepts Any Peer-Supplied Certificate - (`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The default `BlockSupportsPeras` instance's `validatePerasCert` function always returns `Right` — it performs zero cryptographic or structural validation. Any unprivileged peer can inject an arbitrary `PerasCert` (with any round number and any boosted block point) through the object-diffusion mini-protocol. The certificate is accepted unconditionally, timestamped, and added to the ChainDB, where it applies a Peras weight boost that directly influences chain selection.

### Finding Description

The `BlockSupportsPeras` class declares `validatePerasCert` as the mandatory gate for accepting inbound Peras certificates:

```haskell
validatePerasCert ::
  PerasCfg blk ->
  PerasCert blk ->
  Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

The default instance (which covers all `StandardHash blk` blocks, i.e., every production block type) is: [1](#0-0) 

```haskell
-- TODO: perform actual validation against all
-- possible 'PerasValidationErr' variants
validatePerasCert params cert =
  Right
    ValidatedPerasCert
      { vpcCert = cert
      , vpcCertBoost = perasWeight params
      }
```

This is not a conditional — it is an unconditional `Right`. No committee membership check, no quorum proof, no cryptographic signature, no round-number plausibility check is performed. Notably, the `PerasCert` data type itself carries no signature field: [2](#0-1) 

The production inbound path in `makePerasCertPoolWriterFromChainDB` passes this stub directly as the `validateCert` callback: [3](#0-2) 

`processCerts` then partitions results and adds every certificate that passes validation to the ChainDB: [4](#0-3) 

Because `validatePerasCert` always returns `Right`, every certificate in every batch is "valid" and forwarded to `ChainDB.addPerasCertAsync`, which triggers chain selection side-effects.

The same structural gap exists for `validatePerasVote`: the `PerasVote` type carries no signature field, and the validation only checks stake-distribution membership — it cannot verify that the claimed voter actually cast the vote: [5](#0-4) 

### Impact Explanation

A `ValidatedPerasCert` carries a `vpcCertBoost :: PerasWeight` that is applied directly in chain selection to prefer the certified block. By injecting a certificate that boosts an adversary-controlled block, an unprivileged peer can make an honest node assign elevated weight to a non-canonical chain, potentially causing it to switch away from the honest chain. This is a bypass of Peras certificate/vote checks that enables unauthorized certificate acceptance and chain-selection manipulation — matching the "Critical: bypass of certificate/signature validation" and "High: chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain" impact categories.

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is wired into the production node setup via `makePerasCertPoolWriterFromChainDB`. Any NTN peer that speaks the protocol can send a crafted `PerasCert` batch. No keys, stake, or operator access are required. The only prerequisite is that the Peras feature flag is active on the target node.

### Recommendation

1. **Implement real cryptographic validation** in `validatePerasCert` before the Peras feature is enabled on any network. At minimum, verify committee membership and the aggregate signature over `(round, boostedBlock)`.
2. **Add a signature field** to `PerasCert` and `PerasVote` so that the data types structurally require a proof of authorization, analogous to how `userOpHash` in the reference report should be reconstructed from `userOp` rather than accepted as a caller-supplied input.
3. **Gate the object-diffusion handlers** behind a feature flag that is disabled until validation is complete, so the stub cannot be reached on production nodes.

### Proof of Concept

1. Connect to a node with Peras object-diffusion enabled as an NTN peer.
2. Send a `PerasCert` message with `pcCertRound = <any round>` and `pcCertBoostedBlock = <point of adversary block>`.
3. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })` unconditionally.
4. The certificate is passed to `ChainDB.addPerasCertAsync`, which stores it and triggers chain selection.
5. The adversary block now carries a Peras weight boost in the node's chain-selection logic, causing the node to prefer it over an equally-long honest chain.

### Citations

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
