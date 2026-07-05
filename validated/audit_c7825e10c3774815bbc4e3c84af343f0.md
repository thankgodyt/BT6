### Title
Peras Certificate Validation Bypass via Unconditional `Right` Return in `validatePerasCert` Enables Unauthorized Certificate Injection and Chain-Selection Manipulation — (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The universal `BlockSupportsPeras` instance — the only active production implementation — unconditionally returns `Right` from `validatePerasCert`, accepting every inbound Peras certificate without any cryptographic or semantic check. This is wired directly into the production certificate-diffusion path. Any unprivileged peer can inject a crafted `PerasCert` pointing to an arbitrary block; the certificate is stored and immediately triggers chain selection with a weight boost of `perasWeight = 15`, potentially causing honest nodes to adopt an adversarial chain.

---

### Finding Description

**Root cause — `validatePerasCert` always succeeds**

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`, lines 350–358:

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

This is the **only** instance of `BlockSupportsPeras` in the codebase (the comment at line 318 explicitly calls it "degenerate instance for all blks to get things to compile"). No Cardano-era-specific override exists. The function ignores the certificate payload entirely — no aggregate BLS signature check, no committee-membership check, no quorum check.

**Production call path — `makePerasCertPoolWriterFromChainDB`**

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`, lines 118–133:

```haskell
makePerasCertPoolWriterFromChainDB systemTime chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasCertRound
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (ChainDB.getPerasCertIds chainDB)
          -- TODO replace when actual plumbing is in place
          (validatePerasCert mkPerasParams)   -- ← always Right
          (void . ChainDB.addPerasCertAsync chainDB)
          certs
    ...
    }
``` [2](#0-1) 

`processCerts` partitions the results of `validateCert` into errors and successes. Because `validatePerasCert` never returns `Left`, the error branch is structurally unreachable:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)   -- never reached
``` [3](#0-2) 

Every accepted certificate is forwarded to `ChainDB.addPerasCertAsync`, whose documented contract is:

> "If this leads to a fork to be weightier than our current selection, this will trigger a fork switch." [4](#0-3) 

**Analog to the external report**

| External report | Consensus analog |
|---|---|
| `withdrawMargin` check passes because current margin > required margin (profitable position) | `validatePerasCert` check passes because it unconditionally returns `Right` |
| User drains all collateral; invariant (collateral ≥ maintenance margin) is violated | Adversary injects any certificate; invariant (cert must carry valid quorum proof) is violated |
| Liquidation later finds zero collateral to deduct | Chain selection later applies a `perasWeight = 15` boost to an adversarially chosen block |

The structural pattern is identical: a validation gate that is too permissive in the present allows a state to be committed that violates a security invariant when acted upon later.

---

### Impact Explanation

An unprivileged peer that speaks the Peras certificate diffusion mini-protocol can send a `PerasCert` for any round number, pointing to any block hash. The certificate is accepted, stored in `PerasCertDB`, and immediately submitted to chain selection. The targeted block receives a weight boost of `perasWeight = 15` (the default from `mkPerasParams`). [5](#0-4) 

If the adversary simultaneously diffuses a valid block (which passes normal header/body validation) and injects a certificate for it, the boosted chain can become preferred over the honest chain, causing honest nodes to switch — a consensus safety failure. This matches the **Critical** allowed impact: bypass of Peras certificate checks enabling unauthorized certificate acceptance.

---

### Likelihood Explanation

The attack requires only:
1. A standard peer connection via the Peras object-diffusion mini-protocol.
2. Constructing a `PerasCert` CBOR value (two fields: `pcCertRound` and `pcCertBoostedBlock`).

No stake, no keys, no admin access. The entry point is fully reachable by any unprivileged network peer.

---

### Recommendation

Replace the stub implementation with real validation before the Peras certificate diffusion path is active in production:

1. **Aggregate BLS signature verification** — verify `pcSignature` against the claimed voters' public keys and the election identifier.
2. **Committee membership** — verify each claimed voter seat index against the epoch's committee selection output (wFA^LS).
3. **Quorum check** — verify that the total stake of the claimed voters exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
4. **Round/slot bounds** — verify that the certificate's round number is within the acceptable window relative to the current chain tip.

Until the full implementation is ready, the diffusion layer should refuse to accept inbound certificates (return a hard error or disable the writer) rather than silently accepting everything.

---

### Proof of Concept

```
1. Peer connects to an honest node via the Peras cert diffusion protocol.

2. Peer constructs a minimal PerasCert CBOR payload:
     { pcCertRound      = <any round number>
     , pcCertBoostedBlock = <Point of a block already in the node's VolatileDB> }

3. Peer sends the cert batch to the node.

4. processCerts calls (validatePerasCert mkPerasParams cert)
   → always returns Right ValidatedPerasCert { vpcCertBoost = 15 }

5. addCert (ChainDB.addPerasCertAsync) is called with the crafted cert.

6. ChainDB triggers chain selection; the targeted block now carries
   a weight boost of 15.

7. If the adversary's chain (containing the boosted block) is otherwise
   competitive, the honest node switches to it — consensus safety violated.
``` [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-443)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Params.hs (L171-177)
```haskell
    , perasWeight =
        PerasWeight 15
    , perasQuorumStakeThreshold =
        PerasQuorumStakeThreshold (3 / 4)
    , perasQuorumStakeThresholdSafetyMargin =
        PerasQuorumStakeThresholdSafetyMargin (2 / 100)
    }
```
