### Title
Peras Certificate Validation Bypass: `validatePerasCert` Unconditionally Accepts Any Peer-Supplied Certificate Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all degenerate `BlockSupportsPeras` instance implements `validatePerasCert` to unconditionally return `Right` (success) for every certificate, performing zero cryptographic or semantic checks. This function is directly wired into the production miniprotocol inbound handler `processCerts` in `MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs`. Any unprivileged peer can send a crafted `PerasCert` naming an arbitrary block, have it accepted without any authorization check, and cause the receiving node to boost that block in chain selection with full Peras weight.

This is the direct structural analog of the Phantasia bug: the Phantasia handler checked key identity but not the signer flag; here, not even an identity check is performed — the certificate is accepted unconditionally.

---

### Finding Description

**Root cause — `validatePerasCert` stub always returns `Right`**

The `BlockSupportsPeras` class requires a `validatePerasCert` method. The catch-all instance that covers all block types is:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/120
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

The `PerasCert` data type in this instance carries no signature field at all:

```haskell
data PerasCert blk = PerasCert
  { pcCertRound :: PerasRoundNo
  , pcCertBoostedBlock :: Point blk
  }
``` [2](#0-1) 

There is no aggregate BLS signature, no voter bitmap, no quorum check — and `validatePerasCert` returns `Right` for every input regardless.

**Wiring into the network-facing handler**

`processCerts` in `MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs` is the production handler for Peras certificates received from peers. It calls `validatePerasCert` directly:

```haskell
, opwAddObjects = \certs ->
    processCerts
      systemTime
      (ChainDB.getPerasCertIds chainDB)
      -- TODO replace when actual plumbing is in place
      (validatePerasCert mkPerasParams)
      (void . ChainDB.addPerasCertAsync chainDB)
      certs
``` [3](#0-2) 

`processCerts` partitions results into errors and successes. Because `validatePerasCert` never returns `Left`, the error branch is never taken and every inbound certificate is forwarded to `addPerasCertAsync`:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

**Chain-selection consequence**

`ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`. This boost is the mechanism by which Peras certificates cause a node to prefer one chain over another. Accepting a forged certificate for an attacker-chosen block directly manipulates the chain-selection weight of that block.

**Analog mapping**

| Phantasia | Ouroboros Consensus |
|---|---|
| `sell_order_data.seller_wallet != *seller_wallet_account.key` — identity check present | `lookupPerasVoteStake` / round-number dedup — minimal structural check |
| `seller_wallet_account.is_signer` — authorization check **absent** | Aggregate BLS signature verification — **absent** |
| Anyone can cancel any sell order | Any peer can boost any block with a forged certificate |

---

### Impact Explanation

**High — Chain selection manipulation via forged Peras certificates.**

An unprivileged peer can cause an honest node to assign full Peras boost weight to an arbitrary block by sending a certificate that names that block. Because `validatePerasCert` always succeeds, the node cannot distinguish a legitimate certificate (backed by a quorum of committee signatures) from a completely fabricated one. This lets an attacker steer chain selection toward a non-canonical tip, violating the security assumption that only a quorum of eligible committee members can produce a valid certificate.

---

### Likelihood Explanation

**High.** The attacker needs only a standard peer connection and the ability to send a well-formed CBOR-encoded `PerasCert` message over the Peras certificate object-diffusion miniprotocol. No keys, no stake, no privileged access are required. The `PerasCert` type in the degenerate instance contains only a round number and a block point — both are public information. The only gate is the round-number deduplication check (`certsNotAlreadyInDb`), which is trivially bypassed by using a round number not yet present in the database.

---

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that:

1. Verifies the aggregate BLS signature (`pcSignature`) against the aggregated public keys of the claimed voters.
2. Checks each claimed voter against the current committee (eligibility, stake, seat index).
3. Verifies that the aggregate stake of the signers meets the quorum threshold.

The concrete `PerasCert` type in `Peras/Cert/V1.hs` already carries the necessary fields (`pcSignature :: AggregateVoteSignature PerasBLSCrypto`, `pcVoters :: PerasCertVoters`) for a complete implementation. [5](#0-4) 

Until a real implementation is in place, the miniprotocol handler should reject all inbound certificates rather than accept them unconditionally.

---

### Proof of Concept

1. Connect to a target node as a peer via the Peras certificate object-diffusion miniprotocol.
2. Construct a `PerasCert` value with:
   - `pcCertRound` set to any round number not yet in the node's certificate database.
   - `pcCertBoostedBlock` set to the `Point` of any block the attacker wishes to boost (e.g., a minority-fork tip).
3. Send the certificate to the node.
4. `processCerts` calls `validatePerasCert`, which returns `Right ValidatedPerasCert { vpcCertBoost = perasWeight params }` unconditionally.
5. The certificate is stored in ChainDB via `addPerasCertAsync`.
6. The target block now carries full Peras boost weight in chain selection.
7. The node will prefer the boosted block over equally-long or shorter chains that lack a certificate, diverging from the canonical chain. [6](#0-5) [7](#0-6)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Cert/V1.hs (L49-60)
```haskell
-- | Concrete Peras certificates using BLS signatures
data PerasCert
  = PerasCert
  { pcRoundNo :: !PerasRoundNo
  -- ^ Election identifier
  , pcBoostedBlock :: !PerasBoostedBlock
  -- ^ Certificate message, i.e., the hash of the block being boosted
  , pcVoters :: !PerasCertVoters
  -- ^ Voters who contributed to this certificate
  , pcSignature :: !(AggregateVoteSignature PerasBLSCrypto)
  -- ^ Aggregate BLS signature on the hash of the election identifier and
  -- the certificate message
```
