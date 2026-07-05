### Title
Peras Certificate Validation Bypass Allows Unprivileged Peer to Manipulate Chain Selection - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The production implementation of `validatePerasCert` unconditionally accepts every inbound Peras certificate without performing any cryptographic, quorum, or committee-membership check. An unprivileged peer can send a crafted `PerasCert` targeting any block, and the node will accept it, store it in the `PerasCertDB`, and use it to boost that block's weight in chain selection — potentially causing the node to prefer a non-canonical adversarial fork.

---

### Finding Description

The `BlockSupportsPeras` type class defines `validatePerasCert` as the gate that must verify a certificate before it is stored and used in chain selection. The production instance (the only instance, used for all block types) is a stub that always returns `Right`:

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

This stub is wired directly into the network-facing certificate ingestion path. Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` pass `validatePerasCert mkPerasParams` as the validation callback to `processCerts`:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) [3](#0-2) 

`processCerts` relies entirely on this callback to decide whether to accept or reject certificates from peers:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
  (errs, _) ->
    throw (PerasCertValidationError errs)
``` [4](#0-3) 

Because `validatePerasCert` never returns `Left`, `partitionEithers` always produces an empty error list, and every certificate is unconditionally added. Once stored, the certificate's boosted block is immediately submitted to chain selection:

```haskell
lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
``` [5](#0-4) 

Chain selection then computes `totalWeightOfFragment` using the `PerasWeightSnapshot` derived from all stored certificates, and prefers the fragment with the highest total weight:

```haskell
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
``` [6](#0-5) 

The analog to the external report is exact: the external bug used `min` instead of `max`, allowing a weaker threshold to pass validation. Here, the threshold is effectively zero — no validation is performed at all — which is the degenerate case of the same class of flaw.

---

### Impact Explanation

An unprivileged peer can send a `PerasCert` naming any block as the boosted target. The certificate passes validation unconditionally, is stored in the `PerasCertDB`, and causes the node to re-run chain selection with the adversarial block now carrying a weight boost of `perasWeight params` (currently 15 on mainnet defaults). By targeting a block on an adversarial fork, the attacker can make that fork's total weight exceed the honest chain's total weight, causing the node to switch to the adversarial fork. This is a **chain selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain**, matching the "High" impact tier.

---

### Likelihood Explanation

The certificate ingestion path is reachable by any connected peer via the object diffusion mini-protocol. No stake, keys, or special privileges are required. The attacker only needs to craft a `PerasCert` with `pcCertBoostedBlock` pointing to a block on their fork. The boost weight is fixed by the local node's config (`perasWeight params = 15`), so the attacker needs to send enough certificates (one per round, since the DB deduplicates by round number) to accumulate sufficient weight to outweigh the honest chain. With `perasWeight = 15` and a chain of modest length, a small number of crafted certificates suffices.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real one that verifies:
1. The certificate carries a valid aggregate signature from a quorum of eligible committee members for the claimed round.
2. The committee membership and stake weights are derived from the ledger state at the relevant epoch boundary, not from attacker-supplied data.
3. The `vpcCertBoost` is derived from the verified quorum stake, not blindly set to `perasWeight params`.

Until real validation is implemented, inbound certificates from peers should be rejected entirely rather than accepted unconditionally.

---

### Proof of Concept

1. Attacker connects to a victim node via the Peras object diffusion mini-protocol.
2. Attacker constructs `PerasCert { pcCertRound = r, pcCertBoostedBlock = adversarialBlockPoint }` for successive round numbers `r = 0, 1, 2, ...`.
3. Each certificate is sent to the victim. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = PerasWeight 15 }` unconditionally.
4. Each accepted certificate is stored in `PerasCertDB` and triggers `chainSelectionForBlock` for `adversarialBlockPoint`.
5. After `ceil(honest_chain_length / 15)` certificates, the adversarial fork's total weight (`blockNo + 15 * numCerts`) exceeds the honest chain's weight (`blockNo`), and the node switches to the adversarial fork. [7](#0-6) [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L320-358)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L103-103)
```haskell
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L126-126)
```haskell
          (validatePerasCert mkPerasParams)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L156-173)
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
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L531-531)
```haskell
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L58-61)
```haskell
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv
```
