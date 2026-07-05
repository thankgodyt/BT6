### Title
Unconditional `validatePerasCert` Acceptance Enables Forged Peras Certificate Injection and Chain-Selection Manipulation - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The sole production instance of `BlockSupportsPeras` implements `validatePerasCert` as an unconditional `Right` — it accepts every inbound certificate without performing any cryptographic or quorum check. A malicious peer can therefore inject a certificate for any block it chooses via the object-diffusion mini-protocol. Because accepted certificates are fed directly into chain selection and increase the Peras weight of the targeted block, the attacker can make an honest node prefer an adversarial fork over the canonical chain whenever Peras is enabled.

---

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub wired into the live inbound path.**

`ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs` defines the only `BlockSupportsPeras` instance (the `StandardHash blk =>` catch-all). Its `validatePerasCert` implementation is:

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

No signature, committee-membership, or quorum check is performed. Every `PerasCert` value, regardless of content, is wrapped in `Right ValidatedPerasCert` and returned as valid.

**Inbound path — the stub is called for every certificate received from a peer.**

`makePerasCertPoolWriterFromChainDB` in `ObjectPool/PerasCert.hs` passes this stub directly as the validator for all inbound certificates:

```haskell
(validatePerasCert mkPerasParams)   -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` then calls this validator on every certificate not already in the DB, and on success adds each one via `addPerasCertAsync`: [3](#0-2) 

**Chain-selection consequence — accepted certificates alter fragment weight.**

`chainSelSync` processes each accepted certificate by calling `chainSelectionForBlock` for the boosted block: [4](#0-3) 

`preferAnchoredCandidate` then compares fragments using `weightedSelectView`, which sums block number and the Peras weight boost from the `PerasWeightSnapshot`: [5](#0-4) 

A forged certificate adds `perasWeight params` to the total weight of the targeted chain suffix, potentially making an adversarial fork heavier than the honest chain.

**Structural analog to the MerkleDB bug.**

The MerkleDB bug allowed a prover to omit the bottom of the proof path; the verifier reconstructed only the upper trie, which still matched the root hash, so the exclusion proof passed. Here, the "verifier" (`validatePerasCert`) reconstructs nothing at all — it simply echoes the certificate back as valid. Both bugs share the same class: a verification function that is supposed to check the completeness/authenticity of a proof/certificate but instead unconditionally accepts any input.

---

### Impact Explanation

When Peras is enabled, any unprivileged peer can:

1. Craft a `PerasCert` naming any block as the boosted block (e.g., the tip of an adversarial fork).
2. Send it over the object-diffusion mini-protocol.
3. The certificate passes `validatePerasCert` unconditionally and is stored in the `PerasCertDB`.
4. Chain selection is re-run for the boosted block with the forged weight boost applied.
5. If the boost is large enough, the node switches to the adversarial fork.

This is a **Critical** bypass of Peras certificate/vote verification that enables unauthorized certificate acceptance and a resulting chain-selection safety failure: an honest node can be made to prefer a non-canonical chain constructed by an unprivileged attacker.

---

### Likelihood Explanation

Peras is disabled by default and not yet deployed on mainnet, which limits immediate exposure. However, the production code path is fully wired: `makePerasCertPoolWriterFromChainDB` is the live writer used by the node kernel, and the stub validator is already in place. Any operator or testnet participant who enables Peras is immediately vulnerable. The attack requires only a network connection — no keys, no stake, no privileged access.

---

### Recommendation

Replace the stub `validatePerasCert` implementation with a real check that verifies:

1. Each vote in the certificate carries a valid cryptographic signature from the claimed voter.
2. Each voter was legitimately elected to the voting committee for the claimed round (via the committee-selection mechanism, e.g., WFALS or EveryoneVotes).
3. The aggregate stake of the verified voters meets the quorum threshold defined in `PerasCfg`.

Until this is implemented, the object-diffusion inbound path for Peras certificates must not be enabled in any environment where an adversarial peer can connect.

---

### Proof of Concept

```
1. Enable Peras on a private testnet (set eraPerasRoundLength in EraParams).
2. Start an honest target node N.
3. Start an adversarial node A that shares a common prefix with N but has a
   shorter fork F diverging at block B.
4. A constructs a PerasCert:
       PerasCert { pcCertRound = <current round>
                 , pcCertBoostedBlock = <tip of fork F> }
   No valid votes, no signatures — the struct is arbitrary.
5. A sends this PerasCert to N via the object-diffusion mini-protocol.
6. N calls processCerts → validatePerasCert → Right (unconditional).
7. N stores the cert and calls chainSelSync (ChainSelAddPerasCert).
8. chainSelectionForBlock is triggered for the tip of F.
9. preferAnchoredCandidate computes weightedSelectView for F's suffix;
   wsvWeightBoost now includes perasWeight params from the forged cert.
10. If perasWeight params > (honest chain length - fork F length),
    N switches to fork F — chain-selection safety failure.
``` [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L483-532)
```haskell
chainSelSync cdb@CDB{..} (ChainSelAddPerasCert cert varProcessed) = do
  curChain <- lift $ atomically $ Query.getCurrentChain cdb
  let immTip = AF.castAnchor $ AF.anchor curChain

  certResult <- withEarlyExitId $ do
    -- Ignore the certificate if it boosts a block that is so old that it can't
    -- influence our selection.
    when (pointSlot boostedBlock < AF.anchorToSlotNo immTip) $ do
      lift $ lift $ traceWith tracer $ IgnorePerasCertTooOld certRound boostedBlock immTip
      idExitEarly PerasCertIgnoredTooOld

    -- Add the certificate to the PerasCertDB.
    certRes <- lift $ lift $ join $ atomically $ PerasCertDB.addCert cdbPerasCertDB cert
    -- Here:
    -- \* if the certificate is already in the PerasCertDB, we exit early with that result
    -- \* if the certificate is newly added to the PerasCertDB, we bind  the result value that we will return in any of the branches below
    addedCertRes <-
      case certRes of
        PerasCertDB.PerasCertAlreadyInDB -> idExitEarly $ PerasCertProcessed PerasCertDB.PerasCertAlreadyInDB
        PerasCertDB.AddedPerasCertToDB -> pure $ PerasCertProcessed PerasCertDB.AddedPerasCertToDB

    -- If the certificate boosts a block on our current chain (including the
    -- anchor), then it just makes our selection even stronger.
    when (AF.withinFragmentBounds (castPoint boostedBlock) curChain) $ do
      lift $ lift $ traceWith tracer $ PerasCertBoostsCurrentChain certRound boostedBlock
      idExitEarly $ addedCertRes

    boostedHash <- case pointHash boostedBlock of
      -- If the certificate boosts the Genesis point, then it can not influence
      -- chain selection as all chains contain it.
      GenesisHash -> do
        lift $ lift $ traceWith tracer $ PerasCertBoostsGenesis certRound
        idExitEarly $ addedCertRes
      -- Otherwise, the certificate boosts a block potentially on a (future)
      -- candidate.
      BlockHash boostedHash -> pure boostedHash
    boostedHdr <-
      lift (lift $ VolatileDB.getBlockComponent cdbVolatileDB GetHeader boostedHash) >>= \case
        -- If we have not (yet) received the boosted block, we don't need to do
        -- anything further for now regarding chain selection. Once we receive
        -- it, the additional weight of the certificate is taken into account.
        Nothing -> do
          lift $ lift $ traceWith tracer $ PerasCertBoostsBlockNotYetReceived certRound boostedBlock
          idExitEarly $ addedCertRes
        Just boostedHdr -> pure boostedHdr

    -- Trigger chain selection for the boosted block.
    lift $ lift $ traceWith tracer $ ChainSelectionForBoostedBlock certRound boostedBlock
    lift $ chainSelectionForBlock cdb BlockCache.empty boostedHdr noPunishment
    pure $ addedCertRes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/SelectView.hs (L57-68)
```haskell
-- | The total weight, ie the sum of 'wsvBlockNo' and 'wsvBoostedWeight'.
wsvTotalWeight :: WeightedSelectView proto -> PerasWeight
-- could be cached, but then we need to be careful to maintain the invariant
wsvTotalWeight wsv =
  PerasWeight (unBlockNo (wsvBlockNo wsv)) <> wsvWeightBoost wsv

instance Ord (TiebreakerView proto) => Ord (WeightedSelectView proto) where
  compare =
    mconcat
      [ compare `on` wsvTotalWeight
      , compare `on` wsvTiebreaker
      ]
```
