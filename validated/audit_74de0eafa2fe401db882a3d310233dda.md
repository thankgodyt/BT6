### Title
Peras Certificate Validation Unconditionally Accepts All Inbound Certificates Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance's `validatePerasCert` implementation unconditionally returns `Right` (success) for every inbound certificate, performing zero cryptographic or structural validation. This stub is wired directly into the live certificate diffusion pipeline. Any unprivileged peer can inject arbitrary `PerasCert` objects that the local node will accept, store in `PerasCertDB`, and use to influence Peras chain selection (boosting), bypassing the quorum and signature requirements that are the entire security basis of the Peras protocol.

### Finding Description

**Root cause — `validatePerasCert` is a no-op stub in production code**

The universal `BlockSupportsPeras` instance, which is the only instance in the codebase, implements `validatePerasCert` as:

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

This function accepts `params` and `cert` and unconditionally wraps the raw, unverified certificate in `Right ValidatedPerasCert`. No signature is checked, no quorum proof is verified, no committee membership is confirmed.

**The stub is wired into the live inbound certificate pipeline**

`makePerasCertPoolWriterFromChainDB` — the production writer used when the ChainDB is the backing store — calls `validatePerasCert mkPerasParams` directly on every certificate received from a peer:

```haskell
(validatePerasCert mkPerasParams)
-- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` then calls this validator on every new certificate from a peer and, if it returns `Right`, timestamps it and adds it to the database: [3](#0-2) 

**The accepted certificate influences chain selection**

Once a `ValidatedPerasCert` is stored in `PerasCertDB`, it is used by chain selection to apply a Peras boost (`vpcCertBoost = perasWeight params = 15`) to the boosted block. The `addPerasCert` path in the ChainDB model confirms that a stored certificate immediately triggers `chainSelection`: [4](#0-3) 

**The same pattern applies to vote validation**

`validatePerasVote` also skips all cryptographic checks — it only looks up the voter in the stake distribution map, ignoring any signature on the vote: [5](#0-4) 

Both pool writers (`makePerasVotePoolWriterFromVoteDB` and `makePerasVotePoolWriterFromChainDB`) call `validatePerasVote mkPerasParams` with the same hardcoded params: [6](#0-5) 

### Impact Explanation

**Impact: Critical — Bypass of Peras certificate/vote verification enabling unauthorized certificate acceptance and chain selection manipulation.**

An attacker who can connect as a peer (no stake, no keys required) can:

1. Craft a `PerasCert` for any block point and any round number.
2. Send it via the ObjectDiffusion mini-protocol.
3. The receiving node calls `validatePerasCert mkPerasParams cert`, which returns `Right` unconditionally.
4. The certificate is stored in `PerasCertDB` with `vpcCertBoost = 15`.
5. Chain selection applies the boost to the attacker-chosen block, potentially causing the honest node to prefer a non-canonical chain.

This directly violates the Peras security invariant: a certificate is supposed to represent a quorum of stake-weighted votes with valid BLS signatures. The stub removes that guarantee entirely. The attacker can boost any block — including a minority fork — without holding any stake or keys.

The `stakeAboveThreshold` quorum check in `votesReachQuorum` is also rendered irrelevant for the certificate path, since `validatePerasCert` bypasses it entirely. [7](#0-6) 

### Likelihood Explanation

**High.** The attack requires only a standard peer connection — no stake, no keys, no privileged access. The ObjectDiffusion mini-protocol for Peras certificates is part of the production diffusion layer. The code path from peer message to `PerasCertDB` insertion is short and fully wired. The only precondition is that the Peras feature flag is enabled on the target node. Given that the diffusion infrastructure is already present and the TODO comments indicate this is known-incomplete rather than intentionally disabled, the risk materialises as soon as Peras is activated.

### Recommendation

Replace the stub `validatePerasCert` implementation with actual cryptographic validation before the Peras certificate diffusion path is enabled in production. Specifically:

1. Verify the BLS aggregate signature over the certificate's `(roundNo, boostedBlock)` payload against the aggregate public key of the claimed committee members.
2. Verify each voter's VRF output to confirm committee membership for the given round.
3. Verify that the total stake of the committee members exceeds `perasQuorumStakeThreshold + perasQuorumStakeThresholdSafetyMargin`.
4. Until the full validation is implemented, gate the certificate diffusion path behind a feature flag that is disabled by default, or add a hard `error`/`Left` in `validatePerasCert` so that no certificate can be accepted in the interim.

The same applies to `validatePerasVote`: add BLS signature verification before accepting votes from peers. [8](#0-7) 

### Proof of Concept

**Setup**: A private testnet with Peras certificate diffusion enabled. Attacker node connects as a standard peer.

**Steps**:

1. Attacker constructs a `PerasCert` targeting a minority-fork block `B_adv` at round `r`:
   ```
   PerasCert { pcCertRound = r, pcCertBoostedBlock = blockPoint B_adv }
   ```
2. Attacker sends this certificate to the honest node via the ObjectDiffusion mini-protocol.
3. On the honest node, `processCerts` is called:
   - `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = 15 }`
   - Certificate is stored in `PerasCertDB`.
4. Chain selection runs; `B_adv` now carries a boost of weight 15.
5. If `B_adv`'s chain weight + 15 exceeds the honest chain's weight, the honest node switches to the adversarial fork.

**Expected (correct) behaviour**: `validatePerasCert` returns `Left PerasValidationErr` because no valid BLS aggregate signature or VRF proofs were provided.

**Actual behaviour**: `validatePerasCert` returns `Right`, the certificate is accepted, and the boost is applied to the attacker-chosen block.

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L162-173)
```haskell
stakeAboveThreshold :: PerasParams -> PerasVoteStake -> Bool
stakeAboveThreshold params voteStake =
  stake >= quorumThreshold + safetyMargin
 where
  stake =
    unPerasVoteStake voteStake
  quorumThreshold =
    unPerasQuorumStakeThreshold
      (perasQuorumStakeThreshold params)
  safetyMargin =
    unPerasQuorumStakeThresholdSafetyMargin
      (perasQuorumStakeThresholdSafetyMargin params)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-389)
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

  -- TODO: extract actual Peras certificates from blocks when the HFC plumbing
  -- is in place.
  getPerasCertInBlock _ = Nothing
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

**File:** ouroboros-consensus/test/storage-test/Test/Ouroboros/Storage/ChainDB/Model.hs (L460-472)
```haskell
addPerasCert ::
  forall blk.
  (LedgerSupportsProtocol blk, LedgerTablesAreTrivial ExtLedgerState blk) =>
  TopLevelConfig blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  Model blk ->
  (AddPerasCertChainSelOutcome, Model blk)
addPerasCert cfg cert m
  | pointSlot (getPerasCertBoostedBlock cert) < Chain.headSlot (immutableChain secParam m) =
      (PerasCertIgnoredTooOld, m)
  | otherwise =
      let (certRes, perasCertModel') = PerasCertDBModel.addCert (perasCertModel m) cert
       in (PerasCertProcessed certRes, chainSelection cfg m{perasCertModel = perasCertModel'})
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L101-117)
```haskell
makePerasVotePoolWriterFromVoteDB systemTime getStakeDistrSTM perasVoteDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (PerasVoteDB.getVoteIds perasVoteDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
          votes
    , opwHasObject = do
        voteIds <- PerasVoteDB.getVoteIds perasVoteDB
        pure $ \voteId -> Set.member voteId voteIds
    }
```
