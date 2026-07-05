### Title
Peras Certificate and Vote Validation Bypass via Stub `validatePerasCert`/`validatePerasVote` — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary

The production `BlockSupportsPeras` instance for all `StandardHash blk` blocks implements `validatePerasCert` as an unconditional `Right` (always-accept stub) and `validatePerasVote` with no cryptographic signature check. Both functions are called on every inbound Peras certificate and vote received from an unprivileged peer via the ObjectDiffusion mini-protocol. Because no real authorization or cryptographic check is enforced, any peer can inject arbitrary certificates or forge votes for any eligible voter ID, directly influencing chain selection by boosting arbitrary blocks.

### Finding Description

**Root cause — `validatePerasCert` always accepts:**

In `SupportsPeras.hs`, the only `BlockSupportsPeras` instance (the catch-all for `StandardHash blk`) implements `validatePerasCert` as:

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

This unconditionally returns `Right` for every certificate, regardless of content. [1](#0-0) 

**Root cause — `validatePerasVote` has no signature verification:**

The `PerasVote blk` data type carries only `pvVoteRound`, `pvVoteBlock`, and `pvVoteVoterId` — no cryptographic signature field exists. [2](#0-1) 

`validatePerasVote` only checks whether the voter ID appears in the stake distribution map — it performs no signature verification:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [3](#0-2) 

**Attacker-controlled entry path:**

The ObjectDiffusion mini-protocol inbound handler for Peras certificates calls `processCerts`, which invokes `validatePerasCert mkPerasParams` on every peer-supplied certificate. Because `validatePerasCert` always returns `Right`, every certificate passes and is forwarded to `ChainDB.addPerasCertAsync`: [4](#0-3) 

The `processCerts` function in the inbound handler confirms this path — it calls `validateCert` (bound to `validatePerasCert mkPerasParams`) and only rejects if the result is `Left`. Since the stub always returns `Right`, no certificate is ever rejected: [5](#0-4) 

Similarly, the vote inbound handler calls `validatePerasVote mkPerasParams sd vote` for each peer-supplied vote. Since voter IDs are public (stake pool key hashes), an attacker can forge votes for any eligible voter without possessing the private key: [6](#0-5) 

Once enough forged votes accumulate to reach quorum, `addPerasVoteWithAsyncCertHandling` triggers certificate generation and `addPerasCertAsync` is called, which can trigger a chain selection switch: [7](#0-6) 

### Impact Explanation

**Impact: High — Chain selection manipulation by an unprivileged peer.**

A `ValidatedPerasCert` carries a `vpcCertBoost` weight that is applied to the boosted block during chain selection. By injecting a certificate that boosts an arbitrary block, an attacker causes the node to assign a Peras weight advantage to a block of the attacker's choosing. If the boosted block is on a minority or adversarial fork, the node may switch away from the canonical chain, violating chain selection safety. This matches the allowed impact category: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."* [8](#0-7) 

### Likelihood Explanation

**Likelihood: High.** The ObjectDiffusion mini-protocol is a standard peer-to-peer channel. Any node that connects as a peer can send crafted `PerasCert` or `PerasVote` messages. No privileged keys, stake majority, or operator compromise is required. The voter IDs used in vote forgery are public (stake pool key hashes visible on-chain). The stub validation is the only gating check before the certificate reaches `addPerasCertAsync` and influences chain selection. [9](#0-8) 

### Recommendation

1. **`validatePerasCert`**: Replace the stub with a real implementation that verifies the certificate's cryptographic proof of committee quorum (BLS aggregate signature or equivalent), checks that the boosted block is on a valid chain, and validates the round number against the current epoch state. The `PerasBLSCrypto` module already provides `verifyVoteSignature` infrastructure that should be wired in. [10](#0-9) 

2. **`validatePerasVote`**: Add a signature field to `PerasVote blk` and verify it in `validatePerasVote` before accepting the vote. Membership in the stake distribution is a necessary but not sufficient condition — the voter must prove possession of the corresponding private key.

3. **Do not deploy Peras certificate/vote diffusion in production** until the TODO items tracked in `https://github.com/tweag/cardano-peras/issues/120` are resolved and the stub instance is replaced with a fully validated implementation. [11](#0-10) 

### Proof of Concept

**Preconditions:** Attacker is an unprivileged peer connected to a victim node via the ObjectDiffusion mini-protocol. Peras is active.

**Steps:**

1. Attacker observes the current chain tip and identifies a target block `B'` on a minority fork they wish to boost.
2. Attacker constructs a `PerasCert` with `pcCertRound = <current round>` and `pcCertBoostedBlock = blockPoint B'`.
3. Attacker sends this certificate to the victim node via the ObjectDiffusion inbound channel.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }` unconditionally.
5. The certificate is passed to `ChainDB.addPerasCertAsync`, which stores it and triggers chain selection.
6. Chain selection now applies the Peras weight boost to `B'`. If `B'`'s boosted weight exceeds the current selection's weight, the node switches to the fork containing `B'`.

**For vote forgery leading to certificate generation:**

1. Attacker queries the public stake distribution to enumerate eligible voter IDs.
2. Attacker constructs `PerasVote` messages for enough voter IDs to exceed the quorum threshold, all targeting block `B'`.
3. `validatePerasVote` accepts each vote (voter ID is in the stake distribution; no signature check).
4. Once quorum is reached, `addPerasVoteWithAsyncCertHandling` forges a certificate and calls `addPerasCertAsync`, triggering the same chain selection manipulation as above. [12](#0-11)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L207-212)
```haskell
data ValidatedPerasCert blk = ValidatedPerasCert
  { vpcCert :: !(PerasCert blk)
  , vpcCertBoost :: !PerasWeight
  }
  deriving stock (Show, Eq, Ord, Generic)
  deriving anyclass NoThunks
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-320)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L330-336)
```haskell
  data PerasVote blk = PerasVote
    { pvVoteRound :: PerasRoundNo
    , pvVoteBlock :: Point blk
    , pvVoteVoterId :: PerasVoterId
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L146-155)
```haskell
-- | Process a batch of inbound Peras certificates received from a peer.
--
-- Certificates whose round number is already present in the database (as
-- determined by @alreadyInDbSTM@) are silently skipped. The remaining
-- certificates are validated; if /any/ certificate in the batch fails
-- validation, the entire batch is rejected by throwing a
-- 'PerasCertInboundException' (which should make us disconnect from the distant
-- peer, see 'withPeer' bracket function from `ouroboros-network`). Otherwise,
-- each valid certificate is timestamped with the current wall-clock time and
-- added to the database via @addCert@.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L134-148)
```haskell
    , opwAddObjects = \votes ->
        processVotes
          systemTime
          (ChainDB.getPerasVoteIds chainDB)
          -- TODO: in the future we won't need just the stake distribution for
          -- validating votes, but also the whole committee selection context
          -- (containing vote weights of committee members = voters)
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          -- We do not want to block the writer thread on waiting for ChainSel
          -- side-effects to complete, so we use the async version of adding
          -- votes to the ChainDB and ignore the returned promise.
          -- The async action (if any) is still launched and executed behind the
          -- scenes even though we drop the promise.
          (void . ChainDB.addPerasVoteWithAsyncCertHandling chainDB)
          votes
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/API.hs (L441-459)
```haskell
  , addPerasCertAsync :: WithArrivalTime (ValidatedPerasCert blk) -> m (AddPerasCertPromise m)
  -- ^ Asynchronously insert a certificate to the DB. If this leads to a fork to
  -- be weightier than our current selection, this will trigger a fork switch.
  , getPerasCertsAfter ::
      PerasCertTicketNo ->
      STM m (Map PerasCertTicketNo (m (WithArrivalTime (ValidatedPerasCert blk))))
  -- ^ Get all known Peras certs with a ticket number strictly greater than the
  -- given one, in ascending order. The values are 'm' actions to allow
  -- implementations with on-disk storage.
  , getPerasCertIds :: STM m (Set PerasRoundNo)
  -- ^ Get the set of all Peras certificate round numbers currently in the
  -- database.
  , addPerasVoteWithAsyncCertHandling ::
      WithArrivalTime (ValidatedPerasVote blk) ->
      m (AddPerasVoteResult blk, Maybe (AddPerasCertPromise m))
  -- ^ Add a Peras vote to the vote database, returning the result of the
  -- vote addition. If a certificate is produced in the process (quorum
  -- reached), it will be added via 'addPerasCertAsync' under the hood, in
  -- which case the corresponding promise will be returned.
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/ChainDB/Impl/ChainSel.hs (L237-245)
```haskell
    chainSelection' curChain candidates =
      assert (all ((curpt ==) . castPoint . AF.anchorPoint . fst) candidates) $
        assert (all (shouldSwitch . preferAnchoredCandidate bcfg weights curChain . fst) candidates) $ do
          cse <- chainSelEnv
          fmap (getSuffix . fst)
            <$> chainSelection
              cse
              (first Diff.extend <$> candidates)
              (\_ _ -> MkSuccessForkerAction $ join . atomically . forkerCommit)
```
