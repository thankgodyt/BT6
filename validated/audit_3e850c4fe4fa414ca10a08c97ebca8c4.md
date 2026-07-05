### Title
Peras Certificate Validation Bypass — `validatePerasCert` Unconditionally Accepts All Certificates Without Cryptographic Verification - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The catch-all `BlockSupportsPeras` instance for `StandardHash blk` implements `validatePerasCert` as a function that unconditionally returns `Right` (success) without performing any cryptographic verification. An unprivileged peer can submit arbitrary forged Peras certificates over the network that will be accepted and stored, bypassing all certificate authenticity checks. Because Peras certificates directly influence chain selection by boosting blocks, this allows an adversary to make honest nodes prefer adversarial chains.

---

### Finding Description

In `SupportsPeras.hs`, the degenerate `BlockSupportsPeras` instance (lines 320–389) is declared as a catch-all for all block types:

```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
``` [1](#0-0) 

Within this instance, `validatePerasCert` is implemented as:

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
``` [2](#0-1) 

This function accepts **any** `PerasCert` value unconditionally — no signature check, no round-number bounds check, no boosted-block existence check. The `ValidatedPerasCert` wrapper that downstream code trusts as proof of validity is produced without any actual validation.

Similarly, `validatePerasVote` only checks stake-distribution membership and performs no cryptographic signature verification:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise =
      Left PerasValidationErr
``` [3](#0-2) 

The attacker-controlled entry path runs through `processVotes` in `ObjectPool/PerasVote.hs`, which is called when inbound Peras votes arrive from a peer:

```haskell
(\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
``` [4](#0-3) 

And `validatePerasCert` is called in `ObjectPool/PerasCert.hs` on the analogous inbound-certificate path. Both paths are reachable by any unprivileged peer connected via the Peras mini-protocol.

**Analog to the external report**: The external report describes a signed message that contains no information unique to the sender, allowing any observer to copy and re-submit it to steal credit. Here, the signed message (`hashVoteSignature`) covers only `(roundNo, boostedBlock)` — it does not include the voter's identity — and the certificate validation function performs no verification at all, so a peer can submit a certificate with arbitrary content and have it accepted as if it were legitimately signed by a quorum of committee members. [5](#0-4) 

---

### Impact Explanation

Peras certificates are used to boost blocks during chain selection. A `ValidatedPerasCert` carries a `vpcCertBoost` weight that is added to the boosted block's chain weight. Because `validatePerasCert` produces a `ValidatedPerasCert` for any input, an adversary can:

1. Forge a `PerasCert` pointing to any block (including one on an adversarial fork).
2. Deliver it to an honest node via the Peras certificate diffusion mini-protocol.
3. The node stores it as a validated certificate and applies its boost during chain selection.
4. The honest node may switch to the adversarial chain, constituting a chain-selection safety failure driven by an unprivileged peer with no stake.

This matches the **Critical** allowed impact: *bypass of certificate/vote verification checks that enables unauthorized certificate acceptance*, and the **High** allowed impact: *chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical chain*.

---

### Likelihood Explanation

The degenerate instance is the only `BlockSupportsPeras` instance in the repository (the comment "for all blks to get things to compile" confirms no concrete Cardano-block instance overrides it). Any peer that can open a Peras mini-protocol connection — i.e., any unprivileged network peer — can trigger this path. No key material, stake, or special privilege is required.

---

### Recommendation

1. Implement real cryptographic verification inside `validatePerasCert` using the `WFALS`/`EveryoneVotes` committee verification logic already present in `Committee/WFALS.hs` (`implVerifyCert`) and `Committee/EveryoneVotes.hs`.
2. Implement signature verification inside `validatePerasVote` (analogous to `implVerifyVote`).
3. Until a concrete, verified `BlockSupportsPeras` instance exists for Cardano blocks, gate the Peras mini-protocol behind a feature flag so the degenerate instance is never reachable from production peers.

---

### Proof of Concept

```
1. Attacker connects to an honest node as a standard peer.
2. Attacker constructs a PerasCert { pcCertRound = <any round>, pcCertBoostedBlock = <adversarial block point> }.
3. Attacker sends the certificate via the Peras certificate diffusion mini-protocol.
4. Node calls validatePerasCert, which returns Right ValidatedPerasCert unconditionally.
5. The certificate is stored in the CertDB with its boost weight.
6. On the next chain-selection event, the adversarial block receives the Peras boost and
   may be preferred over the honest tip, causing the node to switch to the adversarial chain.
``` [2](#0-1) [6](#0-5)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L318-322)
```haskell
-- TODO: degenerate instance for all blks to get things to compile
-- see https://github.com/tweag/cardano-peras/issues/73
instance StandardHash blk => BlockSupportsPeras blk where
  type PerasCfg blk = PerasParams

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L362-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L111-112)
```haskell
          (\vote -> getStakeDistrSTM >>= \sd -> pure $ validatePerasVote mkPerasParams sd vote)
          (void . join . atomically . PerasVoteDB.addVote perasVoteDB)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L161-201)
```haskell
-- | Process a batch of inbound Peras votes received from a peer.
--
-- Votes whose ID is already present in the database (as determined by
-- @alreadyInDbSTM@) are silently skipped. The remaining votes are validated;
-- if /any/ vote in the batch fails validation, the entire batch is rejected
-- by throwing a 'PerasVoteInboundException' (which should make us disconnect
-- from the distant peer, see 'withPeer' bracket function from
-- `ouroboros-network`). Otherwise, each valid vote is timestamped with the
-- current wall-clock time and added to the database via @addVote@.
processVotes ::
  MonadSTM m =>
  SystemTime m ->
  STM m (Set (PerasVoteId blk)) ->
  (PerasVote blk -> STM m (Either (PerasValidationErr blk) (ValidatedPerasVote blk))) ->
  (WithArrivalTime (ValidatedPerasVote blk) -> m ()) ->
  [PerasVote blk] ->
  m ()
processVotes systemTime alreadyInDbSTM validateVote addVote votes = do
  validationResults <- atomically $ do
    alreadyInDb <- alreadyInDbSTM
    let votesNotAlreadyInDb = filter (not . (`Set.member` alreadyInDb) . getPerasVoteId) votes
    mapM validateVote votesNotAlreadyInDb
  now <- systemTimeCurrent systemTime
  case partitionEithers validationResults of
    -- All votes are valid => add them to the pool
    ([], validatedVotes) ->
      mapM_
        (addVote . WithArrivalTime now)
        validatedVotes
    -- Some votes are invalid => reject the whole batch
    --
    -- N.B. it has been requested in PR review
    -- https://github.com/IntersectMBO/ouroboros-consensus/pull/1768#discussion_r2747873186
    -- to gather all validation errors and report them together in the exception
    -- rather than just report the first error encountered.
    -- This assumes that vote validation is cheap, which may not be true in
    -- practice depending on the actual crypto/committee selection scheme.
    -- Hence we may revisit this to lazily abort validation upon the first error
    -- encountered.
    (errs, _) ->
      throw (PerasVoteValidationError errs)
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Peras/Crypto/BLS.hs (L91-115)
```haskell
  Hash HASH (SigDSIGN BLS12381MinSigDSIGN)
hashVoteSignature roundNo boostedBlock =
  Hash.castHash
    . Hash.hashWith id
    . runByteBuilder (8 + 8 + 32)
    $ roundNoBytes
      <> boostedBlockSlotBytes
      <> boostedBlockHashBytes
 where
  roundNoBytes =
    BS.word64BE
      . unPerasRoundNo
      $ roundNo
  boostedBlockSlotBytes =
    BS.word64BE
      . unSlotNo
      . bytes32RealPointSlot
      . unPerasBoostedBlock
      $ boostedBlock
  boostedBlockHashBytes =
    BS.byteStringCopy
      . BS.fromShort
      . bytes32RealPointHash
      . unPerasBoostedBlock
      $ boostedBlock
```
