### Title
Unconditional Peras Certificate Acceptance via Missing Cryptographic Validation in Network-Reachable Handler — (`File: ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as an unconditional `Right`, meaning any Peras certificate received over the `PerasCertDiffusion` miniprotocol from any unprivileged peer is accepted without any cryptographic verification. An attacker can inject a crafted certificate boosting an arbitrary block, causing chain selection to apply an illegitimate weight boost and potentially prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` class defines `validatePerasCert` as the hook for verifying that a received Peras certificate carries a valid aggregate BLS signature from a quorum of eligible committee members. The degenerate instance — explicitly marked as a placeholder to make the code compile — implements this as an unconditional success:

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

This instance is the only one in the codebase — there is no overriding instance for `CardanoBlock` or any Shelley-era block. It is therefore the instance used in production.

The production network path that calls this function is:

1. **`makePerasCertPoolWriterFromChainDB`** constructs the inbound pool writer for the `PerasCertDiffusion` miniprotocol, passing `validatePerasCert mkPerasParams` as the validation function: [2](#0-1) 

2. **`processCerts`** is the inbound batch handler. It calls `validateCert` (bound to `validatePerasCert mkPerasParams`) on every certificate received from a peer. Because `validatePerasCert` always returns `Right`, the `([], validatedCerts)` branch is always taken and every certificate is unconditionally added to the database: [3](#0-2) 

3. **`hPerasCertDiffusionClient`** in the node-to-node handler wires `makePerasCertPoolWriterFromChainDB` directly into the live network stack, making this reachable by any connecting peer: [4](#0-3) 

4. Accepted certificates are forwarded to `ChainDB.addPerasCertAsync`, which triggers chain selection with the fraudulent certificate's weight boost applied.

The `validatePerasCert` contract, as defined by the `BlockSupportsPeras` class, is supposed to verify:
- The aggregate BLS signature over the election identifier and boosted block hash
- That the claimed voters are eligible committee members with sufficient combined stake to constitute a quorum [5](#0-4) 

None of these checks are performed. The concrete BLS-based verification logic exists in `WFALS.hs` and `EveryoneVotes.hs` but is never invoked on the inbound network path. [6](#0-5) 

---

### Impact Explanation

Peras certificates provide a weight boost (`perasWeight`) to a specific block at a specific round. Chain selection in the Peras-extended protocol uses `WeightedSelectView` to prefer chains whose boosted blocks accumulate more certificate weight. By injecting a certificate that boosts an adversarial block, an attacker causes the local node's chain selection to assign that block an illegitimate weight advantage, potentially making the node prefer a non-canonical chain over the honest chain. This is a bypass of Peras certificate verification that enables unauthorized certificate acceptance and chain selection manipulation.

**Impact class: Critical** — Bypass of Peras certificate checks that enables unauthorized certificate acceptance and chain selection divergence from the honest chain.

---

### Likelihood Explanation

The `PerasCertDiffusion` miniprotocol is a standard node-to-node miniprotocol, reachable by any peer that can establish a connection to the node. No authentication, stake ownership, or prior relationship is required. The attacker only needs to connect and send a well-formed CBOR-encoded `PerasCert` message with an arbitrary `pcCertRound` and `pcCertBoostedBlock`. The degenerate `validatePerasCert` stub is the only instance in the codebase, so there is no fallback validation. Likelihood is **High** for any deployment where the `PerasCertDiffusion` miniprotocol is enabled.

---

### Recommendation

Replace the degenerate `validatePerasCert` stub with a real implementation that:
1. Verifies the aggregate BLS signature over `(electionId, boostedBlockHash)` using the aggregated vote verification keys of the claimed voters.
2. Checks that each claimed voter is an eligible committee member (persistent or non-persistent) with a valid VRF output (for non-persistent members).
3. Confirms that the combined stake of the verified voters meets the quorum threshold.

The cryptographic primitives for this already exist in `Ouroboros.Consensus.Committee.WFALS` (`implVerifyCert`) and `Ouroboros.Consensus.Committee.EveryoneVotes` (`implVerifyCert`). The fix is to wire the appropriate committee-specific `implVerifyCert` into the `BlockSupportsPeras` instance for `CardanoBlock` rather than using the degenerate stub. [7](#0-6) 

---

### Proof of Concept

```haskell
-- Attacker constructs a PerasCert boosting an adversarial block
-- No BLS key material, no committee membership, no quorum needed.
let fakeCert = PerasCert
      { pcCertRound      = PerasRoundNo 42          -- any round
      , pcCertBoostedBlock = adversarialBlockPoint   -- any block point
      , pcVoters         = PerasCertVoters mempty    -- empty voter set
      , pcSignature      = emptyAggSig               -- garbage signature
      }

-- Send fakeCert via the PerasCertDiffusion miniprotocol to the target node.
-- processCerts calls validatePerasCert mkPerasParams fakeCert
-- => always returns Right (ValidatedPerasCert { vpcCert = fakeCert, vpcCertBoost = perasWeight })
-- => cert is stored in PerasCertDB and forwarded to ChainDB.addPerasCertAsync
-- => chain selection applies perasWeight boost to adversarialBlockPoint
```

The attacker connects to the target node's node-to-node port, negotiates the `PerasCertDiffusion` sub-protocol, and sends the crafted certificate. Because `validatePerasCert` is a stub returning `Right` unconditionally, the certificate is accepted, stored, and used to influence chain selection without any cryptographic check. [8](#0-7)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L294-297)
```haskell
  validatePerasCert ::
    PerasCfg blk ->
    PerasCert blk ->
    Either (PerasValidationErr blk) (ValidatedPerasCert blk)
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L118-137)
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
    , opwHasObject = do
        certIds <- ChainDB.getPerasCertIds chainDB
        pure $ \roundNo -> Set.member roundNo certIds
    }
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

**File:** ouroboros-consensus-diffusion/src/ouroboros-consensus-diffusion/Ouroboros/Consensus/Network/NodeToNode.hs (L375-383)
```haskell
      , hPerasCertDiffusionClient = \version controlMessageSTM peer ->
          objectDiffusionInbound
            (contramap (TraceLabelPeer peer) (Node.perasCertDiffusionInboundTracer tracers))
            ( perasCertDiffusionMaxObjectsUnacknowledged miniProtocolParameters
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            , 10 -- TODO: see https://github.com/tweag/cardano-peras/issues/97
            )
            (makePerasCertPoolWriterFromChainDB systemTime getChainDB)
            version
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L484-494)
```haskell
implVerifyCert ::
  forall crypto.
  ( CryptoSupportsAggregateVoteSigning crypto
  , CryptoSupportsBatchVRFVerification crypto
  ) =>
  VotingCommittee crypto WFALS ->
  Cert crypto WFALS ->
  Either
    (VotingCommitteeError crypto WFALS)
    (NE [EligibilityWitness crypto WFALS])
implVerifyCert committee = \case
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Committee/WFALS.hs (L550-562)
```haskell
    -- Verify aggregate signature
    aggVerificationKey <-
      bimap CryptoError id $
        aggregateVoteVerificationKeys
          (Proxy @crypto)
          voteVerificationKeys
    bimap InvalidCertSignature id $
      verifyAggregateVoteSignature
        (Proxy @crypto)
        aggVerificationKey
        electionId
        candidate
        aggSig
```
