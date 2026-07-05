### Title
Peras Certificate Validation Unconditionally Accepts Any Peer-Supplied Certificate, Enabling Unauthorized Chain Boost - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

---

### Summary

The degenerate `BlockSupportsPeras` instance used for all block types implements `validatePerasCert` as an unconditional `Right`, accepting every inbound Peras certificate without checking committee membership, aggregate BLS signature, or any other validity criterion. An unprivileged peer can send a crafted `PerasCert` for any block, which is stored in the `PerasCertDB` with a full Peras boost weight and used in chain selection, allowing the peer to make an honest node prefer a non-canonical chain.

---

### Finding Description

The `BlockSupportsPeras` typeclass defines `validatePerasCert` as the mandatory gate before a certificate is stored and used in chain selection. The catch-all instance covering all block types implements it as:

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

This is the **only** instance in the codebase — there is no more-specific override for Cardano block types. The instance is explicitly marked as a degenerate placeholder to make the code compile, but it is wired directly into the production inbound certificate processing path.

`makePerasCertPoolWriterFromChainDB` (the production writer used when the ChainDB handles chain-selection side-effects) passes this stub directly as the `validateCert` argument:

```haskell
(validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
``` [2](#0-1) 

`processCerts` then accepts every certificate that is not already in the DB:

```haskell
case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
  ([], validatedCerts) ->
    mapM_ (addCert . WithArrivalTime now) validatedCerts
``` [3](#0-2) 

The accepted `ValidatedPerasCert` carries `vpcCertBoost = perasWeight params`, which is the full Peras chain-selection weight. This value is used downstream to boost the certified block during chain selection, making the node prefer it over competing chains.

The same pattern applies to `validatePerasVote`: the degenerate instance only checks that the voter appears in the stake distribution but skips signature verification, committee membership, and VRF eligibility proof entirely:

```haskell
validatePerasVote _params stakeDistr vote
  | Just stake <- lookupPerasVoteStake vote stakeDistr =
      Right ValidatedPerasVote { vpvVote = vote, vpvVoteStake = stake }
  | otherwise = Left PerasValidationErr
``` [4](#0-3) 

The `implAddVote` function in `PerasVoteDB.Impl` also carries an explicit TODO acknowledging that non-trivial validation logic is missing:

```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
``` [5](#0-4) 

---

### Impact Explanation

A `ValidatedPerasCert` produced by the stub carries the full `perasWeight` boost. Once stored in the `PerasCertDB` and surfaced to chain selection, it causes the node to prefer the certified block over competing tips. An attacker who can inject one crafted certificate per Peras round can continuously steer an honest node's chain-selection toward an attacker-chosen fork, constituting a chain-selection safety failure reachable by an unprivileged peer.

For votes: any pool with non-zero stake can cast votes for arbitrary blocks in arbitrary rounds without a valid BLS signature or VRF eligibility proof. Enough such votes accumulate into a locally-forged certificate (via `updatePerasRoundVoteStates`), which is then used in chain selection with the same boost weight.

**Impact class:** High — chain-selection bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended Peras security assumptions. Also qualifies as Critical under the bypass-of-Peras-certificate-checks criterion.

---

### Likelihood Explanation

The object-diffusion mini-protocol for Peras certificates is reachable by any connected peer without authentication. The attacker only needs to send a well-formed `PerasCert` CBOR message (round number + block hash + voters map + aggregate signature field — the signature is never checked). No stake, no keys, and no prior registration are required. The degenerate instance is the only instance in the codebase, so every deployed node is affected.

---

### Recommendation

1. Implement `validatePerasCert` to verify the aggregate BLS signature against the claimed committee members and their keys, using the `implVerifyCert` logic already present in `WFALS.hs` and `EveryoneVotes.hs`.
2. Implement `validatePerasVote` to verify the BLS vote signature and, for non-persistent members, the VRF eligibility proof, mirroring `implVerifyVote` in `WFALS.hs`.
3. Remove the catch-all `instance StandardHash blk => BlockSupportsPeras blk` once proper per-era instances are in place, so the compiler enforces that no block type silently falls back to the no-op stub.
4. Track resolution of issue `tweag/cardano-peras#120` as a security-critical milestone before enabling the Peras object-diffusion mini-protocol on any network that enforces Peras chain-selection rules.

---

### Proof of Concept

**Certificate injection (no keys required):**

1. Connect to a target node as a peer via the object-diffusion mini-protocol.
2. Construct a `PerasCert` with:
   - `pcCertRound` = current Peras round
   - `pcCertBoostedBlock` = hash of any block on a minority fork
   - Any syntactically valid voters map and aggregate signature bytes (content is never checked)
3. Send the certificate batch to the node.
4. `processCerts` calls `validatePerasCert mkPerasParams cert`, which returns `Right ValidatedPerasCert{..., vpcCertBoost = perasWeight params}` unconditionally.
5. The certificate is stored in `PerasCertDB` and the boosted block is preferred in chain selection.

**Vote injection leading to local certificate forging:**

1. Connect as a peer and send `PerasVote` messages for a target block, using any `PerasVoterId` that appears in the current stake distribution (publicly known from the ledger).
2. `validatePerasVote` accepts each vote (stake lookup succeeds; no signature check).
3. `updatePerasRoundVoteStates` accumulates stake; once the quorum threshold is crossed, `forgePerasCert` produces a `ValidatedPerasCert` locally.
4. This locally-forged certificate boosts the attacker's chosen block in chain selection. [6](#0-5) [7](#0-6)

### Citations

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L360-371)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L168-173)
```haskell
  case partitionEithers (validateCert <$> certsNotAlreadyInDb) of
    -- All certs are valid => add them to the pool
    ([], validatedCerts) ->
      mapM_
        (addCert . WithArrivalTime now)
        validatedCerts
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasVoteDB/Impl.hs (L172-173)
```haskell
-- TODO: we will need to update this method with non-trivial validation logic
-- see https://github.com/tweag/cardano-peras/issues/120
```

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasVote.hs (L122-148)
```haskell
makePerasVotePoolWriterFromChainDB ::
  (StandardHash blk, IOLike m) =>
  SystemTime m ->
  -- | This is needed for validating votes (since its during the validation of
  -- votes that we give them a verified weight. In the future, we won't read it
  -- from the stake distr directly, but rather use the committee selection data)
  STM m PerasVoteStakeDistr ->
  ChainDB m blk ->
  ObjectPoolWriter (PerasVoteId blk) (PerasVote blk) m
makePerasVotePoolWriterFromChainDB systemTime getStakeDistrSTM chainDB =
  ObjectPoolWriter
    { opwObjectId = getPerasVoteId
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
