### Title
Missing Peras Certificate Validation Allows Unprivileged Peer to Inject Arbitrary Boosted-Block Claims — (`Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The catch-all `BlockSupportsPeras` instance's `validatePerasCert` unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or structural checks. This stub is wired directly into the production certificate pool writers (`makePerasCertPoolWriterFromCertDB`, `makePerasCertPoolWriterFromChainDB`), so any peer can inject a certificate that claims to boost an arbitrary block and have it accepted, stored, and applied to chain selection without any verification.

### Finding Description

**Root cause — always-`Right` validation stub:** [1](#0-0) 

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

The `instance StandardHash blk => BlockSupportsPeras blk` is the only `BlockSupportsPeras` instance in the repository (the TODO comment at line 319 confirms it is a "degenerate instance for all blks to get things to compile"). Every call to `validatePerasCert` therefore resolves to this stub.

**Attacker-controlled entry path — production pool writers:** [2](#0-1) [3](#0-2) 

Both `makePerasCertPoolWriterFromCertDB` and `makePerasCertPoolWriterFromChainDB` pass `(validatePerasCert mkPerasParams)` to `processCerts`. The `processCerts` function receives raw certificates from a remote peer, calls the supplied validator, and — if it returns `Right` — timestamps and stores the certificate: [4](#0-3) 

Because the validator always returns `Right`, every certificate a peer sends is stored unconditionally.

**What a certificate controls:** [5](#0-4) 

The `pcCertBoostedBlock :: Point blk` field is fully attacker-controlled. The boost weight applied is `perasWeight params` — a fixed protocol parameter — so the attacker obtains a full-weight Peras boost for any block hash they choose.

**Analog to the external report:**
The external report's root cause is that `OverlayV1UniswapV3Feed` trusts the pool address supplied by the caller and only partially validates it by calling the pool's own functions. Here, `processCerts` trusts the certificate supplied by the peer and "validates" it by calling a function that unconditionally accepts it. Both cases share the same class: externally-supplied data is accepted after a validation step that cannot reject anything.

### Impact Explanation

A Peras certificate that boosts a block shifts chain selection in favour of that block by `perasWeight` stake-equivalent weight. An unprivileged peer that can inject a certificate pointing to a non-canonical (or even non-existent) block can therefore cause an honest node to prefer a fork over the canonical chain, constituting a chain-selection manipulation attack. This matches the **High** impact category: *"Chain selection, rollback, forecast, genesis, or header-state bug that lets an unprivileged peer make an honest node prefer a non-canonical or less-secure chain beyond the intended security assumptions."*

### Likelihood Explanation

The object-diffusion mini-protocol is open to any connected peer. No stake, keys, or operator privileges are required. The attacker only needs to be a peer of the target node and send a well-formed `PerasCert` CBOR message with an arbitrary `pcCertBoostedBlock`.

### Recommendation

1. Replace the stub `validatePerasCert` with a real implementation that verifies:
   - The aggregate BLS vote signature over `(roundNo, boostedBlock)`.
   - Voter eligibility (VRF proofs for non-persistent voters, seat-index bounds, stake positivity).
   - That `pcCertRound` falls within the current or recent epoch window.
   - That `pcCertBoostedBlock` refers to a known block on a plausible chain.
2. Until real validation is in place, gate `processCerts` so that it rejects all certificates (returns an error) rather than accepting all of them, preventing premature deployment of the stub in a network-facing context.
3. Track the open issue (referenced as `cardano-peras/issues/120` in the TODO comments) and ensure it is resolved before the Peras feature is enabled on any network.

### Proof of Concept

```
1. Attacker connects to a target node as a normal peer via the object-diffusion protocol.

2. Attacker serialises a PerasCert with:
     pcCertRound       = <any valid PerasRoundNo>
     pcCertBoostedBlock = <Point of an attacker-chosen fork block>

3. Attacker sends the certificate batch to the node.

4. processCerts (PerasCert.hs:164-173) calls
     validatePerasCert mkPerasParams cert
   which unconditionally returns
     Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params })

5. The certificate is stored in the PerasCertDB / ChainDB via addCert.

6. Chain selection now sees a Peras boost of weight `perasWeight` on the
   attacker-chosen block, potentially causing the node to prefer the
   attacker's fork over the honest canonical chain.
``` [6](#0-5) [7](#0-6)

### Citations

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs (L319-358)
```haskell
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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/MiniProtocol/ObjectDiffusion/ObjectPool/PerasCert.hs (L99-105)
```haskell
    , opwAddObjects = \certs ->
        processCerts
          systemTime
          (PerasCertDB.getCertIds perasCertDB)
          (validatePerasCert mkPerasParams) -- TODO replace when actual plumbing is in place
          (void . join . atomically . PerasCertDB.addCert perasCertDB)
          certs
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
