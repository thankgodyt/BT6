### Title
Unconditional Peras Certificate Acceptance Allows Unprivileged Peer to Inject Arbitrary Chain-Boosting Certificates - (File: `ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Block/SupportsPeras.hs`)

### Summary
The universal `BlockSupportsPeras` instance's `validatePerasCert` implementation is a stub that unconditionally returns `Right` for every inbound certificate, performing zero cryptographic or semantic checks. Any unprivileged peer connected via the ObjectDiffusion miniprotocol can send a crafted `PerasCert` naming an arbitrary block as the boosted target for any round, and the certificate will be stored in the `PerasCertDB`/`ChainDB` and applied as a Peras weight boost during chain selection. This is the direct analog of the bridge vulnerability: the inbound handler (`processCerts`) delegates to a trusted validation function that silently accepts all attacker-controlled content, causing fraudulent state to be durably stored and acted upon.

### Finding Description

**Root cause — stub validator always returns `Right`:**

In the universal `BlockSupportsPeras` instance, `validatePerasCert` is:

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

No signature is verified, no committee membership is checked, no quorum is confirmed, no round validity is enforced, and no block existence is required. Every `PerasCert` from any peer is unconditionally promoted to `ValidatedPerasCert`. [1](#0-0) 

**Production inbound path — `processCerts` calls the stub:**

`makePerasCertPoolWriterFromChainDB` (the production writer) passes `validatePerasCert mkPerasParams` directly to `processCerts`:

```haskell
(validatePerasCert mkPerasParams)
``` [2](#0-1) 

`processCerts` filters only by round-number deduplication, then calls `validateCert` on each new cert. Since `validateCert` always returns `Right`, every cert passes and is forwarded to `addPerasCertAsync`: [3](#0-2) 

**Durable storage — cert is written to `PerasCertDB` and triggers chain selection:**

`implAddCert` stores the fraudulent cert in the in-memory `PerasCertDbState` (keyed by round number) and updates `pcdsLatestCertSeen`, which is subsequently read by chain selection to apply the Peras weight boost to `pcCertBoostedBlock`. [4](#0-3) 

**Exploit flow (step-by-step analog to the bridge attack):**

1. Attacker connects to a victim node via the ObjectDiffusion miniprotocol (no privilege required — any peer can do this).
2. Attacker crafts a `PerasCert { pcCertRound = N, pcCertBoostedBlock = attackerBlock }` where `N` is any round not yet in the DB and `attackerBlock` is a point on the attacker's fork.
3. The peer sends this cert in a batch to the victim's `ObjectPoolWriter`.
4. `processCerts` reads `alreadyInDb` (round `N` is absent), calls `validatePerasCert mkPerasParams cert` → `Right ValidatedPerasCert { vpcCert = cert, vpcCertBoost = perasWeight params }`.
5. The fraudulent cert is stored in `PerasCertDB` and `addPerasCertAsync` triggers a chain-selection re-evaluation.
6. Chain selection now applies the Peras weight boost to `attackerBlock`, potentially causing the victim to prefer the attacker's fork over the honest chain.

### Impact Explanation

**Critical — bypass of Peras certificate validation enabling unauthorized certificate acceptance and chain selection manipulation.**

An unprivileged peer can inject a certificate for any round and any block, causing the victim node to apply a Peras weight boost to an attacker-chosen block. Because Peras certificates are specifically designed to make boosted blocks resistant to rollback (they increase the effective chain weight), a successfully injected certificate can cause the victim to irreversibly prefer a non-canonical or adversarial chain. This directly violates the Peras protocol's security invariant that only quorum-backed, cryptographically verified certificates may influence chain selection.

This matches the allowed impact scope: *"Critical. Bypass of … Peras voting or certificate checks … that enables unauthorized … certificate acceptance."*

### Likelihood Explanation

**High.** The attacker requires only a standard peer connection to the ObjectDiffusion miniprotocol — no keys, no stake, no privileged access. The stub is the universal production instance used for all block types. The attack is deterministic: every crafted cert for a new round number will be accepted. The only constraint is that one cert per round can be stored (deduplication by round number), but an attacker can target any future round.

### Recommendation

Replace the stub `validatePerasCert` with a real implementation that verifies:
1. The certificate's BLS aggregate signature against the claimed committee members' public keys.
2. That the claimed voters constitute a quorum (≥ threshold stake) drawn from the correct committee for the given round.
3. That `pcCertBoostedBlock` refers to a block that actually exists on a valid chain.
4. That `pcCertRound` falls within the valid range relative to the current slot.

Until the real implementation is in place, the inbound `processCerts` path should reject all externally received certificates (return a hard error or silently drop them) rather than accepting them unconditionally. [5](#0-4) 

### Proof of Concept

```
Precondition: attacker has a standard peer connection to the victim node's
              ObjectDiffusion endpoint (no keys or stake required).

1. Attacker observes that no cert for round R exists in the victim's DB
   (or simply picks a large future round number).

2. Attacker constructs:
     cert = PerasCert
       { pcCertRound      = R
       , pcCertBoostedBlock = Point (attackerBlockHash, attackerSlot)
       }

3. Attacker sends [cert] via the ObjectDiffusion protocol to the victim.

4. Victim's processCerts:
     alreadyInDb = {} (R not present)
     certsNotAlreadyInDb = [cert]
     validatePerasCert mkPerasParams cert
       => Right (ValidatedPerasCert { vpcCert = cert, vpcCertBoost = w })
     addCert (WithArrivalTime now validatedCert)   -- stored in PerasCertDB

5. ChainDB.addPerasCertAsync triggers chain selection.
   Chain selection reads the weight snapshot from PerasCertDB, finds a boost
   of weight w on attackerBlock, and may switch to the attacker's fork.

Expected outcome: victim node's chain selection is manipulated to prefer
the attacker's block, violating the Peras safety invariant.
```

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

**File:** ouroboros-consensus/src/ouroboros-consensus/Ouroboros/Consensus/Storage/PerasCertDB/Impl.hs (L169-201)
```haskell
implAddCert ::
  IOLike m =>
  PerasCertDbEnv m blk ->
  WithArrivalTime (ValidatedPerasCert blk) ->
  STM m (m AddPerasCertResult)
implAddCert PerasCertDbEnv{pcdbTracer, pcdbState} cert = do
  let roundNo = getPerasCertRound cert
  addPerasCertRes <- do
    WithFingerprint pcds fp <- readTVar pcdbState
    if Set.member roundNo (pcdsCertIds pcds)
      then pure PerasCertAlreadyInDB
      else do
        let pcdsLastTicketNo' = succ (pcdsLastTicketNo pcds)
            pcdsCertIds' = Set.insert roundNo (pcdsCertIds pcds)
            pcdsCertsByTicket' = Map.insert pcdsLastTicketNo' cert (pcdsCertsByTicket pcds)
            pcdsLatestCertSeen' = case pcdsLatestCertSeen pcds of
              Nothing -> Just cert
              Just prev
                | getPerasCertRound cert > getPerasCertRound prev -> Just cert
                | otherwise -> Just prev
        writeTVar pcdbState $
          WithFingerprint
            PerasCertDbState
              { pcdsCertIds = pcdsCertIds'
              , pcdsCertsByTicket = pcdsCertsByTicket'
              , pcdsLastTicketNo = pcdsLastTicketNo'
              , pcdsLatestCertSeen = pcdsLatestCertSeen'
              }
            (succ fp)
        pure AddedPerasCertToDB
  pure $ do
    traceWith pcdbTracer (AddCert roundNo cert addPerasCertRes)
    pure addPerasCertRes
```
