### Title
KES and VRF Signing Keys Loaded from Disk Without File Permission Checks, Enabling Unauthorized Block Forgery - (File: `ouroboros-consensus-cardano/src/unstable-cardano-tools/Cardano/Node/Protocol/Shelley.hs`)

---

### Summary

The credential-loading path in `readLeaderCredentialsSingleton` and `readLeaderCredentialsBulk` reads VRF signing keys, KES signing keys, and operational certificates from disk without checking file permissions. A `VRFPrivateKeyFilePermissionError` type and `renderVRFPrivateKeyFilePermissionError` function are defined in `Cardano/Node/Types.hs` but are never invoked anywhere in the production credential loading path. An attacker with local read access to overly permissive key files can steal the complete set of block-production credentials and forge blocks as the legitimate stake pool operator.

---

### Finding Description

`readLeaderCredentialsSingleton` reads the VRF signing key file and KES signing key file directly:

```haskell
vrfSKey <- firstExceptT FileError (newExceptT $ readFileTextEnvelope (AsSigningKey AsVrfKey) vrfFile)
(opCert, kesSKey) <- opCertKesKeyCheck kesFile opCertFile
```

`readLeaderCredentialsBulk` reads the bulk credentials file (a single JSON file containing the operational certificate, VRF signing key, and KES signing key together) via a plain `BS.readFile fp` with no permission check:

```haskell
content <- handleIOExceptT (CredentialsReadError fp) $ BS.readFile fp
```

Neither path checks whether the key files have overly broad permissions (e.g., world-readable). The codebase does define `VRFPrivateKeyFilePermissionError` with constructors `OtherPermissionsExist`, `GroupPermissionsExist`, and `GenericPermissionsExist`, and a corresponding `renderVRFPrivateKeyFilePermissionError` renderer, but a search of the entire codebase finds these symbols referenced only in `Cardano/Node/Types.hs` itself — they are never called in any credential loading path.

Additionally, `PraosCredentialsUnsound` in `Praos/Common.hs` explicitly documents that the default credential loading mode "does not provide mlocking guarantees, **violating the rule that KES secrets must never be stored on disk**," yet this is the only path used by `mkPraosLeaderCredentials` when loading from files. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

---

### Impact Explanation

The VRF signing key, KES signing key, and operational certificate together constitute the complete set of Praos block-production credentials. An attacker who reads these files can:

1. Construct a `PraosCanBeLeader` with the stolen `praosCanBeLeaderSignKeyVRF` and `PraosCredentialsUnsound opcert kesKey`.
2. Produce cryptographically valid block headers that pass all `doValidateVRFSignature` and `doValidateKESSignature` checks, because the signatures are genuine.
3. Forge blocks as the legitimate stake pool operator, bypassing leader eligibility enforcement.

This is a bypass of VRF/KES/certificate validation that enables unauthorized block acceptance, matching the "High" impact tier: bypass of leader eligibility or hot-key rules that enables unauthorized block acceptance. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

The bulk credentials file (`--bulk-credentials-file`) is a single JSON file containing all three secrets. The `db-synthesizer` tool documents and encourages its use. Operators who follow the documented example workflow may not realize the file must be owner-read-only. Because no permission check is performed and no warning is emitted, a misconfigured file (e.g., `644` or `664`) silently exposes all block-production credentials to any local user on the machine. The scenario is directly analogous to the price-feeder finding: a second local account reads the world-readable file and obtains the full credential set. [7](#0-6) [8](#0-7) 

---

### Recommendation

- In `readLeaderCredentialsSingleton`, after resolving `vrfFile` and `kesFile`, call the already-defined `VRFPrivateKeyFilePermissionError` check (or an equivalent for KES) and abort with a clear error if group or other read/write bits are set.
- In `readLeaderCredentialsBulk`, apply the same permission check to the bulk credentials file path before calling `BS.readFile`.
- Emit a prominent warning (or hard error) when `PraosCredentialsUnsound` is used, noting that the KES signing key is being loaded from an unprotected on-disk file without mlocking.
- Document the required file permissions (`600`) for all credential files in the `db-synthesizer` help text and the consensus tools documentation. [3](#0-2) 

---

### Proof of Concept

```bash
# Operator sets up a block-producing node with a bulk credentials file
$ ls -la bulk-creds-k2.json
-rw-r--r-- 1 operator operator 2048 Jan 1 00:00 bulk-creds-k2.json
# File is world-readable; no warning is emitted by readLeaderCredentialsBulk

# Attacker on the same machine (different account) reads the file
$ cat /home/operator/bulk-creds-k2.json
[[ {"type":"NodeOperationalCertificate","cborHex":"..."},
   {"type":"VrfSigningKey_PraosVRF","cborHex":"..."},
   {"type":"KesSigningKey_ed25519_kes_2^6","cborHex":"..."} ]]

# Attacker passes the stolen credentials to their own db-synthesizer instance
$ cabal run db-synthesizer -- \
    --config config.json \
    --db /tmp/attacker-db \
    --bulk-credentials-file /home/operator/bulk-creds-k2.json \
    -s 10000
# Produces a valid chain signed with the legitimate pool's VRF and KES keys,
# passing all doValidateVRFSignature and doValidateKESSignature checks.
``` [9](#0-8) [10](#0-9)

### Citations

**File:** ouroboros-consensus-cardano/src/unstable-cardano-tools/Cardano/Node/Protocol/Shelley.hs (L136-142)
```haskell
    } = do
    vrfSKey <-
      firstExceptT FileError (newExceptT $ readFileTextEnvelope (AsSigningKey AsVrfKey) vrfFile)

    (opCert, kesSKey) <- opCertKesKeyCheck kesFile opCertFile

    return [mkPraosLeaderCredentials opCert vrfSKey kesSKey]
```

**File:** ouroboros-consensus-cardano/src/unstable-cardano-tools/Cardano/Node/Protocol/Shelley.hs (L183-218)
```haskell
readLeaderCredentialsBulk ProtocolFilepaths{shelleyBulkCredsFile = mfp} =
  mapM parseShelleyCredentials =<< readBulkFile mfp
 where
  parseShelleyCredentials ::
    ShelleyCredentials ->
    ExceptT PraosLeaderCredentialsError IO (ShelleyLeaderCredentials StandardCrypto)
  parseShelleyCredentials ShelleyCredentials{scCert, scVrf, scKes} =
    mkPraosLeaderCredentials
      <$> parseEnvelope AsOperationalCertificate scCert
      <*> parseEnvelope (AsSigningKey AsVrfKey) scVrf
      <*> parseEnvelope (AsSigningKey AsUnsoundPureKesKey) scKes

  readBulkFile ::
    Maybe FilePath ->
    ExceptT PraosLeaderCredentialsError IO [ShelleyCredentials]
  readBulkFile Nothing = pure []
  readBulkFile (Just fp) = do
    content <-
      handleIOExceptT (CredentialsReadError fp)
        $ BS.readFile fp
    envelopes <-
      firstExceptT (EnvelopeParseError fp)
        $ hoistEither
        $ Aeson.eitherDecodeStrict' content
    pure $ uncurry mkCredentials <$> zip [0 ..] envelopes
   where
    mkCredentials ::
      Int ->
      (TextEnvelope, TextEnvelope, TextEnvelope) ->
      ShelleyCredentials
    mkCredentials ix (teCert, teVrf, teKes) =
      let loc ty = fp <> "." <> show ix <> ty
       in ShelleyCredentials
            (teCert, loc "cert")
            (teVrf, loc "vrf")
            (teKes, loc "kes")
```

**File:** ouroboros-consensus-cardano/src/unstable-cardano-tools/Cardano/Node/Protocol/Shelley.hs (L220-237)
```haskell
mkPraosLeaderCredentials ::
  OperationalCertificate ->
  SigningKey VrfKey ->
  SigningKey UnsoundPureKesKey ->
  ShelleyLeaderCredentials StandardCrypto
mkPraosLeaderCredentials
  (OperationalCertificate opcert (StakePoolVerificationKey vkey))
  (VrfSigningKey vrfKey)
  (KesSigningKey kesKey) =
    ShelleyLeaderCredentials
      { shelleyLeaderCredentialsCanBeLeader =
          PraosCanBeLeader
            { praosCanBeLeaderColdVerKey = coerceKeyRole vkey
            , praosCanBeLeaderSignKeyVRF = vrfKey
            , praosCanBeLeaderCredentialsSource = PraosCredentialsUnsound opcert kesKey
            }
      , shelleyLeaderCredentialsLabel = "Shelley"
      }
```

**File:** ouroboros-consensus-cardano/src/unstable-cardano-tools/Cardano/Node/Types.hs (L284-304)
```haskell
data VRFPrivateKeyFilePermissionError
  = OtherPermissionsExist FilePath
  | GroupPermissionsExist FilePath
  | GenericPermissionsExist FilePath
  deriving Show

renderVRFPrivateKeyFilePermissionError :: VRFPrivateKeyFilePermissionError -> Text
renderVRFPrivateKeyFilePermissionError err =
  case err of
    OtherPermissionsExist fp ->
      "VRF private key file at: "
        <> Text.pack fp
        <> " has \"other\" file permissions. Please remove all \"other\" file permissions."
    GroupPermissionsExist fp ->
      "VRF private key file at: "
        <> Text.pack fp
        <> "has \"group\" file permissions. Please remove all \"group\" file permissions."
    GenericPermissionsExist fp ->
      "VRF private key file at: "
        <> Text.pack fp
        <> "has \"generic\" file permissions. Please remove all \"generic\" file permissions."
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/Common.hs (L287-294)
```haskell
data PraosCredentialsSource c where
  -- | Pass an opcert and sign key directly. This uses
  -- 'KES.UnsoundPureSignKeyKES', which does not provide mlocking guarantees,
  -- violating the rule that KES secrets must never be stored on disk, but
  -- allows the sign key to be loaded from a local file. This method is
  -- provided for backwards compatibility.
  PraosCredentialsUnsound ::
    OCert.OCert c -> KES.UnsoundPureSignKeyKES (KES c) -> PraosCredentialsSource c
```

**File:** ouroboros-consensus-protocol/src/ouroboros-consensus-protocol/Ouroboros/Consensus/Protocol/Praos/Common.hs (L317-326)
```haskell
instantiatePraosCredentials maxKESEvolutions _ (PraosCredentialsUnsound ocert skUnsound) = do
  sk <- KES.unsoundPureSignKeyKESToSoundSignKeyKES skUnsound
  let startPeriod :: OCert.KESPeriod
      startPeriod = OCert.ocertKESPeriod ocert

  HotKey.mkHotKey
    ocert
    sk
    startPeriod
    maxKESEvolutions
```

**File:** ouroboros-consensus-cardano/app/db-synthesizer.hs (L1-23)
```haskell
-- | This tool synthesizes a valid ChainDB, replicating cardano-node's UX
--
-- Usage: db-synthesizer --config FILE --db PATH
--                       [--shelley-operational-certificate FILE]
--                       [--shelley-vrf-key FILE] [--shelley-kes-key FILE]
--                       [--bulk-credentials-file FILE]
--                       ((-s|--slots NUMBER) | (-b|--blocks NUMBER) |
--                         (-e|--epochs NUMBER)) [-f | -a]
--
-- Available options:
--   --config FILE            Path to the node's config.json
--   --db PATH                Path to the Chain DB
--   --shelley-operational-certificate FILE
--                            Path to the delegation certificate
--   --shelley-vrf-key FILE   Path to the VRF signing key
--   --shelley-kes-key FILE   Path to the KES signing key
--   --bulk-credentials-file FILE
--                            Path to the bulk credentials file
--   -s,--slots NUMBER        Amount of slots to process
--   -b,--blocks NUMBER       Amount of blocks to forge
--   -e,--epochs NUMBER       Amount of epochs to process
--   -f                       Force overwrite an existing Chain DB
--   -a                       Append to an existing Chain DB
```

**File:** ouroboros-consensus-cardano/test/tools-test/disk/config/bulk-creds-k2.json (L1-17)
```json
[
   [
 {
    "type": "NodeOperationalCertificate",
    "description": "",
    "cborHex": "82845820465dad8c08ecfe932f70bf287903d2d1973ac224f61cd0f9914ed052853f736b000058402cf9b1523a570f5a3333e1a602d3212e187b1e4b6b147b7cbc94657039de7e79e8ca6dc964cb7368b135c9607151e715d2ea9ccad9f3f550077b79fa3f64d1095820974aab238e812402dc9dbce33dd28203ae6df68616290a1b4aac347e881057bb"
}
  , {
    "type": "VrfSigningKey_PraosVRF",
    "description": "VRF Signing Key",
    "cborHex": "584040c0bd2dd8acfaded1d93c4844c2130058f86067af2e065dd3ae001e964a5f18b08644bf6ed9d404ba94c9ba9299a2ab53f36c57c02c38139f2138b6c71302c7"
}
  , {
    "type": "KesSigningKey_ed25519_kes_2^6",
    "description": "KES Signing Key",
    "cborHex": "5902606d23bd6e50df9416e52e9ee2cca23ac00f1ae78a62e50afcfc3cc8159b1e9ac888593015ae9c6124e33f143416b5c12195e3a2b947a00ef34e185f672b1047df6f5180047fffdaefea6337b2384087095873ba2d09ba74d1e826bbeec148e2db19ecb1db2e6d28748cf06cd36711d16fbced7fa2d5e0c1111832c36982196b417bd16ed77a4fd795fa22e2d394f3cb8940ca406431f4b105d6e9a47e5bcb4d5f86fa466b8228fcf17056f5e006ed522538c7ed32ad8724d3c63f5443907081f5f54f72868cb1475d05bb79d11a4c6abbed543c4898fc2f157aeb99adb27c31ca22ac195d04b13a0a1a3d118599d7ff8073d90063afcc87586e77b9795f73776e0f0bbf690440a243e729880cbcded7fc778f31cc873791296b1e43f87c869e197f1fd345fdf368136c936c53124caad8786379a194d3b348752b90dbfdd1199a3f8f8388940d5585825e2cffe7108b821d54351b6de2c9c4c8308d157b4b25070c77efc22a327e074e2ec01eac2bf9169a97d65cc826fbe827d0da045e5b680953b17a47b2 ... (truncated)
}
```
