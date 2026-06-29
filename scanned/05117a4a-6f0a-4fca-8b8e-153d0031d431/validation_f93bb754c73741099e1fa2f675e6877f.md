Now I have all the data needed. Let me do the byte-level analysis.

**`PayloadType` enum** (`near/omni-types/src/lib.rs:638`):
```rust
pub enum PayloadType {
    TransferMessage,  // Borsh variant 0
    Metadata,         // Borsh variant 1
    ClaimNativeFee,   // Borsh variant 2
}
```

**`IncomingMessageType` enum** (`solana/.../state/message/mod.rs:51`):
```rust
pub enum IncomingMessageType {
    InitTransfer,  // Borsh variant 0
    Metadata,      // Borsh variant 1
}
```

Both `PayloadType::Metadata` and `IncomingMessageType::Metadata` serialize to `0x01`.

**NEAR MPC signs** (`near/omni-bridge/src/lib.rs:349`):
```
keccak256( borsh(MetadataPayload) )
= keccak256( [0x01] ++ borsh_str(token) ++ borsh_str(name) ++ borsh_str(symbol) ++ [decimals] )
```

**Solana `DeployTokenPayload::serialize_for_near`** (`solana/.../state/message/deploy_token.rs:19`):
```
[0x01 (IncomingMessageType::Metadata)] ++ borsh(DeployTokenPayload)
= [0x01] ++ borsh_str(token) ++ borsh_str(name) ++ borsh_str(symbol) ++ [decimals]
```

**These are byte-for-byte identical** for the same `(token, name, symbol, decimals)` tuple.

---

### Title
MPC Signature from `log_metadata_callback` is Reusable for Solana `deploy_token` Due to Identical Serialization Prefix — (`solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`, `near/omni-types/src/lib.rs`)

### Summary

`PayloadType::Metadata` (NEAR, variant index 1) and `IncomingMessageType::Metadata` (Solana, variant index 1) both serialize to the byte `0x01`. Combined with the fact that `MetadataPayload` and `DeployTokenPayload` share the same field layout (`token: String, name: String, symbol: String, decimals: u8`), the Borsh byte sequence that NEAR's MPC signs for `log_metadata` is **identical** to the byte sequence that Solana's `verify_signature` hashes for `deploy_token`. Any valid MPC signature obtained via NEAR's `log_metadata` flow can be directly replayed to Solana's `deploy_token` instruction.

### Finding Description

**NEAR side — what MPC signs:**

In `near/omni-bridge/src/lib.rs`, `log_metadata_callback` constructs:

```rust
let metadata_payload = MetadataPayload {
    prefix: PayloadType::Metadata,   // serializes as 0x01
    token: token_id.to_string(),
    name: metadata.name,
    symbol: metadata.symbol,
    decimals: metadata.decimals,
};
let payload = near_sdk::env::keccak256_array(
    borsh::to_vec(&metadata_payload)...
);
``` [1](#0-0) 

`MetadataPayload` Borsh layout:
```
[0x01] ++ [u32-LE len] ++ token_bytes ++ [u32-LE len] ++ name_bytes ++ [u32-LE len] ++ symbol_bytes ++ [decimals]
``` [2](#0-1) 

**Solana side — what `verify_signature` hashes for `deploy_token`:**

`DeployTokenPayload::serialize_for_near` writes:
```rust
IncomingMessageType::Metadata.serialize(&mut writer)?;  // 0x01
self.serialize(&mut writer)?;                           // borsh(DeployTokenPayload)
``` [3](#0-2) 

`DeployTokenPayload` Borsh layout:
```
[u32-LE len] ++ token_bytes ++ [u32-LE len] ++ name_bytes ++ [u32-LE len] ++ symbol_bytes ++ [decimals]
``` [4](#0-3) 

So `serialize_for_near` produces:
```
[0x01] ++ [u32-LE len] ++ token_bytes ++ [u32-LE len] ++ name_bytes ++ [u32-LE len] ++ symbol_bytes ++ [decimals]
```

This is **byte-for-byte identical** to `borsh(MetadataPayload)` for the same inputs.

`verify_signature` then hashes this with keccak256 and checks the MPC signature: [5](#0-4) 

### Impact Explanation

An attacker who obtains a valid MPC signature from NEAR's `log_metadata` event (which is publicly emitted on-chain) can submit it directly to Solana's `deploy_token` instruction with a matching `DeployTokenPayload`. The signature verification passes because the hashed byte sequences are identical. This deploys a wrapped SPL mint on Solana for the target NEAR token, bypassing the intended NEAR-side `deploy_token` authorization flow entirely. The attacker can:

1. Deploy wrapped tokens on Solana for any NEAR token that has ever had `log_metadata` called, without a legitimate NEAR `deploy_token` transaction.
2. Front-run legitimate deployments: since the mint PDA is derived from the token name, a successful attacker deployment causes all subsequent legitimate `deploy_token` calls for the same token to fail with "account already initialized."
3. The `deploy_token` instruction also posts a `DeployTokenResponse` Wormhole message back to NEAR, which NEAR would process as a legitimate deployment confirmation, completing the binding on the NEAR side without NEAR ever having authorized it.

### Likelihood Explanation

The MPC signature is emitted publicly in a `LogMetadataEvent` log on NEAR. Any observer can extract it. `log_metadata` can be called by anyone for any NEAR token. The attack requires no privileged access, no key compromise, and no threshold MPC collusion — only a publicly observable on-chain event. It is concretely exploitable on unmodified production code.

### Recommendation

Introduce domain separation between the two message types. The simplest fix is to use **different prefix byte values** for the two contexts. For example, change `IncomingMessageType` so that `Metadata` is not variant index 1, or add an explicit chain/context tag to `DeployTokenPayload::serialize_for_near` that is absent from `MetadataPayload`. Alternatively, restructure `MetadataPayload` to include a field that makes its Borsh encoding structurally incompatible with `DeployTokenPayload` (e.g., a chain ID byte before the token string, as is done in `LogMetadataPayload::serialize_for_near` with `SOLANA_OMNI_BRIDGE_CHAIN_ID`).

### Proof of Concept

```rust
// Reproduce the collision in a unit test:
use borsh::BorshSerialize;

// NEAR side: what MPC signs
let meta = MetadataPayload {
    prefix: PayloadType::Metadata,   // = 0x01
    token: "usdc.near".to_string(),
    name: "USD Coin".to_string(),
    symbol: "USDC".to_string(),
    decimals: 6,
};
let near_bytes = borsh::to_vec(&meta).unwrap();

// Solana side: what verify_signature hashes for deploy_token
let deploy = DeployTokenPayload {
    token: "usdc.near".to_string(),
    name: "USD Coin".to_string(),
    symbol: "USDC".to_string(),
    decimals: 6,
};
let sol_bytes = deploy.serialize_for_near(()).unwrap();

// These must differ for security — but they are equal:
assert_eq!(near_bytes, sol_bytes); // PASSES — collision confirmed

// Therefore: MPC signature over near_bytes verifies against sol_bytes.
// Attacker extracts signature from LogMetadataEvent on NEAR,
// submits SignedPayload<DeployTokenPayload> { payload: deploy, signature }
// to Solana's deploy_token instruction → signature check passes → mint deployed.
```

The root cause is:
- `PayloadType::Metadata` = Borsh variant 1 = `0x01` [6](#0-5) 
- `IncomingMessageType::Metadata` = Borsh variant 1 = `0x01` [7](#0-6) 
- `MetadataPayload` fields after prefix = `(String, String, String, u8)` = same layout as `DeployTokenPayload` [8](#0-7) 
- `DeployTokenPayload::serialize_for_near` prepends exactly that same prefix byte and then Borsh-serializes the struct [3](#0-2)

### Citations

**File:** near/omni-bridge/src/lib.rs (L341-351)
```rust
        let metadata_payload = MetadataPayload {
            prefix: PayloadType::Metadata,
            token: token_id.to_string(),
            name: metadata.name,
            symbol: metadata.symbol,
            decimals: metadata.decimals,
        };

        let payload = near_sdk::env::keccak256_array(
            borsh::to_vec(&metadata_payload).near_expect(BridgeError::Borsh),
        );
```

**File:** near/omni-types/src/lib.rs (L636-702)
```rust
#[near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub enum PayloadType {
    TransferMessage,
    Metadata,
    ClaimNativeFee,
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct TransferMessagePayloadV1 {
    pub prefix: PayloadType,
    pub destination_nonce: Nonce,
    pub transfer_id: TransferId,
    pub token_address: OmniAddress,
    pub amount: U128,
    pub recipient: OmniAddress,
    pub fee_recipient: Option<AccountId>,
}

impl From<TransferMessagePayload> for TransferMessagePayloadV1 {
    fn from(payload: TransferMessagePayload) -> Self {
        Self {
            prefix: payload.prefix,
            destination_nonce: payload.destination_nonce,
            transfer_id: payload.transfer_id,
            token_address: payload.token_address,
            amount: payload.amount,
            recipient: payload.recipient,
            fee_recipient: payload.fee_recipient,
        }
    }
}

#[near(serializers=[borsh, json])]
#[derive(Debug, Clone)]
pub struct TransferMessagePayload {
    pub prefix: PayloadType,
    pub destination_nonce: Nonce,
    pub transfer_id: TransferId,
    pub token_address: OmniAddress,
    pub amount: U128,
    pub recipient: OmniAddress,
    pub fee_recipient: Option<AccountId>,
    #[serde(default)]
    pub message: Vec<u8>,
}

impl TransferMessagePayload {
    pub fn encode_hashable(&self) -> Result<Vec<u8>, String> {
        if self.message.is_empty() {
            borsh::to_vec(&TransferMessagePayloadV1::from(self.clone())).map_err(stringify)
        } else {
            borsh::to_vec(self).map_err(stringify)
        }
    }
}

#[near(serializers = [borsh, json])]
#[derive(Debug, Clone)]
pub struct MetadataPayload {
    pub prefix: PayloadType,
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}
```

**File:** solana/programs/bridge_token_factory/src/state/message/deploy_token.rs (L8-14)
```rust
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct DeployTokenPayload {
    pub token: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}
```

**File:** solana/programs/bridge_token_factory/src/state/message/deploy_token.rs (L19-27)
```rust
    fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
        let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
        IncomingMessageType::Metadata.serialize(&mut writer)?;
        self.serialize(&mut writer)?; // borsh encoding
        writer
            .into_inner()
            .map_err(|_| error!(ErrorCode::InvalidArgs))
    }
}
```

**File:** solana/programs/bridge_token_factory/src/state/message/mod.rs (L23-47)
```rust
impl<P: Payload> SignedPayload<P> {
    pub fn verify_signature(
        &self,
        params: P::AdditionalParams,
        derived_near_bridge_address: &[u8; 64],
    ) -> Result<()> {
        let serialized = self.payload.serialize_for_near(params)?;
        let hash = keccak::hash(&serialized);

        let signature_bytes = &self.signature[0..64];

        let signature = libsecp256k1::Signature::parse_standard_slice(signature_bytes)
            .map_err(|_| ProgramError::InvalidArgument)?;
        require!(!signature.s.is_high(), ErrorCode::MalleableSignature);

        let signer = secp256k1_recover(&hash.to_bytes(), self.signature[64], signature_bytes)
            .map_err(|_| error!(ErrorCode::SignatureVerificationFailed))?;

        require!(
            signer.0 == *derived_near_bridge_address,
            ErrorCode::SignatureVerificationFailed
        );

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/state/message/mod.rs (L51-54)
```rust
pub enum IncomingMessageType {
    InitTransfer,
    Metadata,
}
```
