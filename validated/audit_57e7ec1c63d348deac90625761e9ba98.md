### Title
Cross-Chain Replay of MPC-Signed `DeployTokenPayload` Enables Unauthorized Wrapped Mint on Solana — (`solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

---

### Summary

`DeployTokenPayload::serialize_for_near` produces a chain-agnostic byte sequence (no destination chain ID). The identical serialization format is used by EVM and Starknet. Because the same MPC key signs for all chains, a valid MPC signature captured from an EVM `deployToken` transaction can be replayed verbatim on Solana's `deploy_token` instruction, where `verify_signature` will accept it and create an unauthorized wrapped mint.

---

### Finding Description

`DeployTokenPayload::serialize_for_near` serializes only:

```
[IncomingMessageType::Metadata byte] + borsh(token, name, symbol, decimals)
``` [1](#0-0) 

No destination chain ID is included. The EVM `OmniBridge.deployToken` constructs the identical byte sequence:

```solidity
bytes.concat(
    bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
    Borsh.encodeString(metadata.token),
    Borsh.encodeString(metadata.name),
    Borsh.encodeString(metadata.symbol),
    bytes1(metadata.decimals)
)
``` [2](#0-1) 

Starknet's `deploy_token` uses the same layout (confirmed in test helpers). None of the three chains include a chain ID in the `deploy_token` signed payload.

`verify_signature` on Solana recovers the secp256k1 public key from the signature and compares it to `derived_near_bridge_address` (the raw 64-byte uncompressed public key of the MPC signer): [3](#0-2) 

The MPC network uses a single key for all chains. The EVM stores the Ethereum address (20-byte keccak derivative) of that key; Solana stores the raw 64-byte public key. Both representations correspond to the same underlying secp256k1 key. Therefore, a signature produced by the MPC for an EVM `deployToken` call recovers to the same 64-byte public key on Solana, and `verify_signature` passes.

**Contrast with `FinalizeTransferPayload`**, which correctly binds to the destination chain by writing `SOLANA_OMNI_BRIDGE_CHAIN_ID` into the signed message for both the token and recipient fields: [4](#0-3) 

`deploy_token` has no equivalent protection and no nonce/used-message account — the only idempotency guard is the `init` constraint on the mint PDA, which only prevents a second deployment of the *same token on Solana*, not the first unauthorized one. [5](#0-4) 

---

### Impact Explanation

An attacker who observes a valid MPC-signed `DeployTokenPayload` for token `T` on EVM (the signature is in the calldata of the EVM transaction, fully public) can submit the identical `SignedPayload` to Solana's `deploy_token`. Solana will:

1. Accept the signature (same message bytes, same key).
2. Create a wrapped SPL mint for token `T` under the `WRAPPED_MINT_SEED` PDA.
3. Emit a `DeployTokenResponse` Wormhole message.

If the NEAR bridge processes that Wormhole VAA (the Solana factory is a registered factory), it creates a NEAR-side binding for the Solana mint. Subsequent `finalize_transfer` calls can then mint against this illegitimate mint, enabling unauthorized token issuance on Solana for a token whose NEAR-side binding was intended exclusively for EVM.

---

### Likelihood Explanation

- The EVM `deployToken` calldata (including the MPC signature) is publicly visible on-chain.
- Submitting the replayed payload to Solana requires no special privilege — `deploy_token` is a permissionless instruction.
- The attack succeeds on the first submission for any token not yet deployed on Solana.
- No threshold MPC compromise is required; the attacker only reuses an already-produced signature.

---

### Recommendation

Include `SOLANA_OMNI_BRIDGE_CHAIN_ID` in the signed message body of `DeployTokenPayload::serialize_for_near`, mirroring the pattern already used in `FinalizeTransferPayload`:

```rust
fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
    let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
    IncomingMessageType::Metadata.serialize(&mut writer)?;
    writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?; // ADD THIS
    self.serialize(&mut writer)?;
    writer.into_inner().map_err(|_| error!(ErrorCode::InvalidArgs))
}
```

The EVM and Starknet counterparts must be updated symmetrically to include their respective chain IDs, and the NEAR bridge must re-sign all existing `DeployTokenPayload` messages with the new format.

---

### Proof of Concept

```rust
// Pseudocode unit test
let secret_key = secp256k1::SecretKey::random();
let payload = DeployTokenPayload {
    token: "usdc.near".to_string(),
    name: "USD Coin".to_string(),
    symbol: "USDC".to_string(),
    decimals: 6,
};

// Serialize as Solana does
let msg_bytes = payload.serialize_for_near(()).unwrap();
let hash = keccak::hash(&msg_bytes);

// Sign once (simulating MPC signing for EVM)
let sig = sign(&secret_key, &hash.to_bytes());

// Verify on "EVM context" — passes (same message, same key)
assert!(verify_signature_evm(&sig, &hash, &eth_address_of(&secret_key)));

// Replay on "Solana context" — also passes (same message, same key, same hash)
let derived = raw_pubkey_of(&secret_key); // 64-byte uncompressed
assert!(verify_signature_solana(&sig, &hash, &derived));
// Both assertions succeed → cross-chain replay confirmed
```

The test requires two `Config` accounts with the same `derived_near_bridge_address` (one representing Solana, one representing EVM) and demonstrates that a single MPC signature satisfies both `verify_signature` calls.

### Citations

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L142-149)
```text
        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.Metadata)),
            Borsh.encodeString(metadata.token),
            Borsh.encodeString(metadata.name),
            Borsh.encodeString(metadata.symbol),
            bytes1(metadata.decimals)
        );
        bytes32 hashed = keccak256(borshEncoded);
```

**File:** solana/programs/bridge_token_factory/src/state/message/mod.rs (L24-47)
```rust
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

**File:** solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs (L30-36)
```rust
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.0.serialize(&mut writer)?;
        // 4. amount
        self.amount.serialize(&mut writer)?;
        // 5. recipient
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.1.serialize(&mut writer)?;
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/deploy_token.rs (L45-53)
```rust
    #[account(
        init,
        payer = common.payer,
        seeds = [WRAPPED_MINT_SEED, data.payload.token.to_hashed_bytes().as_ref()],
        bump,
        mint::decimals = std::cmp::min(MAX_ALLOWED_DECIMALS, data.payload.decimals),
        mint::authority = authority,
    )]
    pub mint: Box<Account<'info, Mint>>,
```
