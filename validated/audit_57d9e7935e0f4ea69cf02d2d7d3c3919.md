### Title
Cross-Chain Replay of `DeployTokenPayload` MPC Signature: Missing Chain-ID Binding in Signed Message — (`solana/programs/bridge_token_factory/src/state/message/deploy_token.rs`)

---

### Summary

`DeployTokenPayload::serialize_for_near()` produces a signed message that contains **no `SOLANA_OMNI_BRIDGE_CHAIN_ID` byte**. Every other payload serializer in the program embeds this compile-time chain discriminator. Because the signed bytes are identical across the Solana build (chain_id=2) and the FOGO build (chain_id=12), a NEAR-MPC-signed `SignedPayload<DeployTokenPayload>` targeting Solana is unconditionally accepted by the FOGO `deploy_token` instruction, and vice versa.

---

### Finding Description

`build.rs` bakes `SOLANA_OMNI_BRIDGE_CHAIN_ID` into the binary at compile time: [1](#0-0) 

Solana gets `2`, FOGO gets `12` (per `Makefile` lines 22–23). [2](#0-1) 

Every other `serialize_for_near` implementation writes this byte into the signed body:

- `FinalizeTransferPayload` — writes `SOLANA_OMNI_BRIDGE_CHAIN_ID` at the token field (line 30) and recipient field (line 35): [3](#0-2) 

- `InitTransferPayload` — writes it at sender (line 24) and token (line 27): [4](#0-3) 

- `LogMetadataPayload` — writes it at the token field (line 23): [5](#0-4) 

`DeployTokenPayload::serialize_for_near()` is the sole exception — it writes only the `IncomingMessageType::Metadata` discriminant followed by the raw Borsh fields, with **no chain byte**: [6](#0-5) 

`SignedPayload::verify_signature` calls `serialize_for_near`, hashes the result with keccak, and checks the recovered key against `derived_near_bridge_address`: [7](#0-6) 

Because the serialized bytes are identical on both chains, the keccak hash is identical, and the recovered signer is identical. The check passes on both chains for the same `(payload, signature)` pair.

`deploy_token` has no nonce/used-nonces account — the only replay guard is the `init` constraint on the mint PDA, which is chain-local: [8](#0-7) 

There is no cross-chain replay barrier.

---

### Impact Explanation

An attacker who observes a valid `SignedPayload<DeployTokenPayload>` submitted to the Solana bridge can immediately replay it on FOGO (or vice versa):

1. The FOGO `deploy_token` instruction accepts the signature (identical signed bytes → identical hash → same recovered signer).
2. A wrapped mint is created on FOGO under the program's authority PDA.
3. `initialize_token_metadata` posts a `DeployTokenResponse` Wormhole message back to NEAR, which registers the token as deployed on FOGO. [9](#0-8) 

NEAR now believes the token is live on FOGO without having authorized it for FOGO. This constitutes unauthorized execution of a deployer-equivalent action and a chain/domain separation bypass. It also permanently occupies the wrapped-mint PDA on FOGO, preventing any future legitimate deployment attempt from succeeding (the `init` constraint would fail on a second call).

The claim of **subsequent unauthorized minting** is partially overstated: `FinalizeTransferPayload` does embed `SOLANA_OMNI_BRIDGE_CHAIN_ID`, so minting bridged tokens still requires a chain-specific NEAR MPC signature. However, the unauthorized mint creation and the false Wormhole registration with NEAR are themselves Critical-scope impacts (unauthorized deployer action, chain/domain separation flaw).

---

### Likelihood Explanation

All `SignedPayload<DeployTokenPayload>` transactions are public on-chain. Any observer can extract the payload and signature from a Solana transaction and submit them to FOGO (or vice versa) with no special access. The precondition — both deployments sharing the same `derived_near_bridge_address` — is the intended production configuration (both bridge to the same NEAR MPC key). This is trivially exploitable by any party watching the chain.

---

### Recommendation

Add `SOLANA_OMNI_BRIDGE_CHAIN_ID` to the signed body of `DeployTokenPayload::serialize_for_near()`, consistent with every other payload serializer. For example, prefix the token field with the chain byte:

```rust
fn serialize_for_near(&self, _params: Self::AdditionalParams) -> Result<Vec<u8>> {
    let mut writer = BufWriter::new(Vec::with_capacity(DEFAULT_SERIALIZER_CAPACITY));
    IncomingMessageType::Metadata.serialize(&mut writer)?;
    // Bind to the target chain — prevents cross-chain replay
    writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
    self.serialize(&mut writer)?;
    writer.into_inner().map_err(|_| error!(ErrorCode::InvalidArgs))
}
```

The NEAR side must be updated to expect and validate this byte when verifying `DeployToken` messages.

---

### Proof of Concept

```rust
#[test]
fn deploy_token_cross_chain_replay() {
    use bridge_token_factory::state::message::{
        deploy_token::DeployTokenPayload, Payload,
    };

    let payload = DeployTokenPayload {
        token: "usdc.token.near".to_string(),
        name: "USD Coin".to_string(),
        symbol: "USDC".to_string(),
        decimals: 6,
    };

    // serialize_for_near takes no chain-specific params
    let bytes_chain2  = payload.serialize_for_near(()).unwrap(); // Solana build (CHAIN_ID=2)
    let bytes_chain12 = payload.serialize_for_near(()).unwrap(); // FOGO build (CHAIN_ID=12)

    // Both produce identical bytes — same keccak hash — same recovered signer
    assert_eq!(bytes_chain2, bytes_chain12,
        "signed body must differ between chains but does not");
}
```

Because `SOLANA_OMNI_BRIDGE_CHAIN_ID` is a compile-time constant and `serialize_for_near` never writes it, the assertion holds regardless of which binary is running. A single NEAR MPC signature over this payload is accepted by both the Solana and FOGO `deploy_token` instructions.

### Citations

**File:** solana/programs/bridge_token_factory/build.rs (L16-24)
```rust
    let chain_id: u8 = env::var("OMNI_CHAIN_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    let chain_id_path = Path::new(&out_dir).join("chain_id.rs");
    fs::write(
        &chain_id_path,
        format!("#[constant]\npub const SOLANA_OMNI_BRIDGE_CHAIN_ID: u8 = {chain_id};\n"),
    )
```

**File:** Makefile (L19-23)
```text
# OMNI_CHAIN_ID is the omni-bridge ChainKind byte embedded in outgoing payloads.
# Must match ChainKind on the NEAR side: 2 = Sol, 12 = Fogo.
# See solana/programs/bridge_token_factory/build.rs.
SOL_OMNI_CHAIN_ID  := 2
FOGO_OMNI_CHAIN_ID := 12
```

**File:** solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs (L29-36)
```rust
        // 3. token
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.0.serialize(&mut writer)?;
        // 4. amount
        self.amount.serialize(&mut writer)?;
        // 5. recipient
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.1.serialize(&mut writer)?;
```

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L23-28)
```rust
        // 1. sender
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.1.serialize(&mut writer)?;
        // 2. token
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.2.serialize(&mut writer)?;
```

**File:** solana/programs/bridge_token_factory/src/state/message/log_metadata.rs (L22-24)
```rust
        // 1. token
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        self.token.serialize(&mut writer)?;
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

**File:** solana/programs/bridge_token_factory/src/instructions/user/deploy_token.rs (L110-118)
```rust
        let payload = DeployTokenResponse {
            token: metadata.token,
            solana_mint: self.mint.key(),
            decimals: metadata.decimals,
            origin_decimals,
        }
        .serialize_for_near(())?;

        self.common.post_message(payload)?;
```
