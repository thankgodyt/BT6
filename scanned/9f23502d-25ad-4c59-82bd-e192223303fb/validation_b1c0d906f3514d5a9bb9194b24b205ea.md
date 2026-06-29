The vulnerability is real and exploitable. Here is the full analysis:

---

### Title
Missing `metadata.mint` Cross-Check in `parse_metadata_account` Allows Forged Name/Symbol in Wormhole LogMetadata Message — (`solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs`)

### Summary

`parse_metadata_account` validates that the supplied account's key matches `metadata_pointer.metadata_address` and that the account is owned by `MetaplexID`, but it never verifies that the deserialized `MplMetadata.mint` field equals `self.mint.key()`. An attacker who controls a Token-2022 mint with a metadata pointer to a legitimately-created Metaplex metadata account for a *different* mint can inject arbitrary `name` and `symbol` into the Wormhole `LogMetadata` message.

### Finding Description

In `process()`, the Token-2022 branch dispatches to `parse_metadata_account` when `metadata_pointer.metadata_address != mint.key() && != Pubkey::default()`: [1](#0-0) 

Inside `parse_metadata_account`, the only guards are: [2](#0-1) 

- `require_keys_eq!(metadata.key(), address, ...)` — confirms the account key matches the pointer address.
- `metadata.owner == &MetaplexID` — confirms the account is owned by the Metaplex program.
- `MplMetadata::try_deserialize(...)` — confirms the account has a valid Metaplex discriminator and layout.

**Missing:** `require_keys_eq!(metadata.mint, self.mint.key(), ...)` — there is no check that the deserialized metadata's `mint` field corresponds to the Token-2022 mint being logged.

The resulting payload blindly uses whatever `name`/`symbol` the deserialized account contains: [3](#0-2) 

For the classic SPL path this is not exploitable because the metadata address is computed as a PDA seeded with `self.mint.key()`: [4](#0-3) 

But for Token-2022 with a third-party pointer, the pointer address is freely chosen by the mint creator, so it can point to any existing Metaplex metadata account.

### Impact Explanation

The forged `LogMetadataPayload` is posted as a Wormhole VAA: [5](#0-4) 

On NEAR, `deploy_token_callback` consumes this VAA and calls `deploy_token_internal` with the injected `name` and `symbol`: [6](#0-5) 

This registers the attacker's worthless mint M on NEAR under USDC's name and symbol. Users who subsequently bridge tokens through the UI will see a "USDC" entry backed by the attacker's mint, enabling fund loss through metadata-binding confusion. The invariant — that `LogMetadata` name/symbol must reflect the actual metadata of the logged mint — is broken.

### Likelihood Explanation

The attack requires no privileged access. Any user can:
1. Create a Token-2022 mint M (permissionless).
2. Create a second mint M2 with a Metaplex metadata account containing `name='USDC', symbol='USDC'` (permissionless — attacker controls M2's mint authority).
3. Set M's metadata pointer to `PDA([b"metadata", MetaplexID, M2])`.
4. Call `log_metadata(M, metadata=Some(PDA([b"metadata", MetaplexID, M2])))`.

All four steps are standard, permissionless Solana operations. No admin compromise, no key leakage, no guardian collusion required.

### Recommendation

After deserializing `MplMetadata`, add a cross-check:

```rust
if metadata.owner == &MetaplexID {
    let data = metadata.try_borrow_data()?;
    let mpl = MplMetadata::try_deserialize(&mut data.as_ref())?;
    // ADD THIS:
    require_keys_eq!(
        mpl.mint,
        self.mint.key(),
        ErrorCode::InvalidTokenMetadataAddress,
    );
    Ok((mpl.name.clone(), mpl.symbol.clone()))
}
```

This mirrors the implicit guarantee already present in the classic SPL path, where the metadata PDA is derived from `self.mint.key()`.

### Proof of Concept

Mollusk test outline (unmodified production code):

1. Create Token-2022 mint `M` with a `MetadataPointer` extension pointing to address `X`.
2. Craft account `X` owned by `MetaplexID` with a valid Metaplex discriminator and `mint=M2` (a different mint), `name="USDC"`, `symbol="USDC"`.
3. Call `log_metadata` with `mint=M`, `metadata=Some(X)`.
4. Assert the Wormhole message payload deserializes to `LogMetadataPayload { token: M, name: "USDC", symbol: "USDC", decimals: M.decimals }`.

The check at line 78–82 passes (key match), the check at line 83 passes (owner is MetaplexID), `try_deserialize` succeeds (valid discriminator), and the forged name/symbol are emitted — confirming the missing `mpl.mint == self.mint.key()` guard. [7](#0-6)

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L72-90)
```rust
    fn parse_metadata_account(&self, address: Pubkey) -> Result<(String, String)> {
        let metadata = self
            .metadata
            .as_ref()
            .ok_or_else(|| error!(ErrorCode::TokenMetadataNotProvided))?
            .to_account_info();
        require_keys_eq!(
            metadata.key(),
            address,
            ErrorCode::InvalidTokenMetadataAddress,
        );
        if metadata.owner == &MetaplexID {
            let data = metadata.try_borrow_data()?;
            let metadata = MplMetadata::try_deserialize(&mut data.as_ref())?;
            Ok((metadata.name.clone(), metadata.symbol.clone()))
        } else {
            Ok((String::default(), String::default()))
        }
    }
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L104-106)
```rust
                } else if metadata_pointer.metadata_address.0 != Pubkey::default() {
                    // Third-party metadata
                    self.parse_metadata_account(metadata_pointer.metadata_address.0)?
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L117-127)
```rust
            self.parse_metadata_account(
                Pubkey::find_program_address(
                    &[
                        METADATA_SEED,
                        MetaplexID.as_ref(),
                        &self.mint.key().to_bytes(),
                    ],
                    &MetaplexID,
                )
                .0,
            )?
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L130-136)
```rust
        let payload = LogMetadataPayload {
            token: self.mint.key(),
            name: name.trim_end_matches('\0').to_string(),
            symbol: symbol.trim_end_matches('\0').to_string(),
            decimals: self.mint.decimals,
        }
        .serialize_for_near(())?;
```

**File:** solana/programs/bridge_token_factory/src/state/message/log_metadata.rs (L8-13)
```rust
pub struct LogMetadataPayload {
    pub token: Pubkey,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}
```

**File:** near/omni-bridge/src/lib.rs (L1165-1174)
```rust
        self.deploy_token_internal(
            chain,
            &metadata.token_address,
            BasicMetadata {
                name: metadata.name,
                symbol: metadata.symbol,
                decimals: metadata.decimals,
            },
            attached_deposit,
        )
```
