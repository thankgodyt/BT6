### Title
Token-2022 Third-Party Metaplex Metadata Cross-Mint Spoofing in `log_metadata` — (`solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs`)

---

### Summary

`parse_metadata_account` validates that a supplied Metaplex metadata account is owned by `MetaplexID` and matches the address stored in the Token-2022 `metadata_pointer` extension, but **never verifies that the metadata account's `mint` field equals the Token-2022 mint being logged**. An attacker who controls a Token-2022 mint can point its `metadata_pointer` at a valid Metaplex metadata account they created for a *different* SPL mint — one with attacker-chosen `name` and `symbol` — causing `log_metadata` to emit a Wormhole message to NEAR that binds arbitrary metadata to the attacker's Token-2022 mint address.

---

### Finding Description

The vulnerable path is the Token-2022 "third-party metadata" branch in `process`: [1](#0-0) 

When `metadata_pointer.metadata_address` is neither the mint itself nor `Pubkey::default()`, the code calls: [2](#0-1) 

`parse_metadata_account` performs exactly two checks:
1. `require_keys_eq!(metadata.key(), address, ...)` — the passed-in account key matches the pointer address.
2. `metadata.owner == &MetaplexID` — the account is owned by the Metaplex program.

It then deserializes the account as `MplMetadata` and returns `(metadata.name, metadata.symbol)` **without ever asserting `metadata.mint == self.mint.key()`**.

Contrast this with the classic SPL token path, which derives the canonical Metaplex PDA from the mint's own pubkey via `Pubkey::find_program_address`, making cross-mint substitution impossible: [3](#0-2) 

The emitted payload uses the Token-2022 mint's actual address and decimals, but the attacker-supplied name/symbol: [4](#0-3) 

---

### Impact Explanation

NEAR's `log_metadata_callback` trusts the name and symbol from the Wormhole VAA payload verbatim: [5](#0-4) 

An attacker can register a Token-2022 mint on NEAR with the name "USD Coin" and symbol "USDC" (or any other well-known token's identity), while the token address is the attacker's own worthless mint. Any NEAR-side protocol, DEX, or wallet that displays or routes by `name`/`symbol` will show the attacker's token as if it were the legitimate asset. Users who bridge funds expecting to receive the real token will instead receive the attacker's token, resulting in direct financial loss. This is token metadata binding confusion causing incorrect user balances.

---

### Likelihood Explanation

The attack requires no privileged access. Any user can:
- Create an SPL mint and call Metaplex to register arbitrary `name`/`symbol` metadata for it (fully permissionless).
- Create a Token-2022 mint with a `metadata_pointer` extension pointing to that Metaplex account.
- Call `log_metadata` — a public, unpermissioned instruction — for the Token-2022 mint.

No admin keys, guardian compromise, or validator collusion is needed. The entire attack is executable on a local validator or private testnet.

---

### Recommendation

After deserializing the Metaplex metadata account in `parse_metadata_account`, assert that its `mint` field matches the Token-2022 mint being logged:

```rust
// After: let metadata = MplMetadata::try_deserialize(&mut data.as_ref())?;
require_keys_eq!(
    metadata.mint,
    self.mint.key(),
    ErrorCode::InvalidTokenMetadataAddress,
);
```

This mirrors the implicit guarantee already present in the classic SPL path, where the Metaplex PDA is derived from the mint's own pubkey.

---

### Proof of Concept

1. Create SPL mint `M1`. Call Metaplex `create_metadata_accounts_v3` for `M1` with `name = "USD Coin"`, `symbol = "USDC"`. The resulting metadata account `META_M1` is at PDA `[b"metadata", MetaplexID, M1]`, owned by `MetaplexID`, and contains the attacker's chosen strings.

2. Create Token-2022 mint `M2` with a `MetadataPointer` extension whose `metadata_address` is set to `META_M1`.

3. Call `log_metadata` on the bridge program, passing `mint = M2`, `metadata = META_M1`.

4. Inside `parse_metadata_account`:
   - `require_keys_eq!(META_M1.key(), META_M1)` — passes.
   - `META_M1.owner == MetaplexID` — passes.
   - `MplMetadata::try_deserialize` succeeds (valid Metaplex account).
   - Returns `("USD Coin", "USDC")`.
   - **`metadata.mint == M1 != M2`** — never checked.

5. The Wormhole message is posted with `token = M2`, `name = "USD Coin"`, `symbol = "USDC"`, `decimals = M2.decimals`.

6. NEAR receives the VAA, calls `log_metadata_callback`, and registers `M2` on NEAR as "USD Coin / USDC", binding false metadata to the attacker's mint address.

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

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L98-106)
```rust
            if let Ok(metadata_pointer) = mint_with_extension.get_extension::<MetadataPointer>() {
                if metadata_pointer.metadata_address.0 == self.mint.key() {
                    // Embedded metadata
                    let metadata =
                        mint_with_extension.get_variable_len_extension::<TokenMetadata>()?;
                    (metadata.name, metadata.symbol)
                } else if metadata_pointer.metadata_address.0 != Pubkey::default() {
                    // Third-party metadata
                    self.parse_metadata_account(metadata_pointer.metadata_address.0)?
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L117-128)
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
        };
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

**File:** near/omni-bridge/src/lib.rs (L341-347)
```rust
        let metadata_payload = MetadataPayload {
            prefix: PayloadType::Metadata,
            token: token_id.to_string(),
            name: metadata.name,
            symbol: metadata.symbol,
            decimals: metadata.decimals,
        };
```
