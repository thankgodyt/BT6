Looking at the full code path, I need to verify the critical check: whether `parse_metadata_account` enforces that the metadata account is the canonical PDA for the mint being registered.

### Title
Token-2022 Metadata Pointer Allows Forged Name/Symbol in LogMetadata Wormhole Message — (`solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs`)

### Summary

`LogMetadata::process` reads name/symbol from whatever Metaplex account the Token-2022 `metadata_pointer` extension points to, without verifying that account is the canonical PDA for the mint being registered. An attacker can create a Token-2022 mint whose pointer targets the real USDC (or any other token's) Metaplex metadata account, causing the bridge to emit a Wormhole message that binds the attacker's mint to a stolen name/symbol on NEAR.

### Finding Description

For classic SPL tokens, the code correctly derives the canonical Metaplex PDA from the mint's own pubkey:

```rust
// line 117-127 — canonical derivation, cannot be spoofed
Pubkey::find_program_address(
    &[METADATA_SEED, MetaplexID.as_ref(), &self.mint.key().to_bytes()],
    &MetaplexID,
).0
``` [1](#0-0) 

For Token-2022 mints with a third-party `metadata_pointer`, the code instead calls `parse_metadata_account` with whatever address the extension declares:

```rust
// line 104-106 — no canonical-PDA check
} else if metadata_pointer.metadata_address.0 != Pubkey::default() {
    // Third-party metadata
    self.parse_metadata_account(metadata_pointer.metadata_address.0)?
``` [2](#0-1) 

`parse_metadata_account` only checks two things: that the passed account's key equals the pointer address, and that the account is owned by `MetaplexID`. It does **not** check that the metadata account is the canonical PDA for `self.mint`:

```rust
require_keys_eq!(metadata.key(), address, ErrorCode::InvalidTokenMetadataAddress);
if metadata.owner == &MetaplexID {
    let metadata = MplMetadata::try_deserialize(&mut data.as_ref())?;
    Ok((metadata.name.clone(), metadata.symbol.clone()))
``` [3](#0-2) 

The resulting payload uses `self.mint.key()` (the attacker's mint) as the token identifier but the stolen name/symbol:

```rust
let payload = LogMetadataPayload {
    token: self.mint.key(),
    name: name.trim_end_matches('\0').to_string(),
    symbol: symbol.trim_end_matches('\0').to_string(),
    decimals: self.mint.decimals,
}.serialize_for_near(())?;
``` [4](#0-3) 

On NEAR, `deploy_token_callback` trusts the name/symbol from the Wormhole proof verbatim and deploys a new token contract with those strings:

```rust
self.deploy_token_internal(chain, &metadata.token_address,
    BasicMetadata { name: metadata.name, symbol: metadata.symbol, decimals: metadata.decimals },
    attached_deposit)
``` [5](#0-4) 

### Impact Explanation

The attacker controls M1's mint authority (the only constraint is `!mint.mint_authority.contains(authority.key)`, i.e., the bridge authority must **not** be the mint authority — so the attacker's own key is the mint authority). [6](#0-5) 

Full attack chain:
1. Attacker creates Token-2022 mint M1 with `metadata_pointer` = real USDC's Metaplex PDA.
2. Calls `log_metadata` passing the real USDC Metaplex account as `metadata`.
3. Both checks pass (`key` matches pointer, `owner == MetaplexID`); name='USD Coin', symbol='USDC' are read.
4. Wormhole message emitted: `token=M1, name='USD Coin', symbol='USDC'`.
5. NEAR `deploy_token` deploys a new NEAR token contract with name/symbol='USDC' bound to Solana:M1.
6. Attacker mints unlimited M1 tokens (they hold mint authority), bridges them to NEAR, receives fake "USDC".
7. Attacker sells fake "USDC" to users who cannot distinguish it from the legitimate bridged USDC.

This is unauthorized minting of a token that impersonates a high-value asset, causing direct financial loss to users who acquire the fake token.

### Likelihood Explanation

The preconditions are trivially satisfiable on mainnet: creating a Token-2022 mint with an arbitrary `metadata_pointer` is a standard SPL operation requiring no special permissions. The real USDC Metaplex metadata account is a public, immutable on-chain account. No admin compromise, key leak, or guardian collusion is required.

### Recommendation

In the Token-2022 third-party metadata branch, derive and enforce the canonical Metaplex PDA for the mint being registered, exactly as is done for classic SPL tokens:

```rust
} else if metadata_pointer.metadata_address.0 != Pubkey::default() {
    let canonical = Pubkey::find_program_address(
        &[METADATA_SEED, MetaplexID.as_ref(), &self.mint.key().to_bytes()],
        &MetaplexID,
    ).0;
    require_keys_eq!(
        metadata_pointer.metadata_address.0,
        canonical,
        ErrorCode::InvalidTokenMetadataAddress,
    );
    self.parse_metadata_account(canonical)?
```

This ensures the metadata account is always the one Metaplex created specifically for this mint, making it impossible to borrow another token's metadata.

### Proof of Concept

```rust
// localnet test sketch
// 1. Create real-USDC-like mint with Metaplex metadata
let usdc_mint = create_mint(...);
let usdc_metadata_pda = find_metaplex_pda(usdc_mint);
create_metaplex_metadata(usdc_mint, "USD Coin", "USDC", ...);

// 2. Create attacker's Token-2022 mint with metadata_pointer → usdc_metadata_pda
let attacker_mint = create_token2022_mint_with_metadata_pointer(usdc_metadata_pda);
// attacker_mint.mint_authority = attacker (satisfies !contains(authority))

// 3. Call log_metadata with attacker_mint, passing usdc_metadata_pda as `metadata`
log_metadata(ctx: { mint: attacker_mint, metadata: Some(usdc_metadata_pda), ... });

// 4. Assert Wormhole message payload
let payload = decode_wormhole_message(...);
assert_eq!(payload.token, attacker_mint.pubkey());
assert_eq!(payload.name, "USD Coin");   // stolen from real USDC
assert_eq!(payload.symbol, "USDC");     // stolen from real USDC

// 5. On NEAR: deploy_token with this proof → NEAR deploys fake "USDC" bound to attacker_mint
// 6. Attacker mints unlimited attacker_mint tokens, bridges to NEAR, receives fake "USDC"
```

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L41-45)
```rust
    #[account(
        constraint = !mint.mint_authority.contains(authority.key),
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L78-89)
```rust
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
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L104-106)
```rust
                } else if metadata_pointer.metadata_address.0 != Pubkey::default() {
                    // Third-party metadata
                    self.parse_metadata_account(metadata_pointer.metadata_address.0)?
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L115-128)
```rust
        } else {
            // Only metaplex is supported for the classic SPL tokens
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

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L130-138)
```rust
        let payload = LogMetadataPayload {
            token: self.mint.key(),
            name: name.trim_end_matches('\0').to_string(),
            symbol: symbol.trim_end_matches('\0').to_string(),
            decimals: self.mint.decimals,
        }
        .serialize_for_near(())?;

        self.common.post_message(payload)?;
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
