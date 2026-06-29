Audit Report

## Title
Token-2022 Metadata Pointer Allows Forged Name/Symbol in LogMetadata Wormhole Message — (`solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs`)

## Summary

`LogMetadata::process` reads name/symbol from whatever Metaplex account the Token-2022 `metadata_pointer` extension declares, without verifying that account is the canonical PDA derived from the mint being registered. An attacker can create a Token-2022 mint whose `metadata_pointer` targets the real USDC (or any other token's) Metaplex metadata account, causing the bridge to emit a Wormhole message binding the attacker's mint to a stolen name/symbol on NEAR, enabling unlimited minting of a token that impersonates a high-value asset.

## Finding Description

For classic SPL tokens, `process` correctly derives the canonical Metaplex PDA from the mint's own pubkey before calling `parse_metadata_account`, making spoofing impossible: [1](#0-0) 

For Token-2022 mints with a third-party `metadata_pointer`, the code instead passes the pointer's declared address directly to `parse_metadata_account` with no canonical derivation: [2](#0-1) 

`parse_metadata_account` only checks two things: that the passed account's key equals the pointer address, and that the account is owned by `MetaplexID`. It does **not** check that the metadata account is the canonical PDA for `self.mint`: [3](#0-2) 

Both checks pass trivially when the attacker's `metadata_pointer` is set to the real USDC Metaplex PDA: the key matches the pointer, and the account is owned by MetaplexID. The resulting Wormhole payload uses `self.mint.key()` (the attacker's mint) as the token identifier but the stolen name/symbol: [4](#0-3) 

The only constraint on the mint is that the bridge authority must not be the mint authority — an attacker's own mint trivially satisfies this: [5](#0-4) 

This is not listed as a known design decision or accepted risk in `solana/SECURITY.md`. [6](#0-5) 

## Impact Explanation

This is **unauthorized minting** and **token metadata binding confusion** matching the Critical allowed impact scope. The attacker mints unlimited tokens of their own mint M1, bridges them to NEAR, and receives NEAR-side tokens that carry the name/symbol of a legitimate high-value asset (e.g., "USD Coin"/"USDC"). Users who acquire these NEAR tokens cannot distinguish them from legitimately bridged USDC, resulting in direct financial loss. The NEAR `deploy_token_internal` call trusts the name/symbol from the Wormhole proof verbatim, so the fake binding is permanent once deployed.

## Likelihood Explanation

Preconditions are trivially satisfiable on mainnet with no special permissions. Creating a Token-2022 mint with an arbitrary `metadata_pointer` is a standard SPL operation. The real USDC Metaplex metadata account is a public, immutable on-chain account. No admin compromise, key leak, guardian collusion, or victim mistake is required. The attack is repeatable for any token whose Metaplex metadata exists on-chain.

## Recommendation

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

## Proof of Concept

```rust
// localnet test sketch
// 1. Create real-USDC-like mint with Metaplex metadata
let usdc_mint = create_mint(...);
let usdc_metadata_pda = find_metaplex_pda(usdc_mint); // canonical PDA for usdc_mint
create_metaplex_metadata(usdc_mint, "USD Coin", "USDC", ...);

// 2. Create attacker's Token-2022 mint with metadata_pointer → usdc_metadata_pda
let attacker_mint = create_token2022_mint_with_metadata_pointer(usdc_metadata_pda);
// attacker_mint.mint_authority = attacker (satisfies !contains(authority))

// 3. Call log_metadata with attacker_mint, passing usdc_metadata_pda as `metadata`
log_metadata(ctx: { mint: attacker_mint, metadata: Some(usdc_metadata_pda), ... });
// parse_metadata_account: key matches pointer ✓, owner == MetaplexID ✓ → reads "USD Coin"/"USDC"

// 4. Assert Wormhole message payload
let payload = decode_wormhole_message(...);
assert_eq!(payload.token, attacker_mint.pubkey()); // attacker's mint
assert_eq!(payload.name, "USD Coin");              // stolen from real USDC
assert_eq!(payload.symbol, "USDC");               // stolen from real USDC

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

**File:** solana/SECURITY.md (L1-19)
```markdown
# Security Notes — Solana Bridge Token Factory

## Design Decisions (Non-Issues)

Items reviewed and confirmed as intentional:

- **`initialize` requires `program: Signer` with `address = crate::ID`** — Standard pattern ensuring `initialize` can only be called during program deployment. Not a vulnerability.
- **`deploy_token` and `log_metadata` are not subject to pause controls** — These require a valid MPC signature (`deploy_token`) or are read-only metadata operations (`log_metadata`). Pausing them adds no security value.
- **Initialization Wormhole message has placeholder payload (`vec![0]`)** — The init message exists solely to bootstrap the Wormhole sequence tracker. Payload content is irrelevant.
- **`unpause` accepts arbitrary `u8` value** — Only callable by admin. Naming is slightly misleading but functionally correct as a `set_pause_state` operation.
- **Wrapped tokens are always classic SPL Token, not Token-2022** — Intentional design decision. Bridged mints don't need Token-2022 extensions.

## Known Issues

Low-severity items acknowledged but not yet addressed:

- **No validation of `recipient` string in `InitTransferPayload`** — An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed.
- **No validation of `fee_recipient` length in `FinalizeTransferPayload`** — Excessively large strings increase Wormhole message size. Bounded by Solana tx size limits in practice.
- **Token-2022 tokens with transfer hooks are not supported** — Transfer hook extra account metas are not included in instruction account sets. Affected tokens will fail at runtime (denial, not fund loss).
```
