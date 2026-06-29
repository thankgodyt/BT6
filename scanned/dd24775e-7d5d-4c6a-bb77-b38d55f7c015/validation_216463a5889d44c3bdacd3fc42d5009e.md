### Title
Missing PDA Seed Checks for `metadata` Account in `LogMetadata` Instruction Enables Token Metadata Binding Confusion — (File: `solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs`)

---

### Summary

The `LogMetadata` Anchor accounts struct accepts the Metaplex `metadata` account as an `Option<UncheckedAccount<'info>>` with **no PDA seed derivation, no program-ownership constraint, and no initialization check**. Any unprivileged caller can supply an arbitrary account in place of the real Metaplex metadata PDA for the given mint, causing the bridge to emit a Wormhole message to NEAR containing attacker-controlled token metadata (name, symbol).

---

### Finding Description

In `log_metadata.rs`, the metadata field is declared as:

```rust
/// CHECK: may be unitialized
pub metadata: Option<UncheckedAccount<'info>>,
``` [1](#0-0) 

The Metaplex Token Metadata PDA for a given mint is deterministically derived from seeds `["metadata", mpl_token_metadata::ID, mint_pubkey]`. Without constraining the `metadata` account to these seeds and verifying its program ownership, the program cannot confirm that the supplied account is the authentic metadata record for the provided `mint`.

By contrast, every other security-sensitive account in the same struct is properly constrained. The `mint` is typed as a verified `InterfaceAccount<'info, Mint>`:

```rust
#[account(
    constraint = !mint.mint_authority.contains(authority.key),
    mint::token_program = token_program,
)]
pub mint: Box<InterfaceAccount<'info, Mint>>,
``` [2](#0-1) 

And the `vault` is PDA-constrained to the mint:

```rust
seeds = [VAULT_SEED, mint.key().as_ref()],
``` [3](#0-2) 

The `metadata` account is the sole account that carries no binding to the `mint` whatsoever. An attacker can pass:
- The Metaplex metadata account of a **different, high-value mint** (e.g., USDC's metadata PDA) while supplying a worthless mint as `mint`.
- A hand-crafted raw account with arbitrary `name`/`symbol` bytes in the positions the process function reads.

The `deploy_token` instruction shows that the bridge reads `name` and `symbol` from the Metaplex metadata account and forwards them in the Wormhole payload to NEAR:

```rust
create_metadata_accounts_v3(cpi_ctx, DataV2 {
    name: metadata.name,
    symbol: metadata.symbol,
    ...
}, ...)?;
``` [4](#0-3) 

The same pattern applies to `log_metadata`: the name/symbol read from the unchecked account are serialized into the Wormhole message that NEAR uses to deploy the bridge token.

---

### Impact Explanation

An attacker calls `log_metadata` with a legitimate but worthless mint and a fake `metadata` account containing the name and symbol of a high-value token (e.g., `"USD Coin"` / `"USDC"`). The bridge emits a Wormhole message to NEAR associating the worthless Solana mint with the USDC name/symbol. NEAR deploys a bridge token labeled `"USDC"` backed by the worthless Solana mint. Users who rely on the bridge token's on-chain name/symbol to identify the asset they are receiving are deceived into accepting worthless tokens — a direct token metadata binding confusion leading to user fund loss.

---

### Likelihood Explanation

`log_metadata` is a **permissionless instruction** callable by any user with no role check or admin gate. The attacker only needs to supply a crafted account in the optional `metadata` field, which requires no special privilege and is trivially achievable on-chain.

---

### Recommendation

Add explicit PDA seed and program-ownership constraints to the `metadata` account, binding it to the provided `mint`:

```rust
#[account(
    seeds = [
        b"metadata",
        mpl_token_metadata::ID.as_ref(),
        mint.key().as_ref(),
    ],
    seeds::program = mpl_token_metadata::ID,
    bump,
)]
pub metadata: Option<Account<'info, MetadataAccount>>,
```

This ensures the account is the canonical Metaplex metadata PDA for the provided mint and is owned by the Token Metadata program, directly mirroring the fix applied in the referenced Solana NFT report (PR #94).

---

### Proof of Concept

1. Attacker creates a worthless SPL mint `M_fake` (supply = 1 billion, decimals = 6).
2. Attacker obtains the existing Metaplex metadata PDA for USDC (`M_usdc_meta`), which contains `name = "USD Coin"`, `symbol = "USDC"`.
3. Attacker calls `log_metadata` with `mint = M_fake` and `metadata = Some(M_usdc_meta)`.
4. The program reads `name`/`symbol` from `M_usdc_meta` (no seed check prevents this) and posts a Wormhole message to NEAR: `{ solana_mint: M_fake, name: "USD Coin", symbol: "USDC", decimals: 6 }`.
5. NEAR receives the VAA, trusts the metadata, and deploys a bridge token labeled `"USD Coin (USDC)"` backed by `M_fake`.
6. Victims bridging `M_fake` from Solana receive a NEAR token labeled `"USDC"`, while the attacker holds the supply of `M_fake` and can redeem the NEAR-side "USDC" tokens for real value from deceived counterparties.

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L41-45)
```rust
    #[account(
        constraint = !mint.mint_authority.contains(authority.key),
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L47-48)
```rust
    /// CHECK: may be unitialized
    pub metadata: Option<UncheckedAccount<'info>>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L55-58)
```rust
        seeds = [
            VAULT_SEED,
            mint.key().as_ref(),
        ],
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/deploy_token.rs (L94-108)
```rust
        create_metadata_accounts_v3(
            cpi_ctx,
            DataV2 {
                name: metadata.name,
                symbol: metadata.symbol,
                uri: String::new(),
                seller_fee_basis_points: 0,
                creators: None,
                collection: None,
                uses: None,
            },
            true, // TODO: Maybe better to make it immutable
            true,
            None,
        )?;
```
