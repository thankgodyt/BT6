### Title
`FinalizeTransferPayload` Does Not Bind the `mint` Account, Enabling Vault Substitution and Fund Theft — (`File: solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs`)

### Summary

The Solana `finalize_transfer` instruction accepts a NEAR-MPC-signed `FinalizeTransferPayload` that contains `destination_nonce`, `transfer_id`, `amount`, and `fee_recipient` — but **not** the mint address. The `mint` account passed by the caller is constrained only by `mint::token_program = token_program`. Because the vault PDA is derived from the caller-supplied mint, an attacker can substitute any native-token mint, drain its vault, and permanently consume the nonce that was meant for the original transfer.

### Finding Description

In `finalize_transfer.rs`, the `FinalizeTransfer` account struct constrains the `mint` field only as:

```rust
#[account(
    mut,
    mint::token_program = token_program,
)]
pub mint: Box<InterfaceAccount<'info, Mint>>,
``` [1](#0-0) 

The vault is then derived deterministically from that caller-supplied mint:

```rust
#[account(
    mut,
    token::mint = mint,
    token::authority = authority,
    seeds = [VAULT_SEED, mint.key().as_ref()],
    bump,

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L53-57)
```rust
    #[account(
        mut,
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
```
