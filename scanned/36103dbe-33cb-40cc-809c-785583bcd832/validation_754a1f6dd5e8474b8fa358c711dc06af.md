### Title
Single-Step Admin Transfer Enables Permanent Loss of Bridge Control and Unauthorized Token Minting - (File: `solana/programs/bridge_token_factory/src/instructions/admin/change_config.rs`)

### Summary
The Solana `bridge_token_factory` program's `set_admin` instruction transfers the `admin` role in a single step with no confirmation from the new address. If the admin is erroneously set to a wrong or attacker-controlled key, the attacker gains the ability to call `set_derived_near_bridge_address`, replacing the MPC verification key used by `finalize_transfer` and `deploy_token`, enabling unauthorized minting of bridged tokens.

### Finding Description
`set_admin` in `change_config.rs` immediately overwrites `config.admin` with the caller-supplied `Pubkey`:

```rust
pub fn set_admin(&mut self, admin: Pubkey) -> Result<()> {
    self.config.admin = admin;
    Ok(())
}
``` [1](#0-0) 

There is no pending-admin state, no acceptance step, and no confirmation that the new address is reachable. The `ChangeConfig` account constraint only verifies that the *current* signer matches `config.admin`:

```rust
constraint = signer.key() == config.admin @ crate::error::ErrorCode::Unauthorized,
``` [2](#0-1) 

The `admin` field in `Config` is the sole key that gates all of the following privileged instructions via the `ChangeConfig` context: `set_admin`, `set_pausable_admin`, `set_metadata_admin`, `unpause`, and critically `set_derived_near_bridge_address`. [3](#0-2) 

`set_derived_near_bridge_address` replaces the 64-byte uncompressed public key stored in `config.derived_near_bridge_address`, which is the sole trust anchor used by `verify_signature` to authenticate every `finalize_transfer` and `deploy_token` call:

```rust
require!(
    signer.0 == *derived_near_bridge_address,
    ErrorCode::SignatureVerificationFailed
);
``` [4](#0-3) 

Both `finalize_transfer` and `finalize_transfer_sol` pass `config.derived_near_bridge_address` directly into `verify_signature`: [5](#0-4) [6](#0-5) 

### Impact Explanation
If `set_admin` is called with an attacker-controlled `Pubkey` (e.g., due to a typo, clipboard hijack, or operational error during key rotation), the attacker immediately holds full admin authority. They can then:

1. Call `set_derived_near_bridge_address` to replace the NEAR MPC verification key with a key they control.
2. Construct and self-sign arbitrary `FinalizeTransferPayload` messages.
3. Call `finalize_transfer` or `finalize_transfer_sol` with those forged payloads, passing signature verification, and mint or unlock any amount of bridged tokens (SPL tokens or native SOL) to any recipient.

This constitutes unauthorized minting and theft of all bridged funds held by the program. If the wrong address is inaccessible (e.g., zero key or a burned address), the bridge is permanently bricked: `unpause`, `set_derived_near_bridge_address`, and all other admin functions become permanently unreachable.

### Likelihood Explanation
Admin key rotation is a routine operational task. A single-character typo in a 32-byte base58 Solana public key, a clipboard substitution attack, or a misconfigured deployment script is a realistic and historically observed failure mode. The absence of any confirmation step means there is no recovery window once the transaction is confirmed.

### Recommendation
Implement a two-step admin transfer:
1. **Propose step (`propose_admin`)**: The current admin writes a `pending_admin: Option<Pubkey>` field in `Config` (the `padding: [u8; 35]` field provides space for this).
2. **Accept step (`accept_admin`)**: Only the account whose key matches `pending_admin` can call this, which then atomically sets `config.admin = pending_admin` and clears `pending_admin`.

Add a separate `renounce_admin` instruction if intentional relinquishment is needed.

### Proof of Concept
1. Current admin holds `config.admin = ADMIN_KEY`.
2. Admin calls `set_admin(ATTACKER_KEY)` (e.g., wrong key due to typo). `config.admin` is immediately set to `ATTACKER_KEY` with no confirmation required.
3. Attacker calls `set_derived_near_bridge_address(ATTACKER_SECP256K1_PUBKEY_BYTES)`. `config.derived_near_bridge_address` is now the attacker's own secp256k1 public key.
4. Attacker constructs a `FinalizeTransferPayload` with `destination_nonce = N`, `amount = MAX`, `fee_recipient = None`, targeting any SPL token mint with a large vault balance.
5. Attacker signs the Borsh-serialized payload with their secp256k1 private key.
6. Attacker calls `finalize_transfer` with the forged `SignedPayload`. `verify_signature` recovers the attacker's key, which now matches `derived_near_bridge_address`, so verification passes.
7. The program mints or unlocks the full token amount to the attacker's address. [7](#0-6) [8](#0-7)

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/admin/change_config.rs (L14-18)
```rust
    #[account(
        mut,
        constraint = signer.key() == config.admin @ crate::error::ErrorCode::Unauthorized,
    )]
    pub signer: Signer<'info>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/admin/change_config.rs (L22-26)
```rust
    pub fn set_admin(&mut self, admin: Pubkey) -> Result<()> {
        self.config.admin = admin;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/state/config.rs (L20-28)
```rust
pub struct Config {
    pub admin: Pubkey,
    pub max_used_nonce: u64,
    pub derived_near_bridge_address: [u8; 64],
    pub bumps: ConfigBumps,
    pub paused: u8,
    pub pausable_admin: Pubkey,
    pub metadata_admin: Pubkey,
    pub padding: [u8; 35],
```

**File:** solana/programs/bridge_token_factory/src/state/message/mod.rs (L41-44)
```rust
        require!(
            signer.0 == *derived_near_bridge_address,
            ErrorCode::SignatureVerificationFailed
        );
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L88-91)
```rust
        data.verify_signature(
            (ctx.accounts.mint.key(), ctx.accounts.recipient.key()),
            &ctx.accounts.common.config.derived_near_bridge_address,
        )?;
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L107-110)
```rust
        data.verify_signature(
            (Pubkey::default(), ctx.accounts.recipient.key()),
            &ctx.accounts.config.derived_near_bridge_address,
        )?;
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L167-173)
```rust
    pub fn set_admin(ctx: Context<ChangeConfig>, admin: Pubkey) -> Result<()> {
        msg!("Setting admin");

        ctx.accounts.set_admin(admin)?;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L191-201)
```rust
    pub fn set_derived_near_bridge_address(
        ctx: Context<ChangeConfig>,
        derived_near_bridge_address: [u8; 64],
    ) -> Result<()> {
        msg!("Setting derived NEAR bridge address");

        ctx.accounts
            .set_derived_near_bridge_address(derived_near_bridge_address)?;

        Ok(())
    }
```
