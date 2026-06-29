### Title
`set_admin()` Accepts Zero Pubkey Without Validation, Permanently Locking Admin Control of the Solana Bridge - (File: `solana/programs/bridge_token_factory/src/instructions/admin/change_config.rs`)

### Summary

The Solana bridge program's `set_admin()` function sets the new admin `Pubkey` directly without checking whether it equals `Pubkey::default()` (the all-zero pubkey). If the current admin accidentally passes the zero pubkey, admin control is permanently and irrecoverably lost, because the `ChangeConfig` constraint enforces `signer.key() == config.admin` — and no real keypair corresponds to the zero pubkey. Since unpausing the bridge also requires admin authorization through the same `ChangeConfig` context, a subsequent pause would permanently freeze all bridged funds on Solana.

### Finding Description

In `change_config.rs`, the `set_admin` implementation is:

```rust
pub fn set_admin(&mut self, admin: Pubkey) -> Result<()> {
    self.config.admin = admin;
    Ok(())
}
``` [1](#0-0) 

The `ChangeConfig` account constraint that gates every function in this module is:

```rust
#[account(
    mut,
    constraint = signer.key() == config.admin @ crate::error::ErrorCode::Unauthorized,
)]
pub signer: Signer<'info>,
``` [2](#0-1) 

Every admin-gated operation — `set_admin`, `set_pausable_admin`, `set_metadata_admin`, `set_derived_near_bridge_address`, and `set_paused` (unpause) — flows through this same `ChangeConfig` context. [3](#0-2) 

The top-level instruction dispatcher exposes `set_admin` as a public instruction with no additional validation:

```rust
pub fn set_admin(ctx: Context<ChangeConfig>, admin: Pubkey) -> Result<()> {
    msg!("Setting admin");
    ctx.accounts.set_admin(admin)?;
    Ok(())
}
``` [4](#0-3) 

No check of the form `require!(admin != Pubkey::default(), ...)` exists anywhere in the call path.

### Impact Explanation

If `set_admin` is called with `Pubkey::default()` (32 zero bytes):

1. `config.admin` is permanently set to the zero pubkey.
2. Every subsequent call to any `ChangeConfig` instruction requires `signer.key() == Pubkey::default()`, which is impossible to satisfy — no valid keypair produces the zero pubkey.
3. `set_paused` (the unpause path) is also gated by `ChangeConfig`, so the bridge can never be unpaused by anyone.
4. If the bridge is paused (by `pausable_admin` via `pause_all`, or by the admin before losing control), all user funds locked in the Solana bridge program are permanently frozen with no recovery path.

This matches the allowed critical impact: **permanent freezing of bridged funds on Solana**.

### Likelihood Explanation

The admin is a human operator who may pass a zero pubkey by mistake during a key rotation or scripted deployment. The zero pubkey is the Rust/Anchor default value for `Pubkey` and is trivially easy to pass accidentally. No on-chain guard prevents it. The original M-07 report was accepted on exactly this reasoning for an analogous admin setter.

### Recommendation

Add a zero-pubkey guard at the start of `set_admin` (and analogously for `set_pausable_admin` and `set_metadata_admin`):

```rust
pub fn set_admin(&mut self, admin: Pubkey) -> Result<()> {
    require!(admin != Pubkey::default(), crate::error::ErrorCode::InvalidAdmin);
    self.config.admin = admin;
    Ok(())
}
``` [1](#0-0) 

### Proof of Concept

1. Current admin calls the `set_admin` instruction with `admin = Pubkey::default()` (32 zero bytes).
2. `config.admin` is now `Pubkey::default()`.
3. Any subsequent `ChangeConfig` instruction (including `set_admin` to recover, or `set_paused` to unpause) requires a signer whose pubkey equals `Pubkey::default()` — impossible.
4. `pausable_admin` calls `pause_all`, pausing all bridge operations.
5. No one can call `set_paused(0)` to unpause, because that path requires `ChangeConfig` with `signer.key() == Pubkey::default()`.
6. All user funds in the Solana bridge are permanently frozen. [5](#0-4)

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/admin/change_config.rs (L1-53)
```rust
use anchor_lang::prelude::*;

use crate::{constants::CONFIG_SEED, state::config::Config};

#[derive(Accounts)]
pub struct ChangeConfig<'info> {
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bumps.config,
    )]
    pub config: Box<Account<'info, Config>>,

    #[account(
        mut,
        constraint = signer.key() == config.admin @ crate::error::ErrorCode::Unauthorized,
    )]
    pub signer: Signer<'info>,
}

impl ChangeConfig<'_> {
    pub fn set_admin(&mut self, admin: Pubkey) -> Result<()> {
        self.config.admin = admin;

        Ok(())
    }

    pub fn set_pausable_admin(&mut self, pausable_admin: Pubkey) -> Result<()> {
        self.config.pausable_admin = pausable_admin;

        Ok(())
    }

    pub fn set_paused(&mut self, paused: u8) -> Result<()> {
        self.config.paused = paused;

        Ok(())
    }

    pub fn set_metadata_admin(&mut self, metadata_admin: Pubkey) -> Result<()> {
        self.config.metadata_admin = metadata_admin;

        Ok(())
    }

    pub fn set_derived_near_bridge_address(
        &mut self,
        derived_near_bridge_address: [u8; 64],
    ) -> Result<()> {
        self.config.derived_near_bridge_address = derived_near_bridge_address;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L167-201)
```rust
    pub fn set_admin(ctx: Context<ChangeConfig>, admin: Pubkey) -> Result<()> {
        msg!("Setting admin");

        ctx.accounts.set_admin(admin)?;

        Ok(())
    }

    pub fn set_pausable_admin(ctx: Context<ChangeConfig>, pausable_admin: Pubkey) -> Result<()> {
        msg!("Setting pausable admin");

        ctx.accounts.set_pausable_admin(pausable_admin)?;

        Ok(())
    }

    pub fn set_metadata_admin(ctx: Context<ChangeConfig>, metadata_admin: Pubkey) -> Result<()> {
        msg!("Setting metadata admin");

        ctx.accounts.set_metadata_admin(metadata_admin)?;

        Ok(())
    }

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
