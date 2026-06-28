### Title
Single-Step Admin Transfer Permanently Bricks Solana Bridge - (`solana/programs/bridge_token_factory/src/instructions/admin/change_config.rs`)

### Summary
The Solana `bridge_token_factory` program's `set_admin` instruction overwrites `config.admin` in a single atomic step with no pending-state or confirmation mechanism. If the current admin passes a wrong or inaccessible `Pubkey`, the admin role is permanently lost and every admin-gated operation becomes unreachable forever.

### Finding Description
`set_admin` in `ChangeConfig` directly writes the caller-supplied pubkey into `config.admin` with no two-step confirmation:

```rust
pub fn set_admin(&mut self, admin: Pubkey) -> Result<()> {
    self.config.admin = admin;
    Ok(())
}
``` [1](#0-0) 

The `ChangeConfig` account constraint enforces that only the current admin can invoke any of these instructions:

```rust
#[account(
    mut,
    constraint = signer.key() == config.admin @ crate::error::ErrorCode::Unauthorized,
)]
pub signer: Signer<'info>,
``` [2](#0-1) 

Every admin-gated instruction — `unpause`, `set_admin`, `set_pausable_admin`, `set_metadata_admin`, and `set_derived_near_bridge_address` — uses this same `ChangeConfig` context: [3](#0-2) 

The `Config` struct stores the single `admin` pubkey with no fallback or recovery field: [4](#0-3) 

### Impact Explanation
If `set_admin` is called with a wrong pubkey (typo, burned address, address the caller does not control), the following become permanently impossible:

1. **`unpause`** — the bridge can be paused by `pausable_admin` but can never be unpaused, permanently freezing all in-flight and future Solana-side bridged funds.
2. **`set_derived_near_bridge_address`** — the NEAR MPC-derived address used to verify every `deploy_token` and `finalize_transfer` signature cannot be updated. Any MPC key rotation or bridge address change makes the program unable to process any new cross-chain transfer.
3. **`set_admin`** — admin cannot be recovered; there is no super-admin or recovery path.

This constitutes permanent freezing of bridged funds on the Solana leg of the bridge, matching the Critical impact tier.

### Likelihood Explanation
Low. Requires an operational error by the current admin (e.g., copy-paste mistake, wrong clipboard content, or passing a pubkey for which the private key is unavailable). No attacker action is needed; the admin is the sole actor.

### Recommendation
Implement a two-step admin transfer pattern:
1. Add a `pending_admin: Option<Pubkey>` field to `Config`.
2. `set_admin` writes only to `pending_admin`.
3. Add a new `accept_admin` instruction that requires `signer.key() == config.pending_admin` and then promotes `pending_admin` to `admin`.

This ensures the new admin can sign a transaction before the old admin loses control.

### Proof of Concept
1. Current admin calls `set_admin` with `new_admin = Pubkey::new_unique()` (a key for which no private key exists).
2. `config.admin` is immediately overwritten.
3. Any subsequent call to `unpause`, `set_admin`, `set_pausable_admin`, `set_metadata_admin`, or `set_derived_near_bridge_address` fails with `ErrorCode::Unauthorized` (error code 6009) because no signer can satisfy `signer.key() == config.admin`.
4. If `pausable_admin` then calls `pause`, the bridge is permanently paused with no recovery path — all Solana-side bridged token minting and SOL vault withdrawals are frozen indefinitely.

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

**File:** solana/programs/bridge_token_factory/src/lib.rs (L159-201)
```rust
    pub fn unpause(ctx: Context<ChangeConfig>, paused: u8) -> Result<()> {
        msg!("Unpausing");

        ctx.accounts.set_paused(paused)?;

        Ok(())
    }

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
