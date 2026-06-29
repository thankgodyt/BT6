### Title
Single-Step Admin Transfer Enables Permanent Loss of Bridge Control - (File: `solana/programs/bridge_token_factory/src/instructions/admin/change_config.rs`)

### Summary
The Solana `bridge_token_factory` program's `set_admin` instruction overwrites `config.admin` in a single atomic step with no confirmation from the incoming admin. If the current admin supplies an incorrect or attacker-controlled pubkey, control over the entire bridge program is irrecoverably transferred in one transaction, with no recovery path.

### Finding Description
`set_admin` in `change_config.rs` directly assigns the caller-supplied `admin: Pubkey` argument to `self.config.admin` with no intermediate pending-admin state and no acceptance step required from the new address. [1](#0-0) 

The `Config` account has no `pending_admin` field; the struct only stores the live `admin` pubkey. [2](#0-1) 

The `ChangeConfig` account constraint enforces that only the current `config.admin` may call this instruction, but it performs no validation on the *new* admin value. [3](#0-2) 

The public entry point in `lib.rs` passes the argument straight through. [4](#0-3) 

### Impact Explanation
The `admin` role is the sole authority for the following critical bridge operations:

- `set_derived_near_bridge_address` — changes the 64-byte MPC public key used to verify every `finalize_transfer` and `deploy_token` signed payload. [5](#0-4) 
- `unpause` — the only account that can lift a full bridge pause. [6](#0-5) 
- `set_pausable_admin`, `set_metadata_admin`, `set_admin` — full reconfiguration of all privileged roles. [7](#0-6) 

If `config.admin` is set to an attacker-controlled pubkey (whether by typo or social engineering of the key-holder), the attacker can immediately call `set_derived_near_bridge_address` to substitute their own MPC key, then produce valid-looking `SignedPayload<FinalizeTransferPayload>` messages that pass signature verification, minting arbitrary wrapped tokens to themselves. Alternatively, the attacker can permanently pause the bridge, freezing all user funds. Both outcomes fall within the critical allowed impact scope (unauthorized minting / permanent freezing of bridged funds).

### Likelihood Explanation
The likelihood is low but non-negligible. Solana pubkeys are 32-byte base58 strings with no human-readable structure; a single-character typo produces a syntactically valid but uncontrolled address. The operation is irreversible the moment the transaction lands. No off-chain tooling or on-chain guard prevents the mistake. The original audit report classified the identical pattern as Low severity, which is appropriate here as well.

### Recommendation
Introduce a two-step transfer pattern:

1. Add a `pending_admin: Option<Pubkey>` field to `Config`.
2. Replace `set_admin` with `propose_admin`, which writes only to `pending_admin`.
3. Add an `accept_admin` instruction gated on `signer.key() == config.pending_admin`, which moves `pending_admin` into `admin` and clears the pending slot.

This ensures the incoming admin proves key control before the transfer is finalised, eliminating the risk of accidental or unrecoverable transfers.

### Proof of Concept

1. Current admin calls `set_admin` with a pubkey that contains a one-character typo (or an attacker's pubkey).
2. The instruction executes: `self.config.admin = admin;` — `config.admin` is now the wrong address. [8](#0-7) 
3. The original admin can no longer call any `ChangeConfig`-gated instruction because the constraint `signer.key() == config.admin` now fails for them. [3](#0-2) 
4. If the new pubkey is attacker-controlled, the attacker calls `set_derived_near_bridge_address` with their own MPC key. [5](#0-4) 
5. The attacker crafts a `SignedPayload<FinalizeTransferPayload>` signed by their MPC key; `verify_signature` passes against the now-attacker-controlled `derived_near_bridge_address`, and `finalize_transfer` mints tokens to the attacker's recipient account. [9](#0-8)

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

**File:** solana/programs/bridge_token_factory/src/lib.rs (L78-94)
```rust
    pub fn finalize_transfer(
        ctx: Context<FinalizeTransfer>,
        data: SignedPayload<FinalizeTransferPayload>,
    ) -> Result<()> {
        require!(
            ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
        );
        msg!("Finalizing transfer");

        data.verify_signature(
            (ctx.accounts.mint.key(), ctx.accounts.recipient.key()),
            &ctx.accounts.common.config.derived_near_bridge_address,
        )?;
        ctx.accounts.process(data.payload)?;

        Ok(())
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L159-165)
```rust
    pub fn unpause(ctx: Context<ChangeConfig>, paused: u8) -> Result<()> {
        msg!("Unpausing");

        ctx.accounts.set_paused(paused)?;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L167-173)
```rust
    pub fn set_admin(ctx: Context<ChangeConfig>, admin: Pubkey) -> Result<()> {
        msg!("Setting admin");

        ctx.accounts.set_admin(admin)?;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L175-189)
```rust
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
