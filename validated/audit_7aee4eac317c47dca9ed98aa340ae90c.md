Audit Report

## Title
`deploy_token` Lacks Pause Check, Bypassing Emergency Pause Mechanism — (`solana/programs/bridge_token_factory/src/lib.rs`)

## Summary

The Solana `bridge_token_factory` program defines a pause mechanism with two flags (`INIT_TRANSFER_PAUSED`, `FINALIZE_TRANSFER_PAUSED`) and enforces them on all four transfer instructions. However, the `deploy_token` instruction contains no pause check, meaning it remains fully callable even when the bridge is in a fully-paused emergency state. This constitutes a pause bypass — an explicitly listed Critical impact — allowing any party holding a valid pre-signed `DeployTokenPayload` to register new token mints and mappings on Solana during an emergency pause window.

## Finding Description

`constants.rs` defines `ALL_PAUSED` as only covering the two transfer flags: [1](#0-0) 

The `pause()` instruction sets `config.paused = ALL_PAUSED`, which only covers bits 0 and 1: [2](#0-1) 

All four transfer instructions correctly gate on the pause flags. For example, `finalize_transfer`: [3](#0-2) 

And `init_transfer`: [4](#0-3) 

But `deploy_token` has no such guard — it only verifies the signature and immediately executes: [5](#0-4) 

By contrast, the EVM implementation defines `PAUSED_DEPLOY_TOKEN = 1 << 2` and gates `deployToken` on it, and the Starknet implementation similarly asserts `!_is_paused(@self, PAUSE_DEPLOY_TOKEN)` at the top of its `deploy_token`. Neither of these guards exists in the Solana program.

## Impact Explanation

This is a **pause bypass** — an explicitly listed Critical impact. When the bridge operator triggers an emergency pause, the intent is to halt all bridge operations. Because `deploy_token` is not gated, any party holding a valid pre-signed `SignedPayload<DeployTokenPayload>` — obtained from the NEAR MPC network before the pause — can still submit it to Solana and register a new token mint and mapping. This defeats the purpose of the emergency pause mechanism and allows new token registrations (bridge/token deployer actions) to proceed unconditionally during a crisis window.

## Likelihood Explanation

Realistic. Relayers routinely obtain signed `DeployTokenPayload` messages from the NEAR MPC network and submit them to Solana. Any such payload signed before the pause but not yet submitted can be submitted during the pause window. No admin compromise, key theft, or privileged access is required — only possession of a legitimately-issued but unsubmitted signed payload. The exploit is repeatable for every unsubmitted payload in flight at the time of the pause.

## Recommendation

Add a `DEPLOY_TOKEN_PAUSED` constant and include it in `ALL_PAUSED`:

```rust
// In constants.rs
#[constant]
pub const DEPLOY_TOKEN_PAUSED: u8 = 1 << 2;

#[constant]
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED;
```

Enforce it at the top of `deploy_token` in `lib.rs`, mirroring the pattern used by `finalize_transfer` and `init_transfer`:

```rust
pub fn deploy_token(
    ctx: Context<DeployToken>,
    data: SignedPayload<DeployTokenPayload>,
) -> Result<()> {
    require!(
        ctx.accounts.common.config.paused & DEPLOY_TOKEN_PAUSED == 0,
        error::ErrorCode::Paused
    );
    msg!("Deploying token");
    data.verify_signature((), &ctx.accounts.common.config.derived_near_bridge_address)?;
    ctx.accounts.initialize_token_metadata(data.payload)?;
    Ok(())
}
```

Also import `DEPLOY_TOKEN_PAUSED` in the `use super::constants` line in `lib.rs`.

## Proof of Concept

1. Admin calls `pause()` on the Solana `bridge_token_factory`. `config.paused` is set to `ALL_PAUSED = 0x03` (bits 0 and 1 only).
2. Confirm `init_transfer` and `finalize_transfer` revert with `Paused` — they do, as their `require!` checks fire.
3. A relayer holds a `SignedPayload<DeployTokenPayload>` that was signed by the NEAR MPC before the pause was triggered.
4. The relayer calls `deploy_token` with this payload. The instruction has no `require!` pause check, so execution proceeds unconditionally.
5. `data.verify_signature(...)` passes (the signature is valid and was legitimately issued).
6. `ctx.accounts.initialize_token_metadata(data.payload)` executes, registering a new token mint and mapping on Solana during the emergency pause window — a direct bypass of the intended security control.

### Citations

**File:** solana/programs/bridge_token_factory/src/constants.rs (L35-42)
```rust
#[constant]
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;

#[constant]
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;

#[constant]
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
```

**File:** solana/programs/bridge_token_factory/src/instructions/admin/pause.rs (L26-28)
```rust
    pub fn process(&mut self) -> Result<()> {
        self.config.paused = ALL_PAUSED;

```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L66-76)
```rust
    pub fn deploy_token(
        ctx: Context<DeployToken>,
        data: SignedPayload<DeployTokenPayload>,
    ) -> Result<()> {
        msg!("Deploying token");

        data.verify_signature((), &ctx.accounts.common.config.derived_near_bridge_address)?;
        ctx.accounts.initialize_token_metadata(data.payload)?;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L82-85)
```rust
        require!(
            ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
        );
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L125-128)
```rust
        require!(
            ctx.accounts.common.config.paused & INIT_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
        );
```
