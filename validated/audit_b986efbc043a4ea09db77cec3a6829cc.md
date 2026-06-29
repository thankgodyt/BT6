Audit Report

## Title
`deploy_token` Instruction Missing Pause Check - (`solana/programs/bridge_token_factory/src/lib.rs`)

## Summary
The Solana `bridge_token_factory` program enforces pause checks on `finalize_transfer`, `finalize_transfer_sol`, `init_transfer`, and `init_transfer_sol`, but the `deploy_token` instruction contains no such check. When the bridge is fully paused via `ALL_PAUSED`, any party holding a previously-collected MPC-signed `DeployTokenPayload` can still call `deploy_token` successfully, bypassing the emergency stop. The EVM and Starknet implementations both guard their equivalent `deployToken`/`deploy_token` functions with pause checks; Solana does not.

## Finding Description
`deploy_token` in `lib.rs` proceeds directly to signature verification and token metadata initialization with no pause guard: [1](#0-0) 

By contrast, `finalize_transfer` and `init_transfer` both check the pause bitmask before proceeding: [2](#0-1) [3](#0-2) 

The `pause()` instruction sets `config.paused = ALL_PAUSED`: [4](#0-3) 

`ALL_PAUSED` is defined as the bitwise OR of only `INIT_TRANSFER_PAUSED` and `FINALIZE_TRANSFER_PAUSED` — no `DEPLOY_TOKEN_PAUSED` bit exists: [5](#0-4) 

Even if a `DEPLOY_TOKEN_PAUSED` constant were added to `ALL_PAUSED`, `deploy_token` still performs no `require!` check against it. The root cause is twofold: the missing bitmask constant and the missing `require!` guard in the instruction handler.

## Impact Explanation
This is a pause bypass that lets an unprivileged external user execute a deployer-equivalent action — token deployment — while the bridge is in a fully paused emergency state. This matches the allowed critical impact: *"pause bypass that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions."* When administrators pause the bridge in response to a security incident (e.g., a compromised MPC key or a discovered vulnerability in token metadata handling), the intent is to halt all bridge operations including token deployment. The bypass allows a new token binding to be written to the Solana program state, which can create incorrect or attacker-influenced token mappings that persist after the pause is lifted.

## Likelihood Explanation
Likelihood is medium. The precondition is possession of a valid MPC-signed `DeployTokenPayload`. Such payloads are produced by the NEAR MPC network in response to any `log_metadata` call and are emitted as public on-chain events. Any observer can collect them before a pause is triggered. Pauses are reactive to incidents, so the window between a pause event and an attacker submitting a previously-collected payload to Solana is realistic. No special privileges are required beyond having observed the NEAR chain.

## Recommendation
Add a `DEPLOY_TOKEN_PAUSED` bitmask constant to `constants.rs` and include it in `ALL_PAUSED`:

```rust
pub const DEPLOY_TOKEN_PAUSED: u8 = 1 << 2;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED;
```

Then add a pause guard to `deploy_token` in `lib.rs`, importing `DEPLOY_TOKEN_PAUSED` alongside the existing imports:

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

This is consistent with the pattern already used for `finalize_transfer` and `init_transfer`, and aligns Solana's behavior with the EVM and Starknet implementations.

## Proof of Concept
1. Call `log_metadata` on NEAR for token `T`. The NEAR MPC network signs a `DeployTokenPayload` and emits it as a public on-chain event. Record the `SignedPayload<DeployTokenPayload>`.
2. A security incident occurs. Admin calls `pause()` on the Solana `bridge_token_factory`, setting `config.paused = ALL_PAUSED` (value `0x03`).
3. Verify that `finalize_transfer` and `init_transfer` now reject with `ErrorCode::Paused`.
4. Submit the previously-collected `SignedPayload<DeployTokenPayload>` to the `deploy_token` instruction.
5. Observe that `deploy_token` succeeds — the token is deployed and the token mapping is written — despite `config.paused == ALL_PAUSED`, confirming the pause bypass.

### Citations

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

**File:** solana/programs/bridge_token_factory/src/instructions/admin/pause.rs (L25-30)
```rust
impl Pause<'_> {
    pub fn process(&mut self) -> Result<()> {
        self.config.paused = ALL_PAUSED;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/constants.rs (L36-42)
```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;

#[constant]
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;

#[constant]
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
```
