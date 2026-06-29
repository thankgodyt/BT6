Audit Report

## Title
`deploy_token` Instruction Bypasses Pause Mechanism — (`solana/programs/bridge_token_factory/src/lib.rs`)

## Summary
The Solana `bridge_token_factory` program's `deploy_token` instruction contains no pause check, allowing any party holding a valid MPC-signed `DeployTokenPayload` to deploy bridged tokens on Solana even when the bridge is fully paused via `ALL_PAUSED`. This is a concrete pause bypass inconsistent with the EVM implementation, which explicitly gates `deployToken` behind `whenNotPaused(PAUSED_DEPLOY_TOKEN)` and includes `PAUSED_DEPLOY_TOKEN` in `pauseAll()`.

## Finding Description
`constants.rs` defines the pause bitmask as:

```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
``` [1](#0-0) 

No `DEPLOY_TOKEN_PAUSED` bit is defined, and `ALL_PAUSED` covers only bits 0 and 1.

The `pause` instruction sets `config.paused = ALL_PAUSED`: [2](#0-1) 

`finalize_transfer`, `finalize_transfer_sol`, `init_transfer`, and `init_transfer_sol` all guard execution with a `require!` check against the pause bitmask: [3](#0-2) [4](#0-3) 

However, `deploy_token` performs no such check — it only verifies the MPC signature and immediately calls `initialize_token_metadata`: [5](#0-4) 

By contrast, the EVM `OmniBridge.sol` defines `PAUSED_DEPLOY_TOKEN = 1 << 2`, gates `deployToken` with `whenNotPaused(PAUSED_DEPLOY_TOKEN)`, and includes it in `pauseAll()`: [6](#0-5) [7](#0-6) [8](#0-7) 

## Impact Explanation
This is a concrete **pause bypass** matching the allowed critical impact: "pause bypass... that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions." When the `pausable_admin` pauses the Solana bridge in response to a security incident, the intent is to halt all externally-triggered bridge operations. Because `deploy_token` is not gated by any pause flag, a relayer holding a valid MPC-signed `DeployTokenPayload` can still execute token deployment on Solana, directly circumventing the administrator's emergency halt. If the pause was triggered due to a flaw in the token deployment path, the vulnerable path remains open on Solana while it is correctly closed on EVM.

## Likelihood Explanation
The `deploy_token` instruction has no caller restriction — any Solana account can invoke it. A relayer who obtained a valid MPC-signed `DeployTokenPayload` from the NEAR bridge's `log_metadata` → MPC signing flow (either before or after the pause) can submit it at any time. The NEAR-side `log_metadata` is pause-gated, but previously issued signatures remain valid indefinitely. This makes the exploit straightforwardly repeatable by any relayer holding such a payload.

## Recommendation
1. Add `pub const DEPLOY_TOKEN_PAUSED: u8 = 1 << 2;` to `constants.rs`.
2. Update `ALL_PAUSED` to `INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED`.
3. Add a pause check at the top of `deploy_token` in `lib.rs`, mirroring the pattern used for `init_transfer`:

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

## Proof of Concept
1. `pausable_admin` calls `pause` on the Solana bridge; `config.paused` is set to `ALL_PAUSED = 0x03`.
2. A relayer holds a valid MPC-signed `DeployTokenPayload` (obtained from the NEAR bridge's `log_metadata` → MPC signing flow, before or after the pause).
3. The relayer calls `deploy_token` on the Solana program with the signed payload.
4. `deploy_token` at `lib.rs:72` verifies the MPC signature and at `lib.rs:73` calls `initialize_token_metadata` — no pause check is ever evaluated.
5. A new bridged token is deployed on Solana despite `config.paused == 0x03`, bypassing the administrator's emergency halt.

To reproduce locally: write an Anchor integration test that (a) calls `pause`, asserts `config.paused == 0x03`, then (b) calls `deploy_token` with a valid signed payload and asserts it succeeds — confirming the bypass.

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

**File:** solana/programs/bridge_token_factory/src/instructions/admin/pause.rs (L26-29)
```rust
    pub fn process(&mut self) -> Result<()> {
        self.config.paused = ALL_PAUSED;

        Ok(())
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L55-55)
```text
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-138)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L552-557)
```text
    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }
```
