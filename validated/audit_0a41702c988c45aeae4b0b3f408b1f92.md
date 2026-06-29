Audit Report

## Title
`deploy_token` Instruction Bypasses Pause Mechanism — (`solana/programs/bridge_token_factory/src/lib.rs`)

## Summary
The Solana `bridge_token_factory` program's `deploy_token` instruction performs no pause check. When `pause_all()` is called, `config.paused` is set to `ALL_PAUSED = 0x03`, which only covers `INIT_TRANSFER_PAUSED` and `FINALIZE_TRANSFER_PAUSED`. Any observer holding a previously collected signed `DeployTokenPayload` can submit it to `deploy_token` and successfully deploy a token on Solana while the bridge is in a fully-paused state. Both the EVM and Starknet implementations define and enforce a dedicated `DEPLOY_TOKEN_PAUSED` flag; the Solana implementation has no equivalent.

## Finding Description
In `solana/programs/bridge_token_factory/src/constants.rs` (L36–42), the pause bitmap is defined as:

```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
``` [1](#0-0) 

`ALL_PAUSED = 0x03` covers only two of the three sensitive instructions. In `lib.rs` (L66–76), `deploy_token` performs no pause check:

```rust
pub fn deploy_token(ctx: Context<DeployToken>, data: SignedPayload<DeployTokenPayload>) -> Result<()> {
    msg!("Deploying token");
    data.verify_signature((), &ctx.accounts.common.config.derived_near_bridge_address)?;
    ctx.accounts.initialize_token_metadata(data.payload)?;
    Ok(())
}
``` [2](#0-1) 

By contrast, `finalize_transfer` (L82–85) and `init_transfer` (L125–128) both gate on the pause bitmap before proceeding: [3](#0-2) [4](#0-3) 

The EVM implementation defines `PAUSED_DEPLOY_TOKEN = 1 << 2` and enforces it via `whenNotPaused(PAUSED_DEPLOY_TOKEN)` on `deployToken`: [5](#0-4) [6](#0-5) 

The Starknet implementation defines `PAUSE_DEPLOY_TOKEN: u8 = 0x04` and asserts it at the top of `deploy_token`: [7](#0-6) [8](#0-7) 

The Solana program has no equivalent constant and no equivalent check.

## Impact Explanation
This is a concrete pause bypass that lets an unprivileged external caller execute deployer-equivalent actions — deploying bridge tokens — while the operator believes all sensitive operations are halted. This matches the allowed critical impact: "pause bypass... that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions." If the security incident that triggered the pause is related to the token-deployment or metadata-initialization path, the pause provides zero protection for that code path on Solana.

## Likelihood Explanation
Moderate. The attacker requires no privileged key. Signed `DeployTokenPayload` messages are produced by the NEAR MPC and emitted as observable NEAR on-chain events; any relayer or observer can collect them. The exploit window is any period during which the bridge is paused while one or more signed deploy-token messages have not yet been submitted to Solana — a realistic scenario during incident response. The attacker simply submits the collected payload to `deploy_token`; the genuine MPC signature passes verification and the token is deployed.

## Recommendation
Add a `DEPLOY_TOKEN_PAUSED` constant to `constants.rs` and include it in `ALL_PAUSED`:

```rust
pub const DEPLOY_TOKEN_PAUSED: u8 = 1 << 2;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED;
```

Add the corresponding guard at the top of `deploy_token` in `lib.rs`, mirroring the pattern used for `finalize_transfer` and `init_transfer`:

```rust
pub fn deploy_token(ctx: Context<DeployToken>, data: SignedPayload<DeployTokenPayload>) -> Result<()> {
    require!(
        ctx.accounts.common.config.paused & DEPLOY_TOKEN_PAUSED == 0,
        error::ErrorCode::Paused
    );
    // ...
}
```

Also import `DEPLOY_TOKEN_PAUSED` in the `use super::constants` statement in `lib.rs` alongside the existing imports.

## Proof of Concept
1. NEAR MPC signs a `DeployTokenPayload` for a new token; the signed message is emitted as a NEAR event and observed by an attacker.
2. An operator discovers a security incident and calls `pause_all()` on the Solana `bridge_token_factory`. `config.paused` is set to `ALL_PAUSED = 0x03`.
3. The attacker submits the previously collected signed payload to `deploy_token` on Solana.
4. `deploy_token` performs no pause check; it calls `data.verify_signature(...)` (which passes, since the signature is genuine) and then `ctx.accounts.initialize_token_metadata(data.payload)`.
5. The token is deployed on Solana despite the bridge being in a fully-paused state.

A local integration test can reproduce this by: (a) initializing the program, (b) calling `pause` to set `ALL_PAUSED`, (c) constructing a valid `SignedPayload<DeployTokenPayload>` signed by the configured `derived_near_bridge_address` keypair, and (d) invoking `deploy_token` — the instruction succeeds and the token account is created, confirming the bypass.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L53-55)
```text
    uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
    uint256 constant PAUSED_FIN_TRANSFER = 1 << 1;
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-138)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
```

**File:** starknet/src/omni_bridge.cairo (L69-72)
```text
    const PAUSE_INIT_TRANSFER: u8 = 0x01; // 0001
    const PAUSE_FIN_TRANSFER: u8 = 0x02; // 0010
    const PAUSE_DEPLOY_TOKEN: u8 = 0x04; // 0100
    const PAUSE_ALL: u8 = 0xFF; // 1111
```

**File:** starknet/src/omni_bridge.cairo (L202-203)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');
```
