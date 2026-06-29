### Title
Solana `deploy_token` Instruction Bypasses Pause Check - (`solana/programs/bridge_token_factory/src/lib.rs`)

### Summary
The Solana `bridge_token_factory` program implements a pause mechanism that is correctly enforced on `finalize_transfer`, `finalize_transfer_sol`, `init_transfer`, and `init_transfer_sol`, but is entirely absent from the `deploy_token` instruction. Any holder of a previously-signed `DeployTokenPayload` can call `deploy_token` on Solana even when the bridge is fully paused, bypassing the emergency stop intended to halt all bridge operations.

### Finding Description
The Solana program defines pause constants and enforces them on transfer-related instructions:

`finalize_transfer` checks the pause flag: [1](#0-0) 

`init_transfer` checks the pause flag: [2](#0-1) 

However, `deploy_token` performs no pause check whatsoever: [3](#0-2) 

The `pause()` instruction sets `config.paused = ALL_PAUSED`: [4](#0-3) 

Even with `ALL_PAUSED` set, `deploy_token` proceeds unconditionally. By contrast, the EVM `OmniBridge.sol` correctly guards `deployToken` with `whenNotPaused(PAUSED_DEPLOY_TOKEN)`: [5](#0-4) 

And the Starknet contract checks `PAUSE_DEPLOY_TOKEN` at the top of `deploy_token`: [6](#0-5) 

The Solana implementation is the only chain where `deploy_token` is unguarded.

### Impact Explanation
When administrators pause the bridge in response to a security incident (e.g., a compromised MPC key, a discovered vulnerability in token metadata handling, or an incorrect token binding), the pause is intended to halt all bridge operations including token deployment. Because `deploy_token` on Solana ignores the pause flag, any party holding a valid `SignedPayload<DeployTokenPayload>` — obtained from a prior legitimate `log_metadata` event on NEAR that was MPC-signed before the pause — can still execute token deployment on Solana. This constitutes a pause bypass: an attacker-controlled entry path executes a bridge-equivalent action (token deployer action) that the protocol administrators explicitly intended to block. This falls squarely within the allowed critical impact category of "pause bypass that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions."

### Likelihood Explanation
Likelihood is medium. A valid signed payload is a prerequisite, but signed `DeployTokenPayload` messages are produced by the NEAR MPC network in response to any `log_metadata` call and are broadcast as on-chain events. Any observer can collect these payloads before a pause is triggered. The window between a pause event and an attacker submitting a collected payload to Solana is realistic, particularly since pauses are reactive to incidents and signed payloads have no expiry.

### Recommendation
Add a pause check to `deploy_token` in `solana/programs/bridge_token_factory/src/lib.rs`, consistent with the pattern already used for `finalize_transfer` and `init_transfer`:

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

A corresponding `DEPLOY_TOKEN_PAUSED` bitmask constant should be added to `constants.rs`, and `ALL_PAUSED` should include it.

### Proof of Concept

1. Admin calls `log_metadata` on NEAR for token `T`. The NEAR MPC network signs a `DeployTokenPayload` and emits it as an on-chain event. An attacker (or any observer) records the signed payload.
2. A security incident is discovered. Admin calls `pause()` on the Solana `bridge_token_factory`, setting `config.paused = ALL_PAUSED`.
3. The attacker submits the previously-collected `SignedPayload<DeployTokenPayload>` directly to the Solana `deploy_token` instruction.
4. Because `deploy_token` contains no `require!(config.paused & DEPLOY_TOKEN_PAUSED == 0, ...)` guard, the instruction executes successfully, deploying the token and writing the token mapping — bypassing the emergency pause entirely.
5. All other instructions (`finalize_transfer`, `init_transfer`) correctly reject calls with `ErrorCode::Paused`, but `deploy_token` proceeds.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L548-557)
```text
    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }

    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }
```

**File:** starknet/src/omni_bridge.cairo (L202-203)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');
```
