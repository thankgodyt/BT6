### Title
`deploy_token` Bypasses Pause Mechanism When Bridge Is Fully Paused - (File: `solana/programs/bridge_token_factory/src/lib.rs`)

### Summary
The Solana `bridge_token_factory` program's `deploy_token` instruction lacks any pause check, while `finalize_transfer`, `finalize_transfer_sol`, `init_transfer`, and `init_transfer_sol` all enforce pause flags. The `ALL_PAUSED` constant itself only covers `INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED`, with no `DEPLOY_TOKEN_PAUSED` bit defined. This means that when operators pause the bridge in response to a security incident, `deploy_token` remains fully callable by anyone holding a valid pre-obtained MPC signature, bypassing the intended emergency halt.

### Finding Description
In `solana/programs/bridge_token_factory/src/constants.rs`, the pause bitmask is defined as:

```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
```

`ALL_PAUSED` covers only two operations. In `src/lib.rs`, `finalize_transfer` and `init_transfer` variants each guard themselves:

```rust
require!(
    ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
    error::ErrorCode::Paused
);
```

```rust
require!(
    ctx.accounts.common.config.paused & INIT_TRANSFER_PAUSED == 0,
    error::ErrorCode::Paused
);
```

But `deploy_token` has no such guard:

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

The `pause` instruction sets `config.paused = ALL_PAUSED`, which never sets any bit that `deploy_token` would check — because no such bit exists and no check is present.

On the NEAR side, `log_metadata` (which triggers MPC signing of `DeployTokenPayload`) is decorated with `#[pause(except(roles(Role::DAO)))]`, so new signatures cannot be generated during a pause for non-DAO callers. However, MPC signatures obtained **before** the pause are not invalidated and remain valid indefinitely. An attacker (or any party) holding such a pre-obtained signature can submit it to Solana's `deploy_token` at any time, including during a full bridge pause.

### Impact Explanation
This is a **pause bypass**: the `deploy_token` instruction executes a deployer-equivalent bridge action (creating a new SPL mint and registering a token mapping) even when the bridge is fully paused via `ALL_PAUSED`. The pause mechanism's stated purpose is to halt all bridge operations during emergencies. `deploy_token` structurally escapes this halt. A party with a pre-obtained valid MPC signature can register new token mappings on Solana during a security pause, creating state that persists and becomes active once the bridge is unpaused. This fits the allowed impact scope: "pause bypass that lets an attacker execute bridge, token, deployer, or admin-equivalent actions."

### Likelihood Explanation
MPC signatures for `DeployTokenPayload` are generated on NEAR and broadcast as events. Any relayer or observer can capture these signatures before a pause is triggered. Since signatures are not time-bounded or revocable, a captured signature remains usable indefinitely. The window between signature generation and a pause event is realistic in any incident response scenario.

### Recommendation
1. Define a `DEPLOY_TOKEN_PAUSED: u8 = 1 << 2` constant in `constants.rs`.
2. Include it in `ALL_PAUSED`: `pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED;`
3. Add the corresponding guard at the top of `deploy_token`:
   ```rust
   require!(
       ctx.accounts.common.config.paused & DEPLOY_TOKEN_PAUSED == 0,
       error::ErrorCode::Paused
   );
   ```

### Proof of Concept
1. Operator calls `log_metadata` on NEAR → NEAR MPC signs a `DeployTokenPayload` → signature is emitted as an event.
2. Attacker captures the `(signature, payload)` pair from the event log.
3. A security incident is detected; operator calls `pause` on Solana → `config.paused = ALL_PAUSED = 0b11`.
4. `finalize_transfer` and `init_transfer` now revert with `Paused`.
5. Attacker calls `deploy_token(ctx, SignedPayload { signature, payload })` on Solana.
6. No pause check exists in `deploy_token`; `verify_signature` passes (signature is valid); `initialize_token_metadata` executes, registering the new token mapping on Solana.
7. Bridge state is mutated during the pause, contrary to operator intent. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** solana/programs/bridge_token_factory/src/constants.rs (L36-42)
```rust
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

**File:** solana/programs/bridge_token_factory/src/lib.rs (L78-95)
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
    }
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L124-134)
```rust
    pub fn init_transfer(ctx: Context<InitTransfer>, payload: InitTransferPayload) -> Result<()> {
        require!(
            ctx.accounts.common.config.paused & INIT_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
        );
        msg!("Initializing transfer");

        ctx.accounts.process(&payload)?;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/instructions/admin/pause.rs (L25-30)
```rust
impl Pause<'_> {
    pub fn process(&mut self) -> Result<()> {
        self.config.paused = ALL_PAUSED;

        Ok(())
    }
```
