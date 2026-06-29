### Title
`deploy_token` Missing Pause Check Allows Token Deployment When Program Is Fully Paused - (`solana/programs/bridge_token_factory/src/lib.rs`)

### Summary
The Solana `bridge_token_factory` program enforces pause checks on `finalize_transfer`, `finalize_transfer_sol`, `init_transfer`, and `init_transfer_sol`, but the `deploy_token` instruction has no pause check at all. When the program is fully paused via `pause()`, token deployment remains callable by any unprivileged user who holds a valid pre-existing MPC signature, bypassing the intended emergency halt.

### Finding Description

In `solana/programs/bridge_token_factory/src/lib.rs`, every user-facing transfer instruction guards itself with a bitflag check before proceeding:

```rust
// finalize_transfer (line 82-85)
require!(
    ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
    error::ErrorCode::Paused
);

// init_transfer (line 125-128)
require!(
    ctx.accounts.common.config.paused & INIT_TRANSFER_PAUSED == 0,
    error::ErrorCode::Paused
);
``` [1](#0-0) [2](#0-1) 

The `deploy_token` instruction, however, contains no such guard:

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
``` [3](#0-2) 

The constants file confirms there is no `DEPLOY_TOKEN_PAUSED` bit, and `ALL_PAUSED` only covers the two transfer operations:

```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
``` [4](#0-3) 

The `pause()` instruction sets `config.paused = ALL_PAUSED`, which means even a full emergency pause leaves `deploy_token` completely unblocked. [5](#0-4) 

This is in direct contrast to the EVM `OmniBridge.sol`, where `deployToken` carries `whenNotPaused(PAUSED_DEPLOY_TOKEN)` and `pauseAll()` explicitly includes `PAUSED_DEPLOY_TOKEN` in its flag set. [6](#0-5) [7](#0-6) 

### Impact Explanation

When operators invoke `pause()` to halt the Solana bridge program during an emergency (e.g., a discovered vulnerability in the token-deployment flow, a compromised MPC key, or an active exploit), `deploy_token` continues to accept calls. An attacker who holds any valid, previously-issued MPC signature for a `DeployTokenPayload` can:

1. Deploy a new SPL token with a NEAR-token-ID mapping that overwrites or shadows an existing legitimate mapping, corrupting the token registry used by subsequent `finalize_transfer` calls once the bridge is unpaused.
2. If the emergency was triggered precisely because the MPC signing key is suspected compromised, the attacker can use a freshly-signed payload to deploy an attacker-controlled token address, enabling unauthorized minting of bridged assets when transfers resume.

This constitutes a **pause bypass** leading to potential **unauthorized token deployment and balance manipulation** — matching the critical impact class of authorization/pause bypass that changes user or protocol balances.

### Likelihood Explanation

The entry path is fully unprivileged: `deploy_token` is a public instruction requiring only a valid MPC-signed `DeployTokenPayload`. Valid signatures are routinely produced during normal bridge operation (every time a new token is bridged from NEAR to Solana). An attacker can collect such a signature before the pause is triggered and replay it afterward. No admin compromise, key theft, or collusion is required beyond possessing a legitimately-issued signature.

### Recommendation

1. Add a `DEPLOY_TOKEN_PAUSED` constant (e.g., `1 << 2`) to `constants.rs` and include it in `ALL_PAUSED`.
2. Add the corresponding pause guard at the top of `deploy_token` in `lib.rs`, mirroring the pattern used by `finalize_transfer` and `init_transfer`:

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

### Proof of Concept

1. Operator calls `pause()` → `config.paused = ALL_PAUSED = 0b11` (only bits 0 and 1 set).
2. Attacker calls `deploy_token` with a valid pre-collected `SignedPayload<DeployTokenPayload>`.
3. The instruction has no `require!(config.paused & DEPLOY_TOKEN_PAUSED == 0, ...)` guard, so execution proceeds unconditionally.
4. `initialize_token_metadata` runs, deploying a new SPL token and writing its mapping into program state — despite the bridge being in a fully-paused emergency state.
5. `finalize_transfer` and `init_transfer` remain blocked, but the corrupted token registry is now in place for when the pause is lifted.

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

**File:** solana/programs/bridge_token_factory/src/constants.rs (L36-42)
```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;

#[constant]
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;

#[constant]
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
```

**File:** solana/programs/bridge_token_factory/src/instructions/admin/pause.rs (L25-30)
```rust
impl Pause<'_> {
    pub fn process(&mut self) -> Result<()> {
        self.config.paused = ALL_PAUSED;

        Ok(())
    }
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
