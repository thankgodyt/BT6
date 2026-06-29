### Title
`deploy_token` Bypasses Pause on Solana Bridge — (`solana/programs/bridge_token_factory/src/lib.rs`)

### Summary
The Solana `bridge_token_factory` program defines two pause bits and a `pause()` instruction that sets `ALL_PAUSED`. Every user-facing transfer function checks the relevant pause bit before executing. However, `deploy_token` — which creates new token mints on Solana — contains no pause check at all, and `ALL_PAUSED` does not include a deploy-token bit. When an admin or pausable-admin triggers a full pause, token deployment remains live and can still be executed by any relayer holding a valid pending MPC-signed payload.

---

### Finding Description

The Solana program defines exactly two pause flags: [1](#0-0) 

```
INIT_TRANSFER_PAUSED  = 1 << 0
FINALIZE_TRANSFER_PAUSED = 1 << 1
ALL_PAUSED = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED
```

The `pause()` instruction sets `config.paused = ALL_PAUSED`: [2](#0-1) 

All four transfer entry points correctly gate on these bits: [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

`deploy_token`, however, performs no pause check whatsoever: [7](#0-6) 

The EVM counterpart explicitly guards the equivalent operation with `whenNotPaused(PAUSED_DEPLOY_TOKEN)` and includes that bit in `pauseAll()`: [8](#0-7) [9](#0-8) [10](#0-9) 

The Solana program has no equivalent protection.

---

### Impact Explanation

When an admin or pausable-admin calls `pause()` to halt the Solana bridge (e.g., in response to a security incident), `deploy_token` continues to accept and process calls. Any relayer holding a valid MPC-signed `DeployTokenPayload` — legitimately obtained before the pause — can submit it after the pause is active. This creates new token mints and registers token metadata on-chain while the program is supposed to be fully stopped. Once the pause is lifted, those newly registered mints are immediately usable in `finalize_transfer` calls, potentially with incorrect or attacker-influenced metadata (e.g., wrong decimals), leading to mis-accounting of bridged amounts and potential fund loss. This is a **pause bypass** that lets an unprivileged relayer execute deployer-equivalent actions against the admin's explicit intent.

---

### Likelihood Explanation

Any active relayer who has already obtained a valid MPC-signed `DeployTokenPayload` (a normal part of the bridge flow) can submit it at any time, including after a pause. No key compromise or threshold collusion is required. The window between a pause being triggered and all in-flight signed payloads expiring is realistic in production incident response.

---

### Recommendation

1. Add a `DEPLOY_TOKEN_PAUSED: u8 = 1 << 2` constant to `constants.rs`.
2. Update `ALL_PAUSED` to `INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED`.
3. Add the following guard at the top of `deploy_token`:
   ```rust
   require!(
       ctx.accounts.common.config.paused & DEPLOY_TOKEN_PAUSED == 0,
       error::ErrorCode::Paused
   );
   ```

---

### Proof of Concept

1. Admin calls `pause()` → `config.paused = 0b11` (`ALL_PAUSED`).
2. Relayer holds a valid `SignedPayload<DeployTokenPayload>` obtained before the pause.
3. Relayer calls `deploy_token(ctx, signed_payload)`.
4. The function skips any pause check, calls `data.verify_signature(...)` (succeeds — signature is valid), and calls `ctx.accounts.initialize_token_metadata(data.payload)`.
5. A new token mint is registered on Solana while the program is supposed to be fully paused.
6. After the pause is lifted, `finalize_transfer` uses this mint to distribute tokens to recipients, potentially with incorrect metadata. [7](#0-6) [1](#0-0) [2](#0-1)

### Citations

**File:** solana/programs/bridge_token_factory/src/constants.rs (L36-42)
```rust
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

**File:** solana/programs/bridge_token_factory/src/lib.rs (L82-84)
```rust
        require!(
            ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L101-103)
```rust
        require!(
            ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L125-127)
```rust
        require!(
            ctx.accounts.common.config.paused & INIT_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L140-142)
```rust
        require!(
            ctx.accounts.common.config.paused & INIT_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L53-55)
```text
    uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
    uint256 constant PAUSED_FIN_TRANSFER = 1 << 1;
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L138-138)
```text
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
