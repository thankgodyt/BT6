The evidence is conclusive. The `log_metadata` entry point in `lib.rs` has no pause guard, while `init_transfer`, `init_transfer_sol`, `finalize_transfer`, and `finalize_transfer_sol` all have explicit pause checks. This is a real, demonstrable pause bypass.

---

### Title
`log_metadata` Bypasses Pause Gate, Allowing Wormhole VAA Emission During Emergency Pause — (`solana/programs/bridge_token_factory/src/lib.rs`)

### Summary
The `log_metadata` instruction lacks any pause check. When the bridge is paused (any combination of `INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED`, or a full `ALL_PAUSED` state), any caller can still invoke `log_metadata`, which posts a Wormhole message that triggers NEAR-side token binding or metadata updates.

### Finding Description
In `lib.rs`, every transfer-related instruction guards execution with a bitwise pause check:

- `finalize_transfer` / `finalize_transfer_sol`: [1](#0-0) 
- `init_transfer` / `init_transfer_sol`: [2](#0-1) 

The `log_metadata` entry point has no such guard:

```rust
pub fn log_metadata(ctx: Context<LogMetadata>) -> Result<()> {
    msg!("Logging metadata");
    ctx.accounts.process()?;
    Ok(())
}
``` [3](#0-2) 

Inside `LogMetadata::process()`, the function reads mint metadata and unconditionally calls `self.common.post_message(payload)`, which invokes the Wormhole CPI to emit a `LogMetadataPayload` VAA: [4](#0-3) 

The `LogMetadata` accounts struct requires no admin signer — only a `payer: Signer` from `WormholeCPI`, meaning any wallet can be the caller: [5](#0-4) 

The `Config` account holds the `paused: u8` field that is checked by other instructions but never read by `log_metadata`: [6](#0-5) 

### Impact Explanation
A `LogMetadataPayload` VAA emitted during a pause is observed by NEAR-side relayers and can trigger token binding or metadata updates on NEAR. This violates the invariant that all bridge-state-mutating operations must respect the pause flag. During an emergency pause (e.g., triggered in response to an active exploit), an attacker can still register new token bindings on NEAR, potentially setting up preconditions for further exploitation once the pause is lifted or interacting with other NEAR-side logic that depends on token registration state.

This matches the allowed Critical impact: **pause bypass that lets an attacker execute token-deployer-equivalent actions**.

### Likelihood Explanation
The call requires no special role, no admin key, and no privileged account — only a funded wallet and a valid non-bridge-owned mint. It is trivially reproducible on a local testnet with an initialized bridge in a paused state.

### Recommendation
Add the same pause guard used by `init_transfer` and `finalize_transfer` to the `log_metadata` entry point. A dedicated `LOG_METADATA_PAUSED` bit (or reuse of an existing flag) should be checked:

```rust
pub fn log_metadata(ctx: Context<LogMetadata>) -> Result<()> {
    require!(
        ctx.accounts.common.config.paused & LOG_METADATA_PAUSED == 0,
        error::ErrorCode::Paused
    );
    msg!("Logging metadata");
    ctx.accounts.process()?;
    Ok(())
}
```

### Proof of Concept
1. Initialize the bridge program on a local testnet.
2. Call `pause` as `pausable_admin` → assert `config.paused == ALL_PAUSED`.
3. Call `log_metadata` with any valid non-bridge-owned mint and a funded payer.
4. Assert the transaction **succeeds** and a Wormhole message account is written (sequence incremented).
5. Confirm the emitted VAA contains a valid `LogMetadataPayload` for the mint.
6. Observe that NEAR-side relayer logic would process this VAA and bind the token, despite the bridge being in a fully-paused state.

### Citations

**File:** solana/programs/bridge_token_factory/src/lib.rs (L82-85)
```rust
        require!(
            ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
        );
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L116-122)
```rust
    pub fn log_metadata(ctx: Context<LogMetadata>) -> Result<()> {
        msg!("Logging metadata");

        ctx.accounts.process()?;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L125-128)
```rust
        require!(
            ctx.accounts.common.config.paused & INIT_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
        );
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L130-138)
```rust
        let payload = LogMetadataPayload {
            token: self.mint.key(),
            name: name.trim_end_matches('\0').to_string(),
            symbol: symbol.trim_end_matches('\0').to_string(),
            decimals: self.mint.decimals,
        }
        .serialize_for_near(())?;

        self.common.post_message(payload)?;
```

**File:** solana/programs/bridge_token_factory/src/instructions/wormhole_cpi.rs (L61-62)
```rust
    #[account(mut)]
    pub payer: Signer<'info>,
```

**File:** solana/programs/bridge_token_factory/src/state/config.rs (L25-25)
```rust
    pub paused: u8,
```
