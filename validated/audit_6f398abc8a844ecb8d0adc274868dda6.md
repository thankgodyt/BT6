### Title
Solana `deploy_token` Lacks Pause Check, Bypassing Emergency Pause Mechanism — (`solana/programs/bridge_token_factory/src/lib.rs`)

### Summary

The Solana `bridge_token_factory` program defines a pause mechanism with two flags (`INIT_TRANSFER_PAUSED`, `FINALIZE_TRANSFER_PAUSED`) and enforces them on `init_transfer`, `init_transfer_sol`, `finalize_transfer`, and `finalize_transfer_sol`. However, the `deploy_token` instruction has **no pause check at all**, meaning it remains fully callable even when the bridge is in a fully-paused emergency state. This is a direct analog to the `isClosed()` bug: a pause mechanism exists and is partially applied, but one critical entry point is silently excluded.

### Finding Description

The Solana constants file defines only two pause flags and an `ALL_PAUSED` aggregate: [1](#0-0) 

`ALL_PAUSED` covers only `INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED`. There is no `DEPLOY_TOKEN_PAUSED` bit defined, unlike the EVM contract which explicitly defines `PAUSED_DEPLOY_TOKEN = 1 << 2`: [2](#0-1) 

The `pause()` instruction sets `config.paused = ALL_PAUSED`: [3](#0-2) 

The four transfer instructions correctly gate on the pause flags: [4](#0-3) 

But `deploy_token` has no such guard: [5](#0-4) 

By contrast, both the EVM and Starknet implementations explicitly gate `deploy_token`/`deployToken` on their respective pause flags: [6](#0-5) [7](#0-6) 

### Impact Explanation

When the bridge operator triggers an emergency pause (e.g., in response to a discovered exploit in `finalize_transfer` or a suspected MPC key leak), the intent is to halt **all** bridge operations. Because `deploy_token` is not gated, any party holding a valid pre-signed `DeployTokenPayload` — obtained from the NEAR MPC network before the pause — can still submit it to Solana and register a new token mint and mapping. This:

1. **Bypasses the emergency pause** as a security control, defeating its purpose.
2. **Allows new token registrations during a crisis window**, which can be used to pre-position a malicious token mapping (e.g., mapping a near-zero-value token to a high-value Solana mint address) in preparation for a subsequent `finalize_transfer` attack once the bridge is unpaused.
3. Constitutes a **pause bypass** — an explicitly listed critical impact in scope.

### Likelihood Explanation

Realistic. Relayers routinely obtain signed `DeployTokenPayload` messages from the NEAR MPC network and submit them to Solana. Any such payload that was signed before the pause but not yet submitted can be submitted during the pause window. No admin compromise or key theft is required — only possession of a legitimately-issued but unsubmitted signed payload.

### Recommendation

Add a `DEPLOY_TOKEN_PAUSED` constant and enforce it in `deploy_token`, mirroring the EVM and Starknet implementations:

```rust
// In constants.rs
#[constant]
pub const DEPLOY_TOKEN_PAUSED: u8 = 1 << 2;

#[constant]
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED;
```

```rust
// In lib.rs, deploy_token
pub fn deploy_token(
    ctx: Context<DeployToken>,
    data: SignedPayload<DeployTokenPayload>,
) -> Result<()> {
    require!(
        ctx.accounts.common.config.paused & DEPLOY_TOKEN_PAUSED == 0,
        error::ErrorCode::Paused
    );
    // ...
}
```

### Proof of Concept

1. Admin calls `pause()` on the Solana `bridge_token_factory` in response to an emergency. `config.paused` is set to `ALL_PAUSED = 0x03` (bits 0 and 1 only).
2. `init_transfer` and `finalize_transfer` correctly revert with `Paused`.
3. A relayer holds a previously-obtained `SignedPayload<DeployTokenPayload>` (signed by the NEAR MPC before the pause).
4. The relayer calls `deploy_token` with this payload. The instruction has no pause check, so it executes unconditionally.
5. `data.verify_signature(...)` passes (the signature is valid). [8](#0-7) 
6. `ctx.accounts.initialize_token_metadata(data.payload)` executes, registering a new token on Solana during the emergency pause window — a direct bypass of the intended security control. [9](#0-8)

### Citations

**File:** solana/programs/bridge_token_factory/src/constants.rs (L36-42)
```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;

#[constant]
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;

#[constant]
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
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

**File:** starknet/src/omni_bridge.cairo (L202-203)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');
```
