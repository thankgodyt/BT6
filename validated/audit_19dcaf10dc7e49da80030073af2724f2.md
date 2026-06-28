### Title
Solana `bridge_token_factory` `deploy_token` Instruction Bypasses Pause Mechanism — (File: `solana/programs/bridge_token_factory/src/lib.rs`)

---

### Summary

The Solana `bridge_token_factory` program's `deploy_token` instruction has no pause check. When `pause_all()` is called, only `init_transfer` and `finalize_transfer` are blocked. `deploy_token` remains fully callable, creating an incomplete pause that is inconsistent with the EVM and Starknet implementations, both of which define and enforce a `DEPLOY_TOKEN_PAUSED` flag.

---

### Finding Description

The Solana program defines its pause constants in `constants.rs`:

```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
``` [1](#0-0) 

`ALL_PAUSED` covers only two of the three sensitive instructions. The `deploy_token` instruction performs no pause check whatsoever:

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
``` [2](#0-1) 

Compare with `finalize_transfer` and `init_transfer`, which both gate on the pause bitmap before proceeding: [3](#0-2) [4](#0-3) 

The EVM implementation defines and enforces `PAUSED_DEPLOY_TOKEN = 1 << 2` on `deployToken`: [5](#0-4) [6](#0-5) 

The Starknet implementation defines `PAUSE_DEPLOY_TOKEN: u8 = 0x04` and checks it at the top of `deploy_token`: [7](#0-6) [8](#0-7) 

The Solana program has no equivalent constant and no equivalent check.

---

### Impact Explanation

When an operator calls `pause_all()` on the Solana bridge in response to a security incident — for example, a discovered bug in the token-deployment or metadata-initialization path — `deploy_token` continues to accept and execute signed payloads. Any signed `DeployTokenPayload` that was emitted by the NEAR MPC before the pause (observable as a NEAR on-chain event) can be submitted to Solana and will succeed. If the security incident is specifically related to the token-deployment logic (e.g., a flaw in `initialize_token_metadata`), the pause provides no protection for that code path. This constitutes a pause bypass that lets an unprivileged caller execute deployer-equivalent actions against the bridge while the operator believes all sensitive operations are halted.

---

### Likelihood Explanation

Moderate. The attacker does not need to compromise any key. Signed `DeployTokenPayload` messages are produced by the NEAR MPC and broadcast as NEAR events; any observer can collect them. The window of opportunity is any period during which the bridge is paused while one or more signed deploy-token messages have not yet been submitted to Solana — a realistic scenario during incident response.

---

### Recommendation

Add a `DEPLOY_TOKEN_PAUSED` constant to `constants.rs` (e.g., `1 << 2`) and include it in `ALL_PAUSED`. Add the corresponding guard at the top of `deploy_token`, mirroring the pattern already used for `init_transfer` and `finalize_transfer`:

```rust
pub const DEPLOY_TOKEN_PAUSED: u8 = 1 << 2;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED;
```

```rust
pub fn deploy_token(ctx: Context<DeployToken>, data: SignedPayload<DeployTokenPayload>) -> Result<()> {
    require!(
        ctx.accounts.common.config.paused & DEPLOY_TOKEN_PAUSED == 0,
        error::ErrorCode::Paused
    );
    // ...
}
```

This aligns the Solana implementation with the EVM and Starknet deployments.

---

### Proof of Concept

1. NEAR MPC signs a `DeployTokenPayload` for a new token; the signed message is emitted as a NEAR event and observed by a relayer/attacker.
2. An operator discovers a security incident and calls `pause_all()` on the Solana `bridge_token_factory`. `config.paused` is set to `ALL_PAUSED = 0x03`.
3. The attacker submits the previously collected signed payload to `deploy_token` on Solana.
4. `deploy_token` performs no pause check; it calls `data.verify_signature(...)` (which passes, since the signature is genuine) and then `initialize_token_metadata(data.payload)`.
5. The token is deployed on Solana despite the bridge being in a fully-paused state, executing deployer-equivalent actions that the operator intended to halt. [2](#0-1) [9](#0-8)

### Citations

**File:** solana/programs/bridge_token_factory/src/constants.rs (L36-43)
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
