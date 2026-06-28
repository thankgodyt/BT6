### Title
Inconsistent Pause Enforcement: `deploy_token` Lacks Pause Check in Solana `bridge_token_factory` - (File: `solana/programs/bridge_token_factory/src/lib.rs`)

### Summary
The Solana `bridge_token_factory` program's `deploy_token` instruction has no pause check, while every other chain's equivalent function (`deployToken` on EVM, `deploy_token` on Starknet, `deploy_token` on NEAR) enforces a pause guard. When the Solana bridge is fully paused via `ALL_PAUSED`, token deployment can still proceed, undermining the emergency pause mechanism.

### Finding Description

The Solana program defines two pause flags and a combined constant:

```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
``` [1](#0-0) 

`finalize_transfer` and `finalize_transfer_sol` both enforce the pause:

```rust
require!(
    ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
    error::ErrorCode::Paused
);
``` [2](#0-1) 

`init_transfer` and `init_transfer_sol` also enforce the pause: [3](#0-2) 

However, `deploy_token` has **no pause check at all**:

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
``` [4](#0-3) 

There is no `DEPLOY_TOKEN_PAUSED` flag defined, and `ALL_PAUSED` does not cover token deployment. Calling `pause` sets `ALL_PAUSED = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED`, which leaves `deploy_token` fully reachable. [5](#0-4) 

**Contrast with all other chains:**

- **EVM** `deployToken`: `whenNotPaused(PAUSED_DEPLOY_TOKEN)` [6](#0-5) 
- **Starknet** `deploy_token`: `assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED')` [7](#0-6) 
- **NEAR** `deploy_token`: `#[pause(except(roles(Role::DAO)))]` [8](#0-7) 
- **Solana** `deploy_token`: **no pause check** [4](#0-3) 

### Impact Explanation

When the Solana bridge is paused in an emergency (e.g., due to a discovered vulnerability in the token deployment or finalization path), an actor holding a valid pre-issued `SignedPayload<DeployTokenPayload>` can still call `deploy_token` and register a new SPL token mint into the bridge's state. This:

1. Directly bypasses the emergency pause mechanism for a deployer-equivalent action.
2. Creates an inconsistent paused state: transfers are blocked but token registration proceeds.
3. If the pause was triggered because of a flaw in the token initialization path (`initialize_token_metadata`), the bypass allows continued exploitation of that flaw even while the bridge is supposedly halted.

This matches the allowed impact: **pause bypass that lets an attacker execute deployer-equivalent actions**.

### Likelihood Explanation

The attacker needs a valid `SignedPayload<DeployTokenPayload>` signed by the NEAR bridge's derived address. Such a payload could have been legitimately issued by the NEAR side (whose `deploy_token` is separately pausable) before the Solana-side pause was triggered. Any relayer or user who obtained such a signed payload before the pause can submit it to Solana after the pause is active. This is a realistic scenario during incident response where the Solana bridge is paused but the NEAR bridge had already signed a deployment.

### Recommendation

1. Add a `DEPLOY_TOKEN_PAUSED` flag constant:
```rust
pub const DEPLOY_TOKEN_PAUSED: u8 = 1 << 2;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED;
```

2. Add a pause check to `deploy_token`:
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

1. Admin calls `pause` on the Solana `bridge_token_factory`, setting `config.paused = ALL_PAUSED` (value `0x03`).
2. `finalize_transfer` and `init_transfer` now revert with `Paused`.
3. A relayer holds a valid `SignedPayload<DeployTokenPayload>` that was signed by the NEAR bridge before the pause.
4. The relayer calls `deploy_token` with this payload. The instruction succeeds — no pause check exists — and a new SPL token mint is initialized and registered in the bridge state.
5. The bridge is in an inconsistent state: transfers are blocked but a new token has been deployed, potentially exploiting whatever vulnerability triggered the pause.

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

**File:** solana/programs/bridge_token_factory/src/lib.rs (L82-85)
```rust
        require!(
            ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
        );
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L135-138)
```text
    function deployToken(
        bytes calldata signatureData,
        BridgeTypes.MetadataPayload calldata metadata
    ) external payable whenNotPaused(PAUSED_DEPLOY_TOKEN) returns (address) {
```

**File:** starknet/src/omni_bridge.cairo (L202-203)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');
```

**File:** near/omni-bridge/src/lib.rs (L1136-1138)
```rust
    #[payable]
    #[pause(except(roles(Role::DAO)))]
    pub fn deploy_token(&mut self, #[serializer(borsh)] args: DeployTokenArgs) -> Promise {
```
