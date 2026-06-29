### Title
`deploy_token` Bypasses Pause Mechanism on Solana — (`solana/programs/bridge_token_factory/src/lib.rs`)

### Summary
The Solana `bridge_token_factory` program's `deploy_token` instruction has no pause check, while `init_transfer`, `init_transfer_sol`, `finalize_transfer`, and `finalize_transfer_sol` all enforce pause flags. Furthermore, the `ALL_PAUSED` bitmask is defined to cover only `INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED` — there is no `DEPLOY_TOKEN_PAUSED` flag at all, unlike the EVM and Starknet bridge implementations which both define and enforce a deploy-token pause flag.

### Finding Description
The Solana bridge defines two pause flags: [1](#0-0) 

`INIT_TRANSFER_PAUSED = 1 << 0` and `FINALIZE_TRANSFER_PAUSED = 1 << 1`, with `ALL_PAUSED = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED`. There is no `DEPLOY_TOKEN_PAUSED` bit.

The four transfer instructions correctly enforce these flags: [2](#0-1) [3](#0-2) 

But `deploy_token` has no such check: [4](#0-3) 

By contrast, the EVM bridge defines and enforces `PAUSED_DEPLOY_TOKEN`: [5](#0-4) [6](#0-5) 

And the Starknet bridge defines and enforces `PAUSE_DEPLOY_TOKEN`: [7](#0-6) [8](#0-7) 

The Solana bridge has no equivalent flag and no enforcement in `deploy_token`.

### Impact Explanation
When the Solana bridge is fully paused (e.g., in response to a discovered vulnerability), any relayer holding a pre-signed `DeployTokenPayload` — signed by the NEAR MPC before the pause — can still call `deploy_token` on Solana. This executes a deployer-equivalent action (creating a new wrapped-token mint account and Metaplex metadata) while the emergency stop is supposed to be in effect. This is a direct pause bypass: the admin's ability to halt all bridge operations is incomplete, and the `deploy_token` surface remains open. The newly deployed mint account is then immediately usable once the bridge is unpaused, potentially racing ahead of any remediation that depends on a clean state.

### Likelihood Explanation
Relayers routinely hold signed payloads in flight. Any `log_metadata` call processed by the NEAR bridge before a pause produces a signed `DeployTokenPayload` that remains valid indefinitely. A relayer (or any party who obtained the signed payload) can submit it to Solana at any time, including during a pause. No special privilege beyond possession of the signed payload is required.

### Recommendation
Add a `DEPLOY_TOKEN_PAUSED` flag to `constants.rs` (e.g., `1 << 2`) and include it in `ALL_PAUSED`. Add the corresponding pause check at the top of `deploy_token` in `lib.rs`, mirroring the pattern used by `finalize_transfer` and `init_transfer`, and matching the behavior already implemented on EVM and Starknet.

### Proof of Concept
1. Before any pause: a user calls `log_metadata` on the NEAR bridge for token `T`. The NEAR MPC signs a `DeployTokenPayload` for `T`. A relayer receives the signed payload.
2. An emergency is discovered; the Solana admin calls `pause`, setting `config.paused = ALL_PAUSED` (`0x03`).
3. Any call to `init_transfer` or `finalize_transfer` now reverts with `Paused`.
4. The relayer submits the pre-signed `DeployTokenPayload` to `deploy_token`. Because `deploy_token` reads `config.paused` nowhere, the instruction succeeds: a new wrapped-mint PDA and Metaplex metadata account for token `T` are created on Solana while the bridge is supposed to be fully halted. [4](#0-3) [9](#0-8)

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

**File:** solana/programs/bridge_token_factory/src/lib.rs (L124-128)
```rust
    pub fn init_transfer(ctx: Context<InitTransfer>, payload: InitTransferPayload) -> Result<()> {
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

**File:** starknet/src/omni_bridge.cairo (L69-71)
```text
    const PAUSE_INIT_TRANSFER: u8 = 0x01; // 0001
    const PAUSE_FIN_TRANSFER: u8 = 0x02; // 0010
    const PAUSE_DEPLOY_TOKEN: u8 = 0x04; // 0100
```

**File:** starknet/src/omni_bridge.cairo (L202-203)
```text
        fn deploy_token(ref self: ContractState, signature: Signature, payload: MetadataPayload) {
            assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED');
```
