Audit Report

## Title
`deploy_token` Bypasses Pause Mechanism on Solana — (`solana/programs/bridge_token_factory/src/lib.rs`)

## Summary
The Solana `bridge_token_factory` program defines only two pause flags (`INIT_TRANSFER_PAUSED` and `FINALIZE_TRANSFER_PAUSED`) and enforces them on all transfer instructions, but the `deploy_token` instruction has no pause check whatsoever. The EVM and Starknet bridge implementations both define and enforce a dedicated deploy-token pause flag, making this an inconsistency that constitutes a concrete pause bypass on Solana.

## Finding Description
`constants.rs` defines: [1](#0-0) 

There is no `DEPLOY_TOKEN_PAUSED` bit, and `ALL_PAUSED` covers only the two transfer flags.

`lib.rs` `deploy_token` performs only signature verification and metadata initialization — no pause check: [2](#0-1) 

By contrast, all four transfer instructions enforce their respective flags, e.g.: [3](#0-2) [4](#0-3) 

The EVM bridge defines `PAUSED_DEPLOY_TOKEN = 1 << 2` and enforces it: [5](#0-4) [6](#0-5) 

The Starknet bridge defines `PAUSE_DEPLOY_TOKEN = 0x04` and enforces it: [7](#0-6) [8](#0-7) 

The Solana program has no equivalent protection.

## Impact Explanation
This is a concrete pause bypass allowing an unprivileged external party to execute a deployer-equivalent action (creating a new wrapped-token mint PDA and Metaplex metadata account) while the bridge is supposed to be fully halted. This matches the allowed critical impact: *"pause bypass... that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions."* The admin's ability to halt all bridge operations is incomplete; the `deploy_token` surface remains open regardless of the pause state.

## Likelihood Explanation
No special privilege is required beyond possession of a valid pre-signed `DeployTokenPayload`. Such payloads are produced by the NEAR MPC whenever `log_metadata` is called on NEAR, and relayers routinely hold them in flight. Any payload signed before the pause remains valid indefinitely. The call is permissionless — any party holding the signed payload can submit it to Solana at any time, including during an emergency pause. The condition is realistic and repeatable.

## Recommendation
Add a `DEPLOY_TOKEN_PAUSED: u8 = 1 << 2` constant to `solana/programs/bridge_token_factory/src/constants.rs` and include it in `ALL_PAUSED`. Add the corresponding `require!` check at the top of `deploy_token` in `lib.rs`, mirroring the pattern used by `finalize_transfer` and `init_transfer`, consistent with the EVM and Starknet implementations.

## Proof of Concept
1. A user calls `log_metadata` on the NEAR bridge for token `T`. The NEAR MPC signs a `DeployTokenPayload` for `T`. A relayer receives the signed payload.
2. An emergency is discovered; the Solana admin calls `pause`, setting `config.paused = ALL_PAUSED` (`0x03`).
3. Any call to `init_transfer`, `init_transfer_sol`, `finalize_transfer`, or `finalize_transfer_sol` now fails with `Paused`.
4. The relayer (or any party with the payload) submits the pre-signed `DeployTokenPayload` to `deploy_token`. Because `deploy_token` never reads `config.paused`, the instruction succeeds: a new wrapped-mint PDA and Metaplex metadata account for token `T` are created on Solana while the bridge is fully paused. [2](#0-1) 

A local integration test can confirm this by: (a) calling `pause` to set `ALL_PAUSED`, (b) asserting that `init_transfer` reverts, and (c) asserting that `deploy_token` with a valid pre-signed payload still succeeds.

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
