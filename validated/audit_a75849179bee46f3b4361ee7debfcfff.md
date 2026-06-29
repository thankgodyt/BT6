Audit Report

## Title
Missing Pause Check in `deploy_token` Allows Token Deployment While Bridge Is Paused - (File: `solana/programs/bridge_token_factory/src/lib.rs`)

## Summary
The Solana `bridge_token_factory` program's `deploy_token` instruction performs no pause check, while every other chain's equivalent (`deployToken` on EVM, `deploy_token` on Starknet and NEAR) enforces a pause guard. When the bridge is paused via `ALL_PAUSED`, the `deploy_token` instruction remains fully callable, constituting a concrete pause bypass for a deployer-equivalent action.

## Finding Description
`ALL_PAUSED` is defined as the bitwise OR of only two flags: [1](#0-0) 

When `pause` is called, it sets `config.paused = ALL_PAUSED` (value `0x03`): [2](#0-1) 

`finalize_transfer`, `finalize_transfer_sol`, `init_transfer`, and `init_transfer_sol` all gate on the relevant pause bit before proceeding: [3](#0-2) [4](#0-3) 

`deploy_token`, however, contains no pause check at all: [5](#0-4) 

All other chain implementations enforce a pause guard on the equivalent function:

- **EVM** `OmniBridge.sol`: `whenNotPaused(PAUSED_DEPLOY_TOKEN)` [6](#0-5) 
- **Starknet** `omni_bridge.cairo`: `assert(!_is_paused(@self, PAUSE_DEPLOY_TOKEN), 'ERR_DEPLOY_TOKEN_PAUSED')` [7](#0-6) 
- **NEAR** `lib.rs`: `#[pause(except(roles(Role::DAO)))]` [8](#0-7) 

There is no `DEPLOY_TOKEN_PAUSED` bit defined, and `ALL_PAUSED` does not cover token deployment. The only validation `deploy_token` performs is a signature check against `derived_near_bridge_address`, which is satisfied by any legitimately pre-issued `SignedPayload<DeployTokenPayload>`. [9](#0-8) 

## Impact Explanation
This is a concrete pause bypass that allows an external actor to execute a deployer-equivalent action (`deploy_token`) while the Solana bridge is in a fully paused state. This matches the allowed critical impact: *"pause bypass... that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions."* The bypass creates an inconsistent paused state where transfers are blocked but new SPL token mints can still be registered into the bridge's on-chain state. If the emergency pause was triggered due to a flaw in the token initialization path (`initialize_token_metadata`), the bypass allows continued exploitation of that flaw while the bridge is supposedly halted.

## Likelihood Explanation
The attacker requires a valid `SignedPayload<DeployTokenPayload>` signed by the NEAR bridge's derived address. Such payloads are legitimately produced by the NEAR side during normal operation. Because the NEAR and Solana bridges are independently pausable, a payload signed by NEAR before the Solana-side pause was triggered can be submitted to Solana after the pause is active. Any relayer or user who obtained such a payload before the Solana pause can exploit this. This is a realistic incident-response scenario and requires no privileged access beyond possession of a legitimately issued signed payload.

## Recommendation
1. Add a `DEPLOY_TOKEN_PAUSED` flag and include it in `ALL_PAUSED` in `solana/programs/bridge_token_factory/src/constants.rs`:
```rust
pub const DEPLOY_TOKEN_PAUSED: u8 = 1 << 2;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED;
```
2. Add a pause check at the top of `deploy_token` in `solana/programs/bridge_token_factory/src/lib.rs`:
```rust
require!(
    ctx.accounts.common.config.paused & DEPLOY_TOKEN_PAUSED == 0,
    error::ErrorCode::Paused
);
```
3. Import `DEPLOY_TOKEN_PAUSED` alongside the other pause constants in `lib.rs`.

## Proof of Concept
1. Admin calls `pause` on the Solana `bridge_token_factory`; `config.paused` is set to `ALL_PAUSED` (`0x03`).
2. Confirm `finalize_transfer` and `init_transfer` revert with `Paused`.
3. Obtain (or construct) a valid `SignedPayload<DeployTokenPayload>` signed by the NEAR bridge's `derived_near_bridge_address` (e.g., one issued before the pause).
4. Call `deploy_token` with this payload on the paused program.
5. Observe the instruction succeeds: no pause check fires, `initialize_token_metadata` runs, and a new SPL token mint is registered in bridge state.
6. The bridge is in an inconsistent state: transfers are blocked but a new token has been deployed.

A local Anchor integration test can reproduce this by: initializing the program, calling `pause`, then calling `deploy_token` with a correctly signed payload and asserting the transaction succeeds (rather than returning `ErrorCode::Paused`).

### Citations

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
