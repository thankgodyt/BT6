All code references check out. Here is the validation result:

Audit Report

## Title
`deploy_token` Lacks Pause Guard, Bypassing Emergency Pause - (File: `solana/programs/bridge_token_factory/src/lib.rs`)

## Summary
The Solana `bridge_token_factory` program's `deploy_token` instruction (lines 66–76) performs no pause check before executing, allowing token deployment to proceed even when the bridge is fully paused. This is a concrete pause bypass inconsistent with both the EVM and Starknet implementations, which each enforce a dedicated `PAUSE_DEPLOY_TOKEN` / `PAUSED_DEPLOY_TOKEN` flag. The root cause is that no such flag is defined in `constants.rs` and `ALL_PAUSED` covers only `INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED`.

## Finding Description
In `solana/programs/bridge_token_factory/src/lib.rs`, the `deploy_token` handler at lines 66–76 only verifies the MPC signature and calls `initialize_token_metadata` — no pause check is present:

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

By contrast, `finalize_transfer` (lines 82–85) and `init_transfer` (lines 125–128) both gate execution with:

```rust
require!(
    ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
    error::ErrorCode::Paused
);
```

In `constants.rs` (lines 36–42), only two pause flags are defined:

```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
```

The `pause()` instruction in `pause.rs` (line 27) sets `config.paused = ALL_PAUSED` (= `0x03`). Since no `DEPLOY_TOKEN_PAUSED` bit exists, the pause state is never consulted for `deploy_token`.

The EVM implementation correctly defines `PAUSED_DEPLOY_TOKEN = 1 << 2` (`OmniBridge.sol`, line 55) and gates `deployToken` with `whenNotPaused(PAUSED_DEPLOY_TOKEN)` (line 138). The Starknet implementation defines `PAUSE_DEPLOY_TOKEN: u8 = 0x04` (`omni_bridge.cairo`, line 71) and asserts `!_is_paused(@self, PAUSE_DEPLOY_TOKEN)` at the top of `deploy_token` (line 203). The Solana program has neither.

The `DeployToken` accounts struct (`deploy_token.rs`, lines 37–71) imposes no caller restriction beyond providing a valid signed payload — any party holding a legitimately MPC-signed `DeployTokenPayload` can invoke this instruction.

## Impact Explanation
When `pause()` is called on the Solana bridge, `config.paused` is set to `ALL_PAUSED = 0x03`, which only covers `init_transfer` and `finalize_transfer`. Any holder of a valid NEAR MPC-signed `DeployTokenPayload` — e.g., a relayer holding a payload signed before the pause, or one derived from a pending `LogMetadata` cross-chain event — can still call `deploy_token` on the paused bridge. This creates a new SPL mint, initializes Metaplex metadata, and posts a Wormhole message back to NEAR registering the new token, all while the bridge is supposed to be fully halted. This is a concrete pause bypass that lets an external party execute deployer-equivalent actions on the bridge, matching the allowed Critical impact: *"pause bypass... that lets an attacker execute bridge, token, deployer, relayer, or admin-equivalent actions."*

## Likelihood Explanation
No admin compromise or key theft is required. Any relayer or external party who possesses a legitimately-issued NEAR MPC-signed `DeployTokenPayload` (obtainable from a `LogMetadata` event emitted before the pause) can trigger this. The `DeployToken` accounts struct imposes no signer restriction beyond the signed payload. The scenario is realistic: in an emergency pause, in-flight token registration events may already have signed payloads in circulation. The exploit is repeatable for each such payload.

## Recommendation
1. Add a `DEPLOY_TOKEN_PAUSED` flag to `constants.rs` and include it in `ALL_PAUSED`:

```rust
pub const DEPLOY_TOKEN_PAUSED: u8 = 1 << 2;
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED | DEPLOY_TOKEN_PAUSED;
```

2. Add a pause guard at the top of `deploy_token` in `lib.rs`, consistent with `finalize_transfer` and `init_transfer`:

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

Also import `DEPLOY_TOKEN_PAUSED` in the `use super::constants` line in `lib.rs`.

## Proof of Concept
1. Admin calls `pause()` on the Solana bridge (`pause.rs` line 27), setting `config.paused = ALL_PAUSED = 0x03`.
2. `init_transfer` and `finalize_transfer` are now blocked by their `require!` guards.
3. A relayer holds a valid NEAR MPC-signed `DeployTokenPayload` for a new token (e.g., obtained from a `LogMetadata` event emitted before the pause).
4. The relayer constructs the `DeployToken` accounts and calls `deploy_token` on the paused bridge.
5. The instruction succeeds: a new SPL mint is created, Metaplex metadata is initialized, and a Wormhole message is posted to NEAR — all while the bridge is paused.
6. Verification: `config.paused = 0x03`; since no `DEPLOY_TOKEN_PAUSED` bit (which would be `0x04`) is defined or checked, the pause state is never consulted for this instruction. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** solana/programs/bridge_token_factory/src/lib.rs (L82-85)
```rust
        require!(
            ctx.accounts.common.config.paused & FINALIZE_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
        );
```

**File:** solana/programs/bridge_token_factory/src/constants.rs (L36-42)
```rust
pub const INIT_TRANSFER_PAUSED: u8 = 1 << 0;

#[constant]
pub const FINALIZE_TRANSFER_PAUSED: u8 = 1 << 1;

#[constant]
pub const ALL_PAUSED: u8 = INIT_TRANSFER_PAUSED | FINALIZE_TRANSFER_PAUSED;
```

**File:** solana/programs/bridge_token_factory/src/instructions/admin/pause.rs (L26-28)
```rust
    pub fn process(&mut self) -> Result<()> {
        self.config.paused = ALL_PAUSED;

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

**File:** solana/programs/bridge_token_factory/src/instructions/user/deploy_token.rs (L37-71)
```rust
#[derive(Accounts)]
#[instruction(data: SignedPayload<DeployTokenPayload>)]
pub struct DeployToken<'info> {
    #[account(
        seeds = [AUTHORITY_SEED],
        bump = common.config.bumps.authority,
    )]
    pub authority: SystemAccount<'info>,
    #[account(
        init,
        payer = common.payer,
        seeds = [WRAPPED_MINT_SEED, data.payload.token.to_hashed_bytes().as_ref()],
        bump,
        mint::decimals = std::cmp::min(MAX_ALLOWED_DECIMALS, data.payload.decimals),
        mint::authority = authority,
    )]
    pub mint: Box<Account<'info, Mint>>,
    #[account(
        mut,
        seeds = [
            METADATA_SEED,
            MetaplexID.as_ref(),
            &mint.key().to_bytes(),
        ],
        bump,
        seeds::program = MetaplexID,
    )]
    pub metadata: SystemAccount<'info>,

    pub common: WormholeCPI<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub token_metadata_program: Program<'info, Metaplex>,
}
```
