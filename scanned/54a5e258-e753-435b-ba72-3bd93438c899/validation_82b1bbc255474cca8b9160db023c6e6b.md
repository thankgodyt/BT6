### Title
Missing Mint Account Validation Against Signed Payload Token in `finalize_transfer` - (File: `solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs`)

### Summary

The `FinalizeTransfer` accounts struct accepts a `mint` account with no constraint tying it to the token identifier (`data.payload.token`) in the authenticated signed payload. An attacker holding a valid MPC-signed payload for any low-value bridged token can substitute a different (higher-value) bridged token's mint, causing the program to mint the wrong token to themselves.

### Finding Description

In `finalize_transfer.rs`, the `mint` account is declared with only a `mint::token_program` constraint:

```rust
#[account(
    mut,
    mint::token_program = token_program,
)]
pub mint: Box<InterfaceAccount<'info, Mint>>,
``` [1](#0-0) 

There is no PDA seed constraint linking `mint` to `data.payload.token`. By contrast, the `deploy_token` instruction correctly derives the mint from the payload token:

```rust
#[account(
    init,
    seeds = [WRAPPED_MINT_SEED, data.payload.token.to_hashed_bytes().as_ref()],
    bump,
    ...
)]
pub mint: Box<Account<'info, Mint>>,
``` [2](#0-1) 

The `vault` account (which determines native-unlock vs. bridged-mint path) is itself derived from the caller-supplied `mint`:

```rust
seeds = [VAULT_SEED, mint.key().as_ref()],
``` [3](#0-2) 

The only bridged-token guard documented in the security invariants is that `mint_authority == authority PDA` (`InvalidBridgedToken`). This check is satisfied by **any** bridged token deployed through the factory, not just the one named in the payload. [4](#0-3) 

The `used_nonces` account is derived from `data.payload.destination_nonce`, which is part of the signed payload and is correctly validated. However, nonce consumption does not prevent mint substitution — it only prevents replay of the same nonce. [5](#0-4) 

### Impact Explanation

**Critical — Unauthorized minting of arbitrary bridged tokens.**

An attacker who obtains a valid MPC-signed `FinalizeTransferPayload` for token A (e.g., a low-value bridged token) can call `finalize_transfer` substituting mint B (a high-value bridged token). The program:

1. Verifies the ECDSA signature against `derived_near_bridge_address` — passes (payload is authentic).
2. Marks `destination_nonce` as used — passes.
3. Finds no vault for mint B → takes the bridged-token (mint) path.
4. Checks `mint_authority == authority PDA` — passes (all factory-deployed mints share this authority).
5. Mints `payload.amount` of token B to the attacker.

The attacker receives tokens of a completely different (and potentially far more valuable) asset than what the signed payload authorized, constituting unauthorized minting and direct theft of bridged token supply.

### Likelihood Explanation

**High.** The attacker-controlled entry path is the public `finalize_transfer` instruction, callable by any Solana account (relayer role is not required for this instruction). The attacker only needs a legitimately signed payload — obtainable by initiating any real cross-chain transfer from NEAR to Solana for any bridged token. No privileged access, key compromise, or validator collusion is required. [6](#0-5) 

### Recommendation

Add a PDA seed constraint on `mint` in `FinalizeTransfer` that derives the expected wrapped mint from `data.payload.token`, mirroring the pattern used in `DeployToken`:

```rust
// For the bridged-token case, enforce:
#[account(
    mut,
    seeds = [WRAPPED_MINT_SEED, data.payload.token.to_hashed_bytes().as_ref()],
    bump,
    mint::token_program = token_program,
)]
pub mint: Box<InterfaceAccount<'info, Mint>>,
```

For native tokens (where no wrapped mint PDA exists), the instruction should be split into separate `finalize_transfer_native` and `finalize_transfer_bridged` instructions (similar to the existing `finalize_transfer_sol` split), each with the appropriate account constraints enforced at the Anchor constraint level rather than in the process function body.

### Proof of Concept

1. Attacker initiates a transfer of 1 unit of `token_A` (a low-value bridged token, e.g., worth $0.001) from NEAR to Solana, with themselves as recipient. NEAR MPC produces a signed `FinalizeTransferPayload{token: token_A, amount: 1, destination_nonce: N, recipient: attacker}`.

2. Attacker identifies `mint_B` — the Solana mint for a high-value bridged token (e.g., wBTC equivalent) deployed via the same factory. Its `mint_authority` is the program's `authority` PDA.

3. Attacker calls `finalize_transfer` passing:
   - `data` = the signed payload for `token_A`
   - `mint` = `mint_B` (the high-value token's mint address)
   - `vault` = `None` (no vault exists for `mint_B`, forcing the mint path)
   - `token_account` = attacker's ATA for `mint_B`

4. Anchor validates: signature ✓, nonce ✓, `mint_authority == authority` ✓. No constraint rejects `mint_B`.

5. Program mints 1 unit of `mint_B` (high-value token) to the attacker. Nonce N is consumed.

6. The legitimate `token_A` transfer for nonce N is now permanently blocked (nonce already used), and the attacker holds an unauthorized `mint_B` token. [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L23-87)
```rust
#[derive(Accounts)]
#[instruction(data: SignedPayload<FinalizeTransferPayload>)]
pub struct FinalizeTransfer<'info> {
    #[account(
        mut,
        seeds = [CONFIG_SEED],
        bump = config.bumps.config,
    )]
    pub config: Box<Account<'info, Config>>,
    #[account(
        init_if_needed,
        space = usize::try_from(USED_NONCES_ACCOUNT_SIZE).unwrap(),
        payer = common.payer,
        seeds = [
            USED_NONCES_SEED,
            &(data.payload.destination_nonce / u64::from(USED_NONCES_PER_ACCOUNT)).to_le_bytes(),
        ],
        bump,
    )]
    pub used_nonces: AccountLoader<'info, UsedNonces>,
    #[account(
        mut,
        seeds = [AUTHORITY_SEED],
        bump = config.bumps.authority,
    )]
    pub authority: SystemAccount<'info>,

    /// CHECK: this can be any type of account
    pub recipient: UncheckedAccount<'info>,

    #[account(
        mut,
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    // if this account exists the mint registration is already sent
    #[account(
        mut,
        token::mint = mint,
        token::authority = authority,
        seeds = [
            VAULT_SEED,
            mint.key().as_ref(),
        ],
        bump,
        token::token_program = token_program,
    )]
    pub vault: Option<Box<InterfaceAccount<'info, TokenAccount>>>,

    #[account(
        init_if_needed,
        payer = common.payer,
        associated_token::mint = mint,
        associated_token::authority = recipient,
        token::token_program = token_program,
    )]
    pub token_account: Box<InterfaceAccount<'info, TokenAccount>>,

    pub common: WormholeCPI<'info>,

    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
}
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/deploy_token.rs (L37-72)
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

**File:** solana/CLAUDE.md (L30-30)
```markdown
**NEAR → Solana (finalizeTransfer / finalizeTransferSol)**: A relayer calls `finalize_transfer` with a `SignedPayload` containing a NEAR MPC ECDSA signature. The program verifies the signature against `derived_near_bridge_address` stored in config, marks the `destination_nonce` as used, then unlocks (native) or mints (bridged) tokens to the recipient's ATA (auto-created if needed). A confirmation message is posted back via Wormhole.
```

**File:** solana/CLAUDE.md (L38-44)
```markdown
- **No replay attacks**: Every `destination_nonce` is checked and marked used in a bit-array (`UsedNonces`) before any token operation. A nonce must never be reusable. Nonces are bucketed (1024 per account) and accounts are created on demand
- **No mint/unlock without proof**: Tokens must never be minted or unlocked unless the instruction provides a valid, previously-unused ECDSA signature from the NEAR bridge. "Valid" = recovers to `derived_near_bridge_address`; "previously-unused" = the nonce is unmarked in `UsedNonces`. Any code path that moves tokens outward without both checks is a critical vulnerability
- **Atomic Wormhole posting**: A Wormhole message and its corresponding token lock/burn must occur in the same transaction. Never post a message without the token state change, and never change token state without posting the message — either direction is a bridge invariant violation
- **Malleable signature protection**: The program rejects signatures where `s` is high (`signature.s.is_high()`) to prevent signature malleability
- **Fee < amount**: `fee >= amount` must always revert (`InvalidFee`)
- **Bridged token authority check**: When minting/burning bridged tokens, the program verifies `mint_authority` matches the authority PDA (`InvalidBridgedToken`)
- **Pause granularity**: `init_transfer` and `finalize_transfer` can be paused independently via bit flags (`INIT_TRANSFER_PAUSED = 1`, `FINALIZE_TRANSFER_PAUSED = 2`)
```
