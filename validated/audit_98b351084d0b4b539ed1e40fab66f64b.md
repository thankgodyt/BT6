### Title
Missing PDA Seed Constraint on `mint` Account in `FinalizeTransfer` Allows Token Substitution — (`solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs`)

---

### Summary

The `finalize_transfer` instruction accepts a `mint` account with no PDA seed constraint tying it to the token identifier in the signed payload. Because `deploy_token` creates wrapped mints as PDAs seeded by `[WRAPPED_MINT_SEED, token_hash]`, but `finalize_transfer` never re-derives or validates that the supplied `mint` corresponds to `data.payload.token`, an attacker can substitute a different wrapped-token mint and cause the program to mint a higher-value bridged token than what the NEAR MPC actually authorized.

---

### Finding Description

In `deploy_token.rs`, the wrapped mint is created with an explicit PDA constraint:

```rust
#[account(
    init,
    payer = common.payer,
    seeds = [WRAPPED_MINT_SEED, data.payload.token.to_hashed_bytes().as_ref()],
    bump,
    mint::decimals = ...,
    mint::authority = authority,
)]
pub mint: Box<Account<'info, Mint>>,
``` [1](#0-0) 

This binds each wrapped mint to a specific cross-chain token identity at creation time.

However, in `finalize_transfer.rs`, the `mint` account is accepted with only a token-program interface check:

```rust
#[account(
    mut,
    mint::token_program = token_program,
)]
pub mint: Box<InterfaceAccount<'info, Mint>>,
``` [2](#0-1) 

There is no `seeds = [WRAPPED_MINT_SEED, data.payload.token.to_hashed_bytes().as_ref()]` constraint, and no runtime check that `mint.key()` equals the PDA derived from `data.payload.token`. The `vault` account is constrained to the supplied `mint`, not to the payload token:

```rust
#[account(
    mut,
    token::mint = mint,
    token::authority = authority,
    seeds = [VAULT_SEED, mint.key().as_ref()],
    bump,
    ...
)]
pub vault: Option<Box<InterfaceAccount<'info, TokenAccount>>>,
``` [3](#0-2) 

The only security invariant documented for the mint path is that `mint_authority` must equal the `authority` PDA: [4](#0-3) 

This check prevents minting to a completely arbitrary mint, but it does **not** prevent minting to a *different* wrapped mint that was legitimately deployed by the bridge (all wrapped mints share the same `authority` PDA as their mint authority).

---

### Impact Explanation

**Critical — Unauthorized minting / token substitution.**

An attacker who holds a valid NEAR-MPC-signed `FinalizeTransferPayload` for a low-value bridged token (token A, e.g., a dust-value wrapped asset) can call `finalize_transfer` while supplying the mint address of a high-value bridged token (token B, e.g., wrapped ETH or wrapped USDC). Because:

1. The MPC signature is verified against the payload (which names token A and a legitimate nonce/amount), so the signature check passes.
2. The nonce is marked used (preventing replay of the same nonce).
3. The `mint` account is not validated against `data.payload.token`, so token B's mint is accepted.
4. The `authority` PDA is the mint authority for all wrapped mints, so `mint_to` succeeds for token B.

The attacker receives token B tokens (high value) instead of token A tokens (low value), effectively minting unbacked bridged tokens and draining the economic value of token B holders on Solana.

For the native-token vault path (`vault = Some`): the vault is derived from the supplied `mint`, so substituting a different native-token mint redirects the unlock to drain that vault instead.

---

### Likelihood Explanation

**High.** The attack requires only:
- A legitimate (or self-initiated) cross-chain transfer of any low-value token, producing a valid signed payload.
- Knowledge of the wrapped mint addresses of higher-value tokens (all are deterministic PDAs, publicly derivable).
- Calling `finalize_transfer` with the substituted mint before the nonce is consumed.

No admin access, key leakage, or collusion is required. Any bridge user can initiate a transfer of a cheap token and exploit this to receive expensive tokens.

---

### Recommendation

Add an explicit PDA seed constraint on the `mint` account in `FinalizeTransfer` (and analogously in any other instruction that accepts a `mint` without re-deriving it from the payload token):

```rust
#[account(
    mut,
    seeds = [WRAPPED_MINT_SEED, data.payload.token.to_hashed_bytes().as_ref()],
    bump,
    mint::token_program = token_program,
)]
pub mint: Box<InterfaceAccount<'info, Mint>>,
```

For the native-token (vault) path, add a runtime check that the supplied `mint` matches the token registered in the payload, or restructure the account validation so the vault PDA is derived from `data.payload.token` rather than from the caller-supplied `mint.key()`.

Additionally, audit all other instructions that accept a `mint` or `vault` without re-deriving them from the signed payload to ensure no similar substitution is possible.

---

### Proof of Concept

1. Deploy two bridged tokens on Solana via `deploy_token`: token A (worthless) and token B (high-value, e.g., wrapped ETH). Both wrapped mints have `mint_authority = authority PDA`.
2. Initiate a cross-chain transfer of 1,000,000 units of token A from NEAR to Solana. Obtain the resulting `SignedPayload<FinalizeTransferPayload>` (payload references token A, nonce N, amount 1,000,000, recipient = attacker).
3. Call `finalize_transfer` with:
   - `data` = the valid signed payload (token A, nonce N, amount 1,000,000)
   - `mint` = the wrapped mint PDA for token B (not token A)
   - `vault` = `None` (bridged-token path)
   - `token_account` = attacker's ATA for token B
4. The program verifies the MPC signature (passes — payload is authentic), marks nonce N used, then calls `mint_to` on token B's mint using the `authority` PDA signer.
5. Attacker receives 1,000,000 units of token B (high-value) instead of token A, with no corresponding lock on the NEAR side for token B. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L23-88)
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
