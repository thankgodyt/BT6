### Title
Missing Freeze Authority Validation on Native Token Mint Allows Permanent Freezing of Bridge Vault Funds — (`solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs`)

---

### Summary

The `log_metadata` instruction registers a native Solana token with the bridge and creates a PDA vault to hold locked tokens. It does not validate that the token mint has no freeze authority. A token creator can register a mint that retains a freeze authority, accumulate user funds in the vault via `init_transfer`, then freeze the vault PDA, permanently trapping all deposited tokens.

---

### Finding Description

`log_metadata` creates the bridge vault for a native token with only two constraints on the mint:

```rust
#[account(
    constraint = !mint.mint_authority.contains(authority.key),
    mint::token_program = token_program,
)]
pub mint: Box<InterfaceAccount<'info, Mint>>,
``` [1](#0-0) 

The constraint `!mint.mint_authority.contains(authority.key)` only prevents the bridge's own authority PDA from being the mint authority. There is no check that `mint.freeze_authority` is `None`. The vault is then initialized as a PDA seeded by `[VAULT_SEED, mint.key()]` with `token::authority = authority`:

```rust
#[account(
    init_if_needed,
    payer = common.payer,
    token::mint = mint,
    token::authority = authority,
    seeds = [VAULT_SEED, mint.key().as_ref()],
    bump,
    token::token_program = token_program,
)]
pub vault: Box<InterfaceAccount<'info, TokenAccount>>,
``` [2](#0-1) 

In SPL Token, the freeze authority of a mint can call `freeze_account` on **any** token account associated with that mint, regardless of who owns the account. The vault PDA is not exempt. Once frozen, `transfer_checked` on a frozen account fails unconditionally.

`init_transfer` (Solana → NEAR) transfers tokens from the user into the vault:

```rust
transfer_checked(
    CpiContext::new(..., TransferChecked {
        from: self.from.to_account_info(),
        to: vault.to_account_info(),
        ...
    }),
    ...
)?;
``` [3](#0-2) 

`finalize_transfer` (NEAR → Solana) transfers tokens out of the vault to the recipient:

```rust
transfer_checked(
    CpiContext::new_with_signer(..., TransferChecked {
        from: vault.to_account_info(),
        to: self.token_account.to_account_info(),
        ...
    }),
    ...
)?;
``` [4](#0-3) 

Both operations fail if the vault is frozen. Tokens already deposited in the vault become permanently inaccessible.

---

### Impact Explanation

**Permanent loss of bridged funds.** Once the vault is frozen:

- All tokens previously deposited via `init_transfer` are trapped in the vault with no recovery path. The bridge program has no `thaw_account` instruction and no admin escape hatch for frozen vaults.
- Any in-flight NEAR → Solana transfer (where NEAR-side tokens are already burned) cannot be finalized. The nonce is not consumed because the transaction reverts, but the NEAR-side burn is irreversible, so users lose their assets permanently.
- `init_transfer` also fails for new Solana → NEAR transfers, halting all bridge activity for that token.

This matches the allowed impact scope: **permanent freezing of bridged funds**.

---

### Likelihood Explanation

The attack is reachable by any token creator. `log_metadata` is permissionless — anyone can call it for any mint that passes the two existing constraints. A malicious token issuer deploys a mint with a freeze authority, lists the token, waits for users to bridge meaningful value into the vault, then calls `freeze_account` on the vault PDA. No admin compromise, no key leakage, and no bridge-operator action is required. The freeze authority is a standard, publicly visible field on the mint account.

---

### Recommendation

Add a freeze authority check to the `mint` account constraint in `LogMetadata`:

```rust
#[account(
    constraint = !mint.mint_authority.contains(authority.key),
    constraint = mint.freeze_authority.is_none() @ ErrorCode::FreezeAuthorityNotAllowed,
    mint::token_program = token_program,
)]
pub mint: Box<InterfaceAccount<'info, Mint>>,
``` [1](#0-0) 

This mirrors the recommendation in the reference report and prevents any mint with an active freeze authority from being registered as a native bridge token.

---

### Proof of Concept

1. Attacker deploys a SPL Token mint `M` with `freeze_authority = ATTACKER_KEY`.
2. Attacker (or anyone) calls `log_metadata` with mint `M`. The constraint `!mint.mint_authority.contains(authority.key)` passes (attacker's key ≠ bridge authority PDA). Vault PDA `V = PDA([VAULT_SEED, M])` is created.
3. Legitimate users call `init_transfer` with mint `M`, depositing tokens into vault `V`. Wormhole messages are posted; NEAR side processes them and burns/locks NEAR-side assets.
4. Attacker calls SPL Token's `freeze_account(V, ATTACKER_KEY)`. Vault `V` is now frozen.
5. Any subsequent `finalize_transfer` (NEAR → Solana) that routes through vault `V` calls `transfer_checked(from: V, ...)` and receives `AccountFrozen` error. The transaction reverts; the nonce is not consumed; but the NEAR-side burn is already final.
6. All tokens in vault `V` are permanently inaccessible. Users who initiated Solana → NEAR transfers and had their NEAR-side assets burned cannot recover them. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L41-62)
```rust
    #[account(
        constraint = !mint.mint_authority.contains(authority.key),
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    /// CHECK: may be unitialized
    pub metadata: Option<UncheckedAccount<'info>>,

    #[account(
        init_if_needed,
        payer = common.payer,
        token::mint = mint,
        token::authority = authority,
        seeds = [
            VAULT_SEED,
            mint.key().as_ref(),
        ],
        bump,
        token::token_program = token_program,
    )]
    pub vault: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L88-102)
```rust
        if let Some(vault) = &self.vault {
            // Native version. We have a proof of token registration by vault existence
            transfer_checked(
                CpiContext::new(
                    self.token_program.to_account_info(),
                    TransferChecked {
                        from: self.from.to_account_info(),
                        to: vault.to_account_info(),
                        authority: self.user.to_account_info(),
                        mint: self.mint.to_account_info(),
                    },
                ),
                payload.amount.try_into().map_err(|_| error!(ErrorCode::InvalidArgs))?,
                self.mint.decimals,
            )?;
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L101-116)
```rust
        if let Some(vault) = &self.vault {
            // Native version. We have a proof of token registration by vault existence
            transfer_checked(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    TransferChecked {
                        from: vault.to_account_info(),
                        to: self.token_account.to_account_info(),
                        authority: self.authority.to_account_info(),
                        mint: self.mint.to_account_info(),
                    },
                    &[&[AUTHORITY_SEED, &[self.config.bumps.authority]]],
                ),
                data.amount.try_into().map_err(|_| error!(ErrorCode::AmountOverflow))?,
                self.mint.decimals,
            )?;
```
