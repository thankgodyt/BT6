### Title
Delegate Can Drain Any Approved Token Account via `InitTransfer` - (File: `solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

### Summary
The Solana `InitTransfer` instruction does not enforce that the `from` token account is owned by the `user` signer. Because the SPL token program permits delegates to transfer tokens, any account that has been approved as a delegate on a victim's token account can call `init_transfer` to drain the victim's tokens into the bridge vault and route them to an attacker-controlled cross-chain recipient.

### Finding Description
The `InitTransfer` Anchor account struct defines `from` with only mint and token-program constraints:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
``` [1](#0-0) 

There is no `token::authority = user` constraint, so Anchor does not verify that `user` is the owner of `from`. The downstream SPL token CPI uses `user` as the transfer authority:

```rust
transfer_checked(
    CpiContext::new(
        self.token_program.to_account_info(),
        TransferChecked {
            from: self.from.to_account_info(),
            to: vault.to_account_info(),
            authority: self.user.to_account_info(),   // ← attacker-controlled signer
            mint: self.mint.to_account_info(),
        },
    ),
    ...
)?;
``` [2](#0-1) 

The SPL token program accepts a `transfer_checked` call when the `authority` is either the token account's owner **or** an approved delegate with sufficient allowance. Because the bridge only checks that `user` is a `Signer`, an attacker who holds a delegate approval on a victim's token account can supply the victim's account as `from` and their own account as `user`, causing the victim's tokens to be locked in the vault.

The same flaw exists in the `burn` path for bridged tokens:

```rust
burn(
    CpiContext::new(
        self.token_program.to_account_info(),
        Burn {
            mint: self.mint.to_account_info(),
            from: self.from.to_account_info(),
            authority: self.user.to_account_info(),
        },
    ),
    ...
)?;
``` [3](#0-2) 

The cross-chain message posted to NEAR records `user.key()` as the sender and the attacker-supplied `payload.recipient` as the destination:

```rust
self.common.post_message(payload.serialize_for_near((
    self.common.sequence.sequence,
    self.user.key(),
    self.mint.key(),
))?)?;
``` [4](#0-3) 

The attacker therefore controls both the source of funds (victim's `from` account) and the destination (arbitrary cross-chain `recipient`).

### Impact Explanation
An attacker who holds a delegate approval on a victim's Solana token account can call `init_transfer` with:
- `from` = victim's token account
- `user` = attacker's signing key (which is the delegate)
- `payload.recipient` = attacker's address on the destination chain (NEAR, EVM, etc.)

The victim's tokens are locked in the bridge vault and a valid cross-chain transfer message is emitted, causing the tokens to be minted or released to the attacker on the destination chain. This constitutes a complete, irreversible loss of the victim's bridged funds — a critical impact.

### Likelihood Explanation
Solana token account delegation (`spl_token::instruction::approve`) is used by many DeFi protocols (DEXes, lending markets, yield aggregators). Any user who has ever approved a third-party program or keypair as a delegate on a token account that is also supported by the Omni Bridge is at risk. The attacker needs no special role, no admin access, and no leaked keys — only a valid delegate approval that the victim may have granted for an entirely unrelated purpose.

### Recommendation
Add the `token::authority = user` constraint to the `from` account in the `InitTransfer` struct. This Anchor constraint checks that `from.owner == user.key()`, ensuring only the actual owner of the token account can initiate a bridge transfer:

```rust
#[account(
    mut,
    token::mint = mint,
    token::authority = user,          // ← add this
    token::token_program = token_program,
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
```

This mirrors the fix recommended in the external report: enforce that the entity whose tokens are being spent is the same as the transaction signer, rather than accepting an arbitrary caller-supplied account.

### Proof of Concept
1. Alice holds 10,000 USDC in her Solana token account `alice_ata` and has previously called `spl_token::approve(alice_ata, delegate=bob, amount=10_000)` for some unrelated DeFi interaction.
2. Bob constructs an `InitTransfer` instruction with:
   - `from = alice_ata`
   - `user = bob` (Bob signs the transaction)
   - `payload.amount = 10_000`
   - `payload.recipient = "eth:0xBob..."` (Bob's EVM address)
3. The Anchor constraint check passes because `from` only requires `token::mint = mint`.
4. The SPL `transfer_checked` CPI succeeds because Bob is a valid delegate of `alice_ata`.
5. 10,000 USDC are locked in the bridge vault; the Wormhole message triggers minting/release of 10,000 USDC to Bob's EVM address.
6. Alice's funds are permanently lost. [5](#0-4)

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L20-69)
```rust
#[derive(Accounts)]
pub struct InitTransfer<'info> {
    #[account(
        seeds = [AUTHORITY_SEED],
        bump = common.config.bumps.authority,
    )]
    pub authority: SystemAccount<'info>,

    #[account(
        mut,
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        mut,
        token::mint = mint,
        token::token_program = token_program,
    )]
    pub from: Box<InterfaceAccount<'info, TokenAccount>>,
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
        mut,
        seeds = [SOL_VAULT_SEED],
        bump = common.config.bumps.sol_vault,
    )]
    pub sol_vault: SystemAccount<'info>,

    #[account(
        mut,
        owner = common.system_program.key(),
    )]
    pub user: Signer<'info>,

    pub common: WormholeCPI<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L90-102)
```rust
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

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L110-120)
```rust
            burn(
                CpiContext::new(
                    self.token_program.to_account_info(),
                    Burn {
                        mint: self.mint.to_account_info(),
                        from: self.from.to_account_info(),
                        authority: self.user.to_account_info(),
                    },
                ),
                payload.amount.try_into().map_err(|_| error!(ErrorCode::InvalidArgs))?,
            )?;
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L123-127)
```rust
        self.common.post_message(payload.serialize_for_near((
            self.common.sequence.sequence,
            self.user.key(),
            self.mint.key(),
        ))?)?;
```
