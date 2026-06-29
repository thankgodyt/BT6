The vulnerability is real. Let me confirm the exact constraint gap before writing the finding.

The `from` account in `InitTransfer` is constrained only by: [1](#0-0) 

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
```

There is **no** `token::authority = user` constraint. The `user` is only required to be a signer and a system-program-owned account: [2](#0-1) 

In `process`, the CPI authority passed to both `transfer_checked` (native path) and `burn` (bridged path) is `self.user`: [3](#0-2) [4](#0-3) 

The SPL Token program's `transfer_checked` and `burn` accept **either** the account owner **or** an approved delegate as the authority. So if an attacker holds a delegation over a victim's token account, passing `user = attacker` satisfies the SPL Token authority check even though `from.owner != user`.

The Wormhole message is then posted with `sender = self.user.key()` (attacker) and an attacker-controlled `recipient`: [5](#0-4) 

---

### Title
Delegated SPL Token Authority Allows Attacker to Bridge Victim's Tokens to Attacker-Controlled NEAR Recipient — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

### Summary
The `InitTransfer` account struct does not enforce that the `from` token account is owned by `user`. Because SPL Token's `transfer_checked` and `burn` accept a delegate as a valid authority, any attacker who holds a delegation over a victim's token account can call `init_transfer` with `from = victim_account` and `user = attacker`, causing the victim's tokens to be locked in the vault or burned on Solana while the attacker receives the equivalent on NEAR.

### Finding Description
The `from` account is validated only for mint and token-program membership:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
```

No `token::authority = user` constraint is present. In `process`, the CPI calls pass `self.user` as the authority:

```rust
// Native path
TransferChecked { from: self.from, authority: self.user, ... }

// Bridged path
Burn { from: self.from, authority: self.user, ... }
```

SPL Token accepts this CPI if `self.user` is either the owner **or** an approved delegate of `self.from`. The bridge never checks which case applies. After the CPI succeeds, the Wormhole message encodes `sender = self.user.key()` (attacker) and the attacker-supplied `recipient` string, so the NEAR-side finalization releases funds to the attacker.

### Impact Explanation
Victim's SPL tokens are irreversibly locked in the vault or burned on Solana. The attacker receives the equivalent bridged tokens on NEAR at an address they control. This is a direct, permanent theft of user funds routed through the bridge.

### Likelihood Explanation
A delegation prerequisite exists, but it is realistic: users routinely approve contracts or addresses as SPL Token delegates (e.g., for DEX trading, lending, or yield strategies). An attacker who controls any such approved contract, or who tricks a user into approving them, can immediately exploit this path. No admin compromise or key leak is required.

### Recommendation
Add `token::authority = user` to the `from` account constraint:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
    token::authority = user,   // <-- add this
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
```

This restricts `from` to accounts whose `owner` field equals `user`, rejecting delegated-authority callers at the Anchor constraint layer before any CPI is attempted.

### Proof of Concept
1. Victim holds `victim_ata` (owner = victim, mint = M).
2. Victim calls `spl_token::approve(victim_ata, delegate = attacker, amount = X)`.
3. Attacker calls `init_transfer` with:
   - `from = victim_ata`
   - `user = attacker` (signs the transaction)
   - `mint = M`
   - `vault` present (native path) or absent (bridged path)
   - `payload.recipient = attacker_near_address`
4. Anchor constraints pass (mint matches, token_program matches).
5. `transfer_checked` / `burn` CPI succeeds because attacker is a valid delegate.
6. Wormhole message is posted: `sender = attacker`, `recipient = attacker_near_address`.
7. Victim's balance decreases by `payload.amount`; attacker redeems on NEAR.

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L34-39)
```rust
    #[account(
        mut,
        token::mint = mint,
        token::token_program = token_program,
    )]
    pub from: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L60-64)
```rust
    #[account(
        mut,
        owner = common.system_program.key(),
    )]
    pub user: Signer<'info>,
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
