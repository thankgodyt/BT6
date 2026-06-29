### Title
Delegate-Authorized Burn/Transfer Enables Cross-Chain Token Theft via Missing `from.owner == user` Constraint — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

---

### Summary

The `InitTransfer` accounts struct imposes no ownership relationship between the `from` token account and the `user` signer. Because the SPL Token program accepts a delegate as a valid authority for `transfer_checked` and `burn`, any attacker holding a delegate approval over a victim's ATA can call `init_transfer` with `from=victim_ATA` and `user=attacker_keypair`, drain the victim's tokens into the bridge, and have the resulting Wormhole VAA encode the attacker's pubkey as sender and the attacker's NEAR address as recipient — completing a full cross-chain theft.

---

### Finding Description

In `InitTransfer`, the `from` account is declared with only two Anchor constraints:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
``` [1](#0-0) 

There is no `token::authority = user` constraint and no runtime check that `from.owner == user.key()`. The `user` account is only required to be a `Signer` owned by the system program:

```rust
#[account(
    mut,
    owner = common.system_program.key(),
)]
pub user: Signer<'info>,
``` [2](#0-1) 

In `process()`, the CPI to the SPL Token program passes `self.user` as the authority for both the native-token path (`transfer_checked`) and the bridged-token path (`burn`): [3](#0-2) [4](#0-3) 

The SPL Token program accepts either the token account's `owner` **or** an approved `delegate` as a valid authority. If the victim has previously called `approve()` granting the attacker delegate rights, the SPL Token program will accept the attacker as authority and execute the burn/transfer without error.

After the tokens are moved, the Wormhole message is posted with `self.user.key()` (the attacker's pubkey) serialized as the `sender` field:

```rust
self.common.post_message(payload.serialize_for_near((
    self.common.sequence.sequence,
    self.user.key(),   // ← attacker's pubkey becomes sender
    self.mint.key(),
))?)?;
``` [5](#0-4) 

In `serialize_for_near`, `params.1` (the attacker's pubkey) is written as the `sender` field of the outgoing Wormhole payload: [6](#0-5) 

The `recipient` field in the payload is the attacker-controlled NEAR address supplied in `InitTransferPayload`. The Wormhole guardians observe a legitimately-emitted program message and threshold-sign the VAA. The NEAR bridge then finalizes the transfer to the attacker's account.

---

### Impact Explanation

An attacker who holds any SPL delegate approval over a victim's ATA (even a small one, since the attacker controls the `amount` field in the payload — though the SPL program will enforce the delegated amount cap) can:

1. Burn or lock the victim's tokens via the bridge.
2. Have the resulting Wormhole VAA encode the attacker's pubkey as sender and the attacker's NEAR address as recipient.
3. Claim the full bridged amount on NEAR.

This constitutes direct, irreversible theft of the victim's bridged tokens. The impact is **Critical**: unauthorized burning/locking of victim funds with attacker as cross-chain beneficiary.

---

### Likelihood Explanation

The precondition — a victim having previously called `approve()` on their ATA — is realistic. Users routinely grant delegate approvals to DEXes, lending protocols, and other Solana programs. Any such approval, if the attacker is the delegate (or if the attacker is a malicious program that was approved), is sufficient. The bridge is unpaused by default and the call sequence requires no privileged access beyond the delegate approval.

---

### Recommendation

Add an Anchor constraint enforcing that the `from` account's authority is the `user` signer:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
    token::authority = user,   // ← add this
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
``` [1](#0-0) 

This ensures only the actual owner of the token account can initiate a bridge transfer, eliminating the delegate-abuse vector entirely.

---

### Proof of Concept

```rust
// 1. Victim approves attacker as delegate on victim_ATA
spl_token::instruction::approve(
    &token_program_id,
    &victim_ata,
    &attacker_pubkey,   // delegate
    &victim_pubkey,     // owner
    &[],
    victim_balance,     // delegated amount
)?;

// 2. Attacker calls init_transfer:
//    from = victim_ATA  (attacker is delegate, not owner)
//    user = attacker_keypair  (signer)
//    recipient = attacker_near_account
//    amount = victim_balance
//
// Anchor constraint on `from` only checks mint + token_program — passes.
// SPL Token burn/transfer_checked accepts attacker as delegate authority — passes.
// Wormhole message encodes attacker pubkey as sender, attacker NEAR addr as recipient.

// 3. Wormhole guardians threshold-sign the VAA (legitimate program emission).

// 4. Attacker submits VAA on NEAR, claims victim's tokens.
```

The test scaffold in `test_init_transfer.rs` already constructs `from_account` with `owner = user` (line 69), but never tests the case where `from.owner != user` and `user` is a delegate — confirming the missing negative test and the absence of any ownership guard. [7](#0-6)

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

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L23-26)
```rust
        // 1. sender
        writer.write_all(&[SOLANA_OMNI_BRIDGE_CHAIN_ID])?;
        params.1.serialize(&mut writer)?;
        // 2. token
```

**File:** solana/programs/bridge_token_factory/tests/mollusk/test_init_transfer.rs (L68-69)
```rust
    let from = Pubkey::new_unique();
    let from_account = create_token_account(&mint, &user, 10_000_000);
```
