### Title
Missing `from` Token Account Ownership Check Allows Delegate to Drain Victim's Tokens — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

---

### Summary

The `InitTransfer` account struct constrains `from` only by `token::mint` and `token::token_program`, with no `token::authority = user` constraint. Because SPL Token's `transfer_checked` and `burn` accept either the token account **owner** or an approved **delegate** as the authority, any attacker who holds a valid SPL delegation over a victim's token account can pass `from = victim_ata`, `user = attacker` (signer), and successfully drain the victim's tokens into the vault or burn them — posting a Wormhole message with the attacker as sender and an attacker-controlled NEAR recipient.

---

### Finding Description

The `from` account in `InitTransfer` is declared as:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
``` [1](#0-0) 

There is no `token::authority = user` constraint. Anchor's `token::authority` constraint would verify that `from.owner == user.key()` at the account-validation layer, before `process()` is ever called. Without it, the only runtime check is the SPL Token CPI itself.

In `process()`, the CPI is constructed as:

```rust
TransferChecked {
    from: self.from.to_account_info(),
    to: vault.to_account_info(),
    authority: self.user.to_account_info(),   // attacker is the signer
    mint: self.mint.to_account_info(),
}
``` [2](#0-1) 

And for bridged tokens:

```rust
Burn {
    mint: self.mint.to_account_info(),
    from: self.from.to_account_info(),
    authority: self.user.to_account_info(),   // attacker is the signer
}
``` [3](#0-2) 

The SPL Token program's `transfer_checked` and `burn` instructions accept **either** the token account owner **or** an approved delegate as the `authority`. If the victim has previously called `spl_token::approve` granting the attacker (or a program the attacker controls) delegate authority over their ATA, the CPI succeeds with `from = victim_ata` and `authority = attacker`.

After the tokens are moved, the Wormhole message is posted with:

```rust
self.common.post_message(payload.serialize_for_near((
    self.common.sequence.sequence,
    self.user.key(),   // attacker's pubkey becomes the "sender"
    self.mint.key(),
))?)?;
``` [4](#0-3) 

The attacker fully controls the `recipient` field in `InitTransferPayload`, so the NEAR-side finalization will release the tokens to an attacker-controlled NEAR account.

---

### Impact Explanation

- **Native tokens (vault path):** victim's SPL tokens are locked in the bridge vault; attacker receives equivalent tokens on NEAR.
- **Bridged tokens (burn path):** victim's bridged SPL tokens are burned; attacker receives equivalent tokens on NEAR.
- In both cases the victim suffers a permanent, irreversible loss of their SPL tokens with no recourse.

This is a direct theft of bridged funds — Critical impact under the scope.

---

### Likelihood Explanation

SPL token delegations are a standard, widely-used mechanism (DEX approvals, lending protocols, etc.). A victim who has ever approved any program or wallet as a delegate — even for a completely unrelated purpose — is vulnerable if the attacker controls that delegate key. The attacker does not need to compromise any key; they only need to be the holder of a pre-existing delegation. The attack is fully on-chain, requires no privileged access, and is locally reproducible with Bankrun or Mollusk.

---

### Recommendation

Add `token::authority = user` to the `from` account constraint:

```rust
#[account(
    mut,
    token::mint = mint,
    token::token_program = token_program,
    token::authority = user,          // <-- add this
)]
pub from: Box<InterfaceAccount<'info, TokenAccount>>,
``` [1](#0-0) 

This causes Anchor to enforce `from.owner == user.key()` at account-validation time, before any CPI is attempted, closing the delegation-drain path entirely.

---

### Proof of Concept

```rust
// Bankrun / Anchor test sketch
// 1. Mint tokens to victim_ata (owner = victim)
// 2. victim calls spl_token::approve(victim_ata, delegate=attacker, amount=X)
// 3. attacker calls init_transfer with:
//      from    = victim_ata
//      user    = attacker  (signer)
//      payload.recipient = "attacker.near"
// 4. Assert: victim_ata.amount decreased by X
// 5. Assert: vault.amount increased by X  (or mint supply decreased for bridged)
// 6. Assert: Wormhole message sender == attacker.pubkey, recipient == "attacker.near"
```

The SPL Token CPI at line 90–102 will succeed because `attacker` is a valid delegate of `victim_ata`. No guard in `InitTransfer::process` checks `from.owner == user.key()`. [5](#0-4)

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

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L71-130)
```rust
impl InitTransfer<'_> {
    pub fn process(&self, payload: &InitTransferPayload) -> Result<()> {
        require!(payload.amount > payload.fee, ErrorCode::InvalidFee);

        if payload.native_fee > 0 {
            transfer(
                CpiContext::new(
                    self.common.system_program.to_account_info(),
                    Transfer {
                        from: self.user.to_account_info(),
                        to: self.sol_vault.to_account_info(),
                    },
                ),
                payload.native_fee,
            )?;
        }

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
        } else {
            // Bridged version. May be a fake token with our authority set but it will be ignored on the near side
            require!(
                self.mint.mint_authority.contains(self.authority.key),
                ErrorCode::InvalidBridgedToken
            );

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
        }

        self.common.post_message(payload.serialize_for_near((
            self.common.sequence.sequence,
            self.user.key(),
            self.mint.key(),
        ))?)?;

        Ok(())
    }
```
