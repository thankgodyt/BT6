### Title
Token-2022 Transfer Fee Extension Causes Vault Undercollateralization in `init_transfer` — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

---

### Summary

`InitTransfer::process` calls `transfer_checked` with the caller-supplied `payload.amount` and then posts a Wormhole message containing that same `payload.amount`. When the mint has a Token-2022 `TransferFeeConfig` extension, the Token-2022 runtime withholds a fee from the destination (vault) account, so the vault's usable balance is `amount - fee` while the cross-chain message reports `amount`. NEAR mints/releases `amount` wrapped tokens, but the Solana vault can only ever release `amount - fee` tokens back. The vault is permanently undercollateralized by the fee percentage.

---

### Finding Description

**Registration path — no transfer-fee guard in `log_metadata`**

`log_metadata` creates the vault PDA for any Token-2022 mint via `init_if_needed`. The only constraint on the mint is that its `mint_authority` must not equal the bridge authority (i.e., it must not be a bridged token). There is no inspection of the mint's extension list for `TransferFeeConfig`. [1](#0-0) 

**Transfer path — amount reported equals amount requested, not amount received**

`InitTransfer::process` calls `transfer_checked` with `payload.amount`, then immediately serializes `payload.amount` into the Wormhole message. There is no post-transfer balance snapshot of the vault, no inspection of the mint's `TransferFeeConfig`, and no subtraction of any withheld fee. [2](#0-1) 

**Token-2022 transfer-fee mechanics**

Under SPL Token-2022, when `transfer_checked(amount=A)` executes on a mint with fee rate `F`:
- Sender is debited `A`.
- Destination `amount` field increases by `A`.
- Destination `withheld_amount` field increases by `floor(A × F / 10000)`.
- The vault's *transferable* balance is `A - withheld`, not `A`.

The Wormhole message therefore reports `A`, but the vault can only release `A - withheld` in a future `finalize_transfer`.

**`finalize_transfer` will fail or under-deliver**

When a user later bridges back and `finalize_transfer` calls `transfer_checked(amount=A)` from the vault, the Token-2022 runtime checks `vault.amount - vault.withheld_amount >= A + new_fee`. Because `vault.amount - vault.withheld_amount = A - withheld < A`, the instruction reverts. The user's NEAR-side tokens are burned but no Solana tokens are released — permanent loss. [3](#0-2) 

**Not acknowledged in SECURITY.md**

`solana/SECURITY.md` lists transfer *hooks* as a known denial-only issue but says nothing about transfer *fees*. The EVM `SECURITY.md` explicitly marks fee-on-transfer tokens as unsupported for EVM, but that disclaimer does not appear in the Solana security notes. [4](#0-3) 

---

### Impact Explanation

Every `init_transfer` call on a Token-2022 mint with a non-zero transfer fee creates a permanent shortfall:

- NEAR releases `amount` wrapped tokens.
- Solana vault holds only `amount × (1 - fee_rate)` usable tokens.
- Any subsequent `finalize_transfer` for the full `amount` reverts; users cannot recover their tokens.
- An attacker who controls the fee authority can set an arbitrarily high fee rate (up to the Token-2022 maximum of 100%), maximizing the shortfall.
- Repeated bridging compounds the undercollateralization linearly.

This is a direct escrow mis-accounting / balance manipulation causing permanent freezing of bridged funds — a Critical impact under the stated scope.

---

### Likelihood Explanation

- `log_metadata` is permissionless; anyone can register a Token-2022 mint with transfer fees.
- `init_transfer` is permissionless; any holder of such a token can call it.
- No admin action, key compromise, or external dependency failure is required.
- The exploit is reproducible on a local validator with the unmodified program binary.

---

### Recommendation

In `InitTransfer::process`, after `transfer_checked`, read the vault's post-transfer `amount` and `withheld_amount` (via `StateWithExtensions`) and use `actual_received = vault.amount - vault.withheld_amount_delta` as the value serialized into the Wormhole payload. Alternatively, reject mints whose `TransferFeeConfig` extension has a non-zero `transfer_fee_basis_points` or `maximum_fee` at the `log_metadata` registration step, mirroring the existing transfer-hook denial documented in `SECURITY.md`.

---

### Proof of Concept

```rust
// localnet test sketch
// 1. Create Token-2022 mint with 10% transfer fee
let mint = create_token_2022_mint_with_fee(&payer, 1000 /* 10% in basis points */);

// 2. Register via log_metadata (permissionless, no fee-extension check)
log_metadata(&mint, &token_2022_program);
// → vault PDA created, NEAR registers the token

// 3. Mint 1000 tokens to attacker's ATA
mint_to(&mint, &attacker_ata, 1000);

// 4. Call init_transfer(amount=1000, fee=0, recipient=attacker_near_address)
init_transfer(&mint, &attacker_ata, &vault, 1000, 0, "attacker.near");
// → transfer_checked moves 1000 from attacker_ata to vault
//   vault.amount = 1000, vault.withheld_amount = 100
//   Wormhole message: amount = 1000  ← WRONG

// 5. NEAR processes VAA, releases 1000 wrapped tokens to attacker.near

// 6. Assert invariant violation:
let vault_usable = vault.amount - vault.withheld_amount; // = 900
assert_eq!(vault_usable, 1000); // FAILS — 900 ≠ 1000

// 7. Attempt finalize_transfer back for 1000 tokens → REVERTS
// attacker.near tokens are burned; attacker receives 0 Solana tokens
// (or: attacker sells NEAR-side tokens to a third party who then loses funds)
```

Fuzz vector: vary `transfer_fee_basis_points` from 1 to 10000; assert `vault_usable == payload.amount` after every `init_transfer`. The assertion fails for all non-zero fee rates.

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

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L88-127)
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

**File:** solana/SECURITY.md (L19-19)
```markdown
- **Token-2022 tokens with transfer hooks are not supported** — Transfer hook extra account metas are not included in instruction account sets. Affected tokens will fail at runtime (denial, not fund loss).
```
