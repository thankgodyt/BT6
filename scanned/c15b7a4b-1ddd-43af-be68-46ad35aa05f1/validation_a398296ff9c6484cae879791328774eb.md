### Title
Token-2022 Transfer Fee Extension Causes Vault Under-Crediting vs. Cross-Chain Message Amount — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

---

### Summary

`log_metadata` creates a vault PDA for any native Token-2022 mint without checking for the transfer fee extension. When `init_transfer` subsequently calls `transfer_checked` with `payload.amount`, the Token-2022 runtime withholds the fee from the vault's spendable balance, but the Wormhole message still reports the full `payload.amount`. NEAR releases the full amount, while the Solana vault holds less. The fee authority (the attacker) can then harvest the withheld tokens back, completing a double-spend.

---

### Finding Description

**Step 1 — Vault creation with no transfer-fee guard (`log_metadata.rs`)**

`LogMetadata::process` initializes the vault PDA with `init_if_needed` for any mint whose `mint_authority` is not the bridge authority. There is no inspection of Token-2022 extensions: [1](#0-0) 

No call to `get_extension::<TransferFeeConfig>()` or similar guard exists anywhere in this path.

**Step 2 — `init_transfer` posts the caller-supplied amount verbatim**

In the native-token branch, `transfer_checked` is called with `payload.amount`: [2](#0-1) 

With a Token-2022 transfer-fee mint, the Token-2022 runtime deducts the fee from the destination (vault) and stores it as *withheld* balance. The vault's spendable `amount` field becomes `payload.amount − fee`, but no post-transfer balance check is performed.

**Step 3 — Wormhole message carries the unmodified `payload.amount`** [3](#0-2) 

The serialized payload encodes `self.amount` directly: [4](#0-3) 

**Step 4 — Fee authority harvests withheld tokens**

Token-2022 allows the fee authority (the attacker, who created the mint) to call `harvest_withheld_tokens_to_mint` + `withdraw_withheld_tokens_from_mint` on the vault account, extracting the withheld portion back to themselves on Solana.

---

### Impact Explanation

For each `init_transfer` with a fee-bearing mint:

| Side | Tokens |
|---|---|
| Vault spendable balance increase | `amount × (1 − fee_rate)` |
| Wormhole message / NEAR release | `amount` |
| Attacker recovers via harvest | `amount × fee_rate` |

The invariant **vault_balance_increase = cross_chain_amount** is broken. Over repeated transfers the vault is drained relative to NEAR's accounting. With a 10% fee and 1000-token transfer: NEAR releases 1000, vault gains only 900 spendable, attacker harvests 100 — net theft of 10% per transfer, unbounded by repetition.

This is a **Critical** escrow mis-accounting / balance manipulation impact.

---

### Likelihood Explanation

- Creating a Token-2022 mint with a transfer fee is permissionless and costs only rent.
- `log_metadata` is a public, permissionless instruction — no admin approval required.
- `init_transfer` is the standard user-facing bridge entry point.
- The attacker controls the fee authority at mint creation time.
- No existing guard in `log_metadata`, `init_transfer`, or the `InitTransfer` account constraints rejects fee-bearing mints.

Likelihood: **High** — fully permissionless, no privileged access required.

---

### Recommendation

1. **In `log_metadata`**: After unpacking the Token-2022 mint extensions, reject any mint that has a `TransferFeeConfig` extension with a non-zero fee, or a `TransferHook` extension pointing to a non-null program:

```rust
// In log_metadata.rs, after unpacking mint_with_extension:
if mint_with_extension.get_extension::<TransferFeeConfig>().is_ok() {
    return err!(ErrorCode::UnsupportedMintExtension);
}
if mint_with_extension.get_extension::<TransferHook>().is_ok() {
    return err!(ErrorCode::UnsupportedMintExtension);
}
```

2. **In `init_transfer`** (defense-in-depth): After `transfer_checked`, read the vault's post-transfer spendable balance and use that as the amount encoded in the Wormhole message, rather than the caller-supplied `payload.amount`.

3. Apply the same guards to `finalize_transfer` — a fee-bearing vault-to-recipient transfer would similarly under-deliver to the recipient while the message claims the full amount.

---

### Proof of Concept

```rust
// localnet test outline
// 1. Create Token-2022 mint with 10% transfer fee; attacker is fee_authority
let mint = create_token_2022_mint_with_fee(fee_authority, 1000 /* 10% in basis points */);

// 2. Register as native token (creates vault PDA) — permissionless
log_metadata(mint);

// 3. Attacker holds 1000 tokens; calls init_transfer
init_transfer(amount = 1000, recipient = attacker_near_address);

// 4. Assert: vault.amount == 900  (fee withheld 100)
// 5. Assert: wormhole_message.amount == 1000  (full amount posted)
// 6. NEAR finalizes: releases 1000 tokens to attacker on NEAR
// 7. Attacker calls harvest_withheld_tokens_to_mint + withdraw on vault
//    → recovers 100 tokens on Solana
// Net: attacker spent 1000 Solana tokens, received 1000 NEAR tokens + 100 Solana tokens back
//      Protocol escrow is short 100 tokens per round-trip
```

Fuzz vector: vary `transfer_fee_basis_points` from 1 to 10000; assert `vault.amount_after − vault.amount_before == wormhole_payload.amount` — this assertion will fail for any non-zero fee.

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L41-63)
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

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L123-127)
```rust
        self.common.post_message(payload.serialize_for_near((
            self.common.sequence.sequence,
            self.user.key(),
            self.mint.key(),
        ))?)?;
```

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L32-32)
```rust
        self.amount.serialize(&mut writer)?;
```
