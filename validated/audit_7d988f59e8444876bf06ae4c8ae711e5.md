Audit Report

## Title
Token-2022 Transfer Fee Extension Causes Vault Under-Crediting vs. Cross-Chain Message Amount — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

## Summary

`log_metadata` creates a vault PDA for any Token-2022 mint without inspecting the `TransferFeeConfig` extension. When `init_transfer` subsequently calls `transfer_checked` with `payload.amount`, the Token-2022 runtime withholds the fee from the vault's spendable balance, but the Wormhole message encodes the full `payload.amount`. NEAR releases the full amount while the Solana vault holds less, and the fee authority (the attacker who created the mint) can harvest the withheld tokens back — completing a net theft of `fee_rate × amount` per transfer, unbounded by repetition.

## Finding Description

**Step 1 — Vault creation with no transfer-fee guard (`log_metadata.rs` L41–62)**

`LogMetadata` initializes the vault PDA via `init_if_needed` for any mint whose `mint_authority` is not the bridge authority. The only constraint on the mint is:

```rust
constraint = !mint.mint_authority.contains(authority.key),
```

No call to `get_extension::<TransferFeeConfig>()` or any equivalent guard exists. The `process` function unpacks `StateWithExtensions` only to read `MetadataPointer` and `TokenMetadata`; it never inspects fee-related extensions. An attacker-created Token-2022 mint with a `TransferFeeConfig` extension passes all constraints and gets a vault PDA registered.

**Step 2 — `init_transfer` posts the caller-supplied amount verbatim (`init_transfer.rs` L88–127)**

In the native-token branch, `transfer_checked` is called with `payload.amount`:

```rust
transfer_checked(
    CpiContext::new(..., TransferChecked { from, to: vault, authority, mint }),
    payload.amount.try_into()...?,
    self.mint.decimals,
)?;
```

With a Token-2022 transfer-fee mint, the Token-2022 runtime deducts the fee from the destination (vault) and stores it as *withheld* balance. The vault's spendable `amount` field becomes `payload.amount − fee`, but no post-transfer balance check is performed. Immediately after, the Wormhole message is posted with the unmodified `payload.amount`:

```rust
self.common.post_message(payload.serialize_for_near((
    self.common.sequence.sequence,
    self.user.key(),
    self.mint.key(),
))?)?;
```

And `serialize_for_near` encodes `self.amount` directly:

```rust
self.amount.serialize(&mut writer)?;
```

**Step 3 — Fee authority harvests withheld tokens**

Token-2022 allows the fee authority (the attacker, who created the mint) to call `harvest_withheld_tokens_to_mint` on the vault account, moving the withheld portion to the mint's withheld balance, then `withdraw_withheld_tokens_from_mint` to extract it to any account. This is a standard Token-2022 CPI available to any holder of the fee authority keypair.

**Why existing checks are insufficient**

`solana/SECURITY.md` line 19 acknowledges that Token-2022 tokens with *transfer hooks* are not supported and will fail at runtime. Transfer fees are a distinct extension — they do **not** cause a runtime failure; they silently withhold tokens at the destination. No guard in `log_metadata`, `init_transfer`, or the `InitTransfer` account constraints rejects fee-bearing mints.

## Impact Explanation

This is a **Critical** escrow mis-accounting / balance manipulation impact, matching the allowed scope: *"Balance manipulation, escrow mis-accounting, fee mis-accounting… that changes user or protocol balances."*

| Side | Tokens |
|---|---|
| Vault spendable balance increase | `amount × (1 − fee_rate)` |
| Wormhole message / NEAR release | `amount` |
| Attacker recovers via harvest | `amount × fee_rate` |

The invariant `vault_balance_increase = cross_chain_amount` is broken. With a 10% fee and 1000-token transfer: NEAR releases 1000, vault gains only 900 spendable, attacker harvests 100. Net theft of 10% per transfer, repeatable without limit, draining the vault relative to NEAR's accounting.

## Likelihood Explanation

- Creating a Token-2022 mint with a transfer fee is permissionless and costs only rent.
- `log_metadata` is a public, permissionless instruction — no admin approval required.
- `init_transfer` is the standard user-facing bridge entry point.
- The attacker controls the fee authority at mint creation time.
- No existing guard in `log_metadata`, `init_transfer`, or the `InitTransfer` account constraints rejects fee-bearing mints.
- The SECURITY.md explicitly acknowledges transfer hooks as a known non-issue (runtime failure/denial), but makes no mention of transfer fees, confirming the gap is unaddressed.

Likelihood: **High** — fully permissionless, no privileged access required, repeatable.

## Recommendation

1. **In `log_metadata`**: After unpacking `StateWithExtensions`, reject any mint that has a `TransferFeeConfig` extension with a non-zero fee:

```rust
use spl_token_2022::extension::transfer_fee::TransferFeeConfig;

if mint_with_extension.get_extension::<TransferFeeConfig>().is_ok() {
    return err!(ErrorCode::UnsupportedMintExtension);
}
```

2. **In `init_transfer`** (defense-in-depth): After `transfer_checked`, read the vault's post-transfer spendable balance and use that as the amount encoded in the Wormhole message, rather than the caller-supplied `payload.amount`.

3. Apply the same guard to `finalize_transfer` — a fee-bearing vault-to-recipient transfer would similarly under-deliver to the recipient while the message claims the full amount.

## Proof of Concept

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
// 7. Attacker calls harvest_withheld_tokens_to_mint + withdraw_withheld_tokens_from_mint on vault
//    → recovers 100 tokens on Solana
// Net: attacker spent 1000 Solana tokens, received 1000 NEAR tokens + 100 Solana tokens back
//      Protocol escrow is short 100 tokens per round-trip

// Fuzz vector: vary transfer_fee_basis_points from 1 to 10000;
// assert vault.amount_after − vault.amount_before == wormhole_payload.amount
// This assertion will fail for any non-zero fee.
```