### Title
Token-2022 TransferFee Extension Causes Vault Undercollateralization in Solana `init_transfer` — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

---

### Summary

The Solana bridge program explicitly supports Token-2022 via `token_interface` and `token_2022` CPIs. When a native Token-2022 token with the **TransferFee extension** is registered (permissionlessly via `log_metadata`) and then bridged via `init_transfer`, the vault receives `payload.amount - withheld_fee` tokens, but the Wormhole message reports the full `payload.amount`. NEAR mints the full amount. The vault becomes progressively undercollateralized, and later users bridging back to Solana cannot withdraw their full balances.

---

### Finding Description

`init_transfer` handles native (non-bridged) tokens by calling `transfer_checked` from the `token_2022` module: [1](#0-0) 

`transfer_checked` on a Token-2022 mint with the **TransferFee** extension withholds a fee from the destination. The vault (destination) receives `payload.amount - fee`, while the source account loses exactly `payload.amount`. The fee is stored as withheld balance inside the vault's token account data and is claimable only by the fee authority — not by the bridge.

Immediately after the transfer, the program posts a Wormhole message containing the full `payload.amount`: [2](#0-1) 

NEAR reads this VAA and mints `payload.amount` tokens to the recipient. The bridge is now undercollateralized by the withheld fee for every such transfer.

Token registration is permissionless: any caller can invoke `log_metadata`, which creates the vault PDA for any mint whose `mint_authority` is not the bridge authority: [3](#0-2) 

The program explicitly accepts both classic SPL Token and Token-2022 via `TokenInterface`: [4](#0-3) 

The `solana/SECURITY.md` acknowledges that **transfer hooks** are unsupported (causing runtime failure), but says nothing about the **TransferFee extension**, which succeeds silently while corrupting accounting: [5](#0-4) 

The EVM `SECURITY.md` explicitly documents fee-on-transfer tokens as unsupported for EVM, but no equivalent statement exists for Solana: [6](#0-5) 

---

### Impact Explanation

**Critical — balance manipulation / escrow mis-accounting causing permanent loss of bridged funds.**

For every `init_transfer` of a Token-2022 token with TransferFee:
- Vault receives `amount - fee`
- NEAR mints `amount`
- Deficit accumulates with each transfer

When users bridge back (NEAR → Solana), `finalize_transfer` calls `transfer_checked` from the vault for the full signed amount: [7](#0-6) 

Once the vault's spendable balance is exhausted, `finalize_transfer` reverts. The last users to withdraw lose their bridged tokens permanently. The withheld fee balance in the vault is inaccessible to the bridge (only the token's fee authority can harvest it).

---

### Likelihood Explanation

**Medium-High.** Token-2022 with TransferFee is a production-grade, widely deployed Solana extension (e.g., used by several DeFi protocols). The program explicitly targets Token-2022 compatibility. `log_metadata` is permissionless — any user can register any qualifying mint. No admin action or special privilege is required to trigger the vulnerability. The deficit is small per transfer but compounds linearly and is irreversible.

---

### Recommendation

1. **Short term**: In `init_transfer`, after calling `transfer_checked`, read the vault's post-transfer balance and use the actual received amount (not `payload.amount`) in the Wormhole message. Alternatively, reject Token-2022 mints that have the TransferFee extension enabled by inspecting mint extensions in `log_metadata`.

2. **Long term**: Add a check in `log_metadata` that enumerates Token-2022 extensions on the mint and rejects any mint with extensions that alter transfer semantics (TransferFee, ConfidentialTransfer, etc.), consistent with the existing rejection of transfer hooks.

---

### Proof of Concept

1. Deploy a Token-2022 mint on Solana with `TransferFeeConfig` set to 1% fee.
2. Call `log_metadata` (permissionless) — vault PDA is created for the mint.
3. User A calls `init_transfer` with `payload.amount = 1_000_000`. `transfer_checked` deposits `990_000` into the vault (10_000 withheld). Wormhole message reports `1_000_000`. NEAR mints `1_000_000` tokens to User A.
4. Repeat for 100 users. Vault holds `99_000_000` spendable tokens; NEAR has minted `100_000_000`.
5. First 99 users bridge back successfully (each `finalize_transfer` of `1_000_000` succeeds until vault is drained).
6. User 100's `finalize_transfer` reverts — vault has `0` spendable balance. User 100 loses `1_000_000` bridged tokens permanently.

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L1-8)
```rust
use anchor_lang::{
    prelude::*,
    system_program::{transfer, Transfer},
};
use anchor_spl::{
    token_2022::{burn, transfer_checked, Burn, TransferChecked},
    token_interface::{Mint, TokenAccount, TokenInterface},
};
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

**File:** solana/SECURITY.md (L19-19)
```markdown
- **Token-2022 tokens with transfer hooks are not supported** — Transfer hook extra account metas are not included in instruction account sets. Affected tokens will fail at runtime (denial, not fund loss).
```

**File:** evm/SECURITY.md (L7-7)
```markdown
- **Fee-on-transfer tokens not supported**: `initTransfer` emits the requested `amount`, not the actual received balance. Fee-on-transfer and rebasing tokens are intentionally unsupported
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
