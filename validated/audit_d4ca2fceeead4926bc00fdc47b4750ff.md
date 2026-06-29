Audit Report

## Title
Token-2022 TransferFee Extension Causes Vault Undercollateralization via Unreported Fee Withholding — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

## Summary

`init_transfer` calls `transfer_checked` on Token-2022 mints, which silently withholds a fee from the vault (destination) when the TransferFee extension is active. The Wormhole message is posted with the full `payload.amount`, causing NEAR to mint more tokens than the vault holds. The deficit compounds with every transfer, eventually causing `finalize_transfer` to revert and permanently stranding the last users' funds.

## Finding Description

In `init_transfer`, when a vault exists (native token path), the program calls `transfer_checked` with the full `payload.amount`: [1](#0-0) 

For a Token-2022 mint with the TransferFee extension, `transfer_checked` withholds a fee from the destination (vault). The vault receives `payload.amount - withheld_fee`; the source loses exactly `payload.amount`. The withheld balance is stored inside the vault's token account data and is only claimable by the token's fee authority — not by the bridge program.

Immediately after, the program posts a Wormhole message containing the unmodified `payload`: [2](#0-1) 

NEAR reads the VAA and mints the full `payload.amount`. The vault is now short by `withheld_fee` per transfer.

Token registration via `log_metadata` is permissionless and performs no check for the TransferFee extension — any mint whose `mint_authority` is not the bridge authority can be registered: [3](#0-2) 

The only extension-related guard in `log_metadata` is implicit: it reads metadata extensions but never inspects TransferFeeConfig. No rejection path exists for mints with fee-altering extensions.

When users bridge back (NEAR → Solana), `finalize_transfer` calls `transfer_checked` from the vault for the full signed amount: [4](#0-3) 

Once the vault's spendable balance is exhausted (which happens before all NEAR-minted tokens are redeemed), `finalize_transfer` reverts. The remaining users cannot withdraw their bridged tokens.

`solana/SECURITY.md` acknowledges only transfer hooks as unsupported (causing runtime denial, not fund loss), with no mention of TransferFee: [5](#0-4) 

The EVM counterpart explicitly documents fee-on-transfer tokens as unsupported, but no equivalent statement exists for Solana: [6](#0-5) 

## Impact Explanation

This is a **Critical** impact matching the allowed scope: *"Balance manipulation, escrow mis-accounting, fee mis-accounting... that changes user or protocol balances."* The vault is permanently undercollateralized by the cumulative withheld fees. The withheld balance is inaccessible to the bridge (only the token's fee authority can harvest it). The last users to bridge back lose their funds permanently with no recovery path.

## Likelihood Explanation

Token-2022 with TransferFee is a production-grade, widely deployed extension used by multiple DeFi protocols on Solana mainnet. `log_metadata` is fully permissionless — any external user can register any qualifying mint without admin involvement. No special privilege, victim mistake, or external collusion is required. The deficit is small per transfer but accumulates linearly and is irreversible. The program explicitly targets Token-2022 compatibility via `TokenInterface` and `token_2022` CPIs, making this a realistic attack surface.

## Recommendation

**Short term:** In `init_transfer`, after calling `transfer_checked`, read the vault's post-transfer token balance and use the actual received amount (not `payload.amount`) in the Wormhole message. This requires a reload of the vault account after the CPI.

**Long term:** In `log_metadata`, when `token_program.key() == token_2022::ID`, unpack the mint extensions and reject any mint that has `TransferFeeConfig`, `ConfidentialTransfer`, or other extensions that alter transfer semantics. This is consistent with the existing implicit rejection of transfer-hook mints (which fail at runtime) but makes the rejection explicit and prevents silent accounting corruption.

## Proof of Concept

1. Deploy a Token-2022 mint on Solana devnet/localnet with `TransferFeeConfig` set to 1% fee.
2. Call `log_metadata` (permissionless) — vault PDA is created for the mint with no extension check.
3. User A calls `init_transfer` with `payload.amount = 1_000_000`. `transfer_checked` deposits `990_000` into the vault (10_000 withheld by the fee extension). Wormhole message reports `1_000_000`. NEAR mints `1_000_000` tokens to User A.
4. Repeat for 100 users. Vault holds `99_000_000` spendable tokens; NEAR has minted `100_000_000`.
5. First 99 users bridge back: each `finalize_transfer` of `1_000_000` succeeds until vault spendable balance reaches `0`.
6. User 100's `finalize_transfer` reverts — vault has `0` spendable balance (10_000 × 100 = 1_000_000 is withheld and inaccessible). User 100 permanently loses `1_000_000` bridged tokens.

A localnet integration test can reproduce this by: deploying a Token-2022 mint with `TransferFeeConfig`, calling `log_metadata`, executing 100 `init_transfer` calls, then asserting that the 100th `finalize_transfer` fails with an insufficient-funds error while the vault's withheld balance equals the total deficit.

### Citations

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

**File:** evm/SECURITY.md (L7-7)
```markdown
- **Fee-on-transfer tokens not supported**: `initTransfer` emits the requested `amount`, not the actual received balance. Fee-on-transfer and rebasing tokens are intentionally unsupported
```
