Audit Report

## Title
Token-2022 Transfer Fee Extension Causes Vault Under-Crediting vs. Cross-Chain Message Amount — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

## Summary

`InitTransfer::process` calls `transfer_checked` with `payload.amount` and then posts a Wormhole message encoding that same `payload.amount` unmodified. When the mint carries a Token-2022 `TransferFeeConfig` extension, `transfer_checked` credits the vault with only `amount - withheld_fee`, while the cross-chain message reports the full `amount`. NEAR finalizes a release for `amount`, permanently over-releasing assets relative to what is actually locked in the Solana vault.

## Finding Description

In `InitTransfer::process`, the native-token branch calls `transfer_checked` with `payload.amount`: [1](#0-0) 

Under Token-2022's `TransferFeeConfig` extension, `transfer_checked` debits the sender by `amount` but credits the vault by only `amount - withheld_fee`; the withheld portion is recorded inside the vault's token account as fee-authority-owned, inaccessible to the bridge authority. No code reads back the actual post-transfer vault balance. Immediately after, the Wormhole message is posted with the unmodified `payload`: [2](#0-1) 

The serializer encodes `self.amount` directly without any fee deduction: [3](#0-2) 

The vault is registered permissionlessly via `log_metadata`, which unpacks the mint with `StateWithExtensions` but only inspects `MetadataPointer` and `TokenMetadata` extensions: [4](#0-3) 

`get_extension::<TransferFeeConfig>()` is never called; mints carrying a transfer fee extension are accepted and a vault PDA is created for them: [5](#0-4) 

`SECURITY.md` acknowledges transfer hooks as a known non-issue (runtime denial, not fund loss) but makes no mention of transfer fees, which succeed silently: [6](#0-5) 

## Impact Explanation

This is a Critical escrow mis-accounting / fund-loss vulnerability. For every `init_transfer` on a mint with a transfer fee at rate `f` bps:

- Vault receives: `amount × (1 − f/10000)`
- Wormhole message claims: `amount`
- NEAR releases: `amount`
- Protocol loss per transfer: `amount × f/10000`

Repeated transfers drain the NEAR-side escrow relative to the Solana vault. An attacker can extract more assets from NEAR than were ever deposited on Solana, matching the allowed impact class: *"Stealing, loss of bridged funds"* and *"escrow mis-accounting, fee mis-accounting that changes user or protocol balances."*

## Likelihood Explanation

The attack is fully permissionless and requires no admin access, key compromise, or external collusion:

1. Create a Token-2022 mint with `TransferFeeConfig` (standard, permissionless Solana operation).
2. Call `log_metadata` to register the vault — succeeds with no fee-extension check.
3. Call `init_transfer` repeatedly with any amount.

The exploit is locally testable, repeatable, and self-contained. The only precondition is the ability to create a Token-2022 mint, which any Solana account can do.

## Recommendation

**Option A (preferred):** In `InitTransfer::process`, after `transfer_checked`, read back the vault's actual post-transfer token balance (or compute the withheld fee via `TransferFeeConfig::calculate_epoch_fee`) and use the net received amount in the Wormhole message instead of `payload.amount`.

**Option B:** In `log_metadata::process`, after unpacking the mint with `StateWithExtensions`, call `get_extension::<TransferFeeConfig>()` and return an error if the extension is present, preventing fee-bearing mints from being registered as native vault tokens.

## Proof of Concept

1. On localnet, create a Token-2022 mint with `TransferFeeConfig` at 1000 bps (10%).
2. Call `log_metadata` — succeeds, vault PDA created.
3. Call `init_transfer` with `amount = 1_000_000`.
4. Assert `vault.amount == 900_000` (actual credited) vs. Wormhole payload `amount == 1_000_000` (reported).
5. On the NEAR side, finalize the transfer — NEAR releases `1_000_000` units while only `900_000` are locked in the Solana vault.
6. Repeat to drain the NEAR escrow by 10% per round-trip.

### Citations

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

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L50-62)
```rust
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

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L95-114)
```rust
            let mint_with_extension =
                StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;

            if let Ok(metadata_pointer) = mint_with_extension.get_extension::<MetadataPointer>() {
                if metadata_pointer.metadata_address.0 == self.mint.key() {
                    // Embedded metadata
                    let metadata =
                        mint_with_extension.get_variable_len_extension::<TokenMetadata>()?;
                    (metadata.name, metadata.symbol)
                } else if metadata_pointer.metadata_address.0 != Pubkey::default() {
                    // Third-party metadata
                    self.parse_metadata_account(metadata_pointer.metadata_address.0)?
                } else {
                    // No metadata
                    (String::default(), String::default())
                }
            } else {
                // No metadata pointer extension found
                (String::default(), String::default())
            }
```

**File:** solana/SECURITY.md (L19-19)
```markdown
- **Token-2022 tokens with transfer hooks are not supported** — Transfer hook extra account metas are not included in instruction account sets. Affected tokens will fail at runtime (denial, not fund loss).
```
