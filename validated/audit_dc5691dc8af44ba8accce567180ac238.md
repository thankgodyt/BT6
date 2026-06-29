Audit Report

## Title
Token-2022 Transfer Fee Extension Causes Vault Under-Crediting vs. Cross-Chain Message Over-Reporting — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

## Summary

In `InitTransfer::process`, the native-token path calls `transfer_checked` with `payload.amount` and then posts a Wormhole message encoding that same `payload.amount`. When the mint has a Token-2022 `TransferFeeConfig` extension, the vault receives only `amount - withheld_fee` as spendable balance while the cross-chain message reports the full `amount`. NEAR finalizes the transfer for the full reported amount, permanently over-releasing assets from its escrow relative to what is locked on Solana.

## Finding Description

In `InitTransfer::process`, the native-token path executes `transfer_checked` with the caller-supplied `payload.amount`: [1](#0-0) 

Immediately after, the Wormhole message is posted with the same unmodified `payload.amount`: [2](#0-1) 

The serialized message encodes `self.amount` directly without any post-transfer balance delta check: [3](#0-2) 

Under Token-2022's `TransferFeeConfig` extension, `transfer_checked(amount)` debits the sender by `amount` but credits the recipient (vault) only `amount - withheld_fee`. The withheld fee is stored as `withheld_amount` in the vault's token account extension data — it is not part of the vault's spendable balance and cannot be used to fulfill future `finalize_transfer` withdrawals.

The mint account constraint in `InitTransfer` only validates `token_program` consistency, with no check for a `TransferFeeConfig` extension: [4](#0-3) 

The `log_metadata` instruction, which creates the vault PDA and registers the mint, also performs no check for a transfer fee extension: [5](#0-4) 

`SECURITY.md` acknowledges transfer hooks as a known denial-only issue but makes no mention of transfer fees, which are a distinct extension with fundamentally different behavior (silent success with recipient under-crediting, not runtime failure): [6](#0-5) 

## Impact Explanation

For every `init_transfer` involving a Token-2022 mint with a transfer fee of `F` basis points, the Solana vault receives `amount × (1 - F/10000)` spendable tokens while NEAR releases `amount` tokens to the recipient. The difference `amount × F/10000` is permanently over-released from NEAR's escrow per transfer. This is a direct, quantifiable, and repeatable escrow mis-accounting — matching the Critical allowed impact: "Balance manipulation, escrow mis-accounting, fee mis-accounting... that changes user or protocol balances."

## Likelihood Explanation

The attack is fully permissionless. Any unprivileged user can: (1) create a Token-2022 mint with `TransferFeeConfig` set to any basis-point value, (2) call `log_metadata` to register it and create the vault PDA (no role check, no extension validation), and (3) call `init_transfer` with that mint. No admin compromise, key leakage, oracle manipulation, or victim mistake is required. The attack is repeatable indefinitely, draining NEAR-side escrow at a rate proportional to the configured fee per transfer.

## Recommendation

In `InitTransfer::process` (native vault path), after `transfer_checked` completes, read the vault's actual post-transfer spendable balance and use the delta (balance after − balance before) as the amount encoded in the Wormhole message, rather than the caller-supplied `payload.amount`. Alternatively, reject mints that have a `TransferFeeConfig` extension by unpacking the mint's extension state in both `log_metadata` and `init_transfer` and returning an error if the extension is present — consistent with how the program already rejects unsupported configurations. The `log_metadata` instruction already unpacks mint extension state for `MetadataPointer` and can be extended to check for `TransferFeeConfig` at the same point. [7](#0-6) 

## Proof of Concept

1. On localnet, create a Token-2022 mint with `TransferFeeConfig` set to 1000 basis points (10%) and mint 10,000 tokens to a test user.
2. Call `log_metadata` with that mint to register it and create the vault PDA.
3. Call `init_transfer` with `amount = 1000`, `fee = 0`, `native_fee = 0`.
4. Read the vault's token account `amount` field after the instruction — it will be 900 (not 1000), because 100 tokens are withheld as `withheld_amount` in the vault's `TransferFeeAmount` extension.
5. Observe the Wormhole message payload encodes `amount = 1000`.
6. The invariant `vault_spendable_delta == message_amount` is violated by exactly the withheld fee (100 tokens).
7. On the NEAR side, finalizing this transfer releases 1000 units of the bridged asset while only 900 are locked and available for future redemption — a permanent 100-token deficit per transfer.

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L28-32)
```rust
    #[account(
        mut,
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
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

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L123-127)
```rust
        self.common.post_message(payload.serialize_for_near((
            self.common.sequence.sequence,
            self.user.key(),
            self.mint.key(),
        ))?)?;
```

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L31-32)
```rust
        // 4. amount
        self.amount.serialize(&mut writer)?;
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L41-45)
```rust
    #[account(
        constraint = !mint.mint_authority.contains(authority.key),
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L95-98)
```rust
            let mint_with_extension =
                StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;

            if let Ok(metadata_pointer) = mint_with_extension.get_extension::<MetadataPointer>() {
```

**File:** solana/SECURITY.md (L19-19)
```markdown
- **Token-2022 tokens with transfer hooks are not supported** — Transfer hook extra account metas are not included in instruction account sets. Affected tokens will fail at runtime (denial, not fund loss).
```
