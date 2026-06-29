Audit Report

## Title
Token-2022 Transfer Fee Causes Vault Under-Collateralization on Solana, Enabling NEAR Over-Minting — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

## Summary

The `init_transfer` instruction locks tokens in a vault via `transfer_checked(payload.amount)` and then posts a Wormhole message carrying the same `payload.amount`. For Token-2022 mints with the transfer fee extension enabled, `transfer_checked` credits the vault with `amount − fee` while the fee is withheld; the program never reads the vault's post-transfer balance. The Wormhole message therefore overstates the escrowed amount, causing NEAR to mint more tokens than were actually locked. Repeated round-trips drain the vault at the expense of other depositors.

## Finding Description

In `init_transfer.rs`, `process` calls `transfer_checked` with `payload.amount` and immediately serialises that same `payload.amount` into the Wormhole message without ever reading the vault's actual post-transfer balance: [1](#0-0) 

The serialised Wormhole payload carries `self.amount` verbatim: [2](#0-1) 

On the NEAR side, `fin_transfer_callback` denormalises and mints the amount field from the prover result without any independent verification of what was actually locked: [3](#0-2) 

`log_metadata` is permissionless for any mint whose `mint_authority` is not the bridge authority, and it performs no check for the Token-2022 `TransferFeeConfig` extension: [4](#0-3) 

The `SECURITY.md` explicitly acknowledges Token-2022 transfer hook tokens as unsupported (denial, not fund loss) but makes no mention of transfer fee tokens being excluded or rejected: [5](#0-4) 

A grep across the entire Solana program source confirms zero occurrences of `TransferFeeConfig`, `transfer_fee_config`, or any equivalent guard. When bridging back, `finalize_transfer` calls `transfer_checked(data.amount)` from the vault using the over-stated figure from the Wormhole message, drawing down more than was deposited: [6](#0-5) 

## Impact Explanation

This is a concrete **escrow mis-accounting / balance manipulation** vulnerability matching the critical impact class. The bridge invariant `locked_on_Solana == mintable_on_NEAR` is broken for every Token-2022 mint with a non-zero transfer fee. An attacker who deposits into a shared vault that also holds other users' funds can withdraw more than they deposited, directly stealing those funds. Each round-trip extracts `fee` tokens from the vault; repeated iterations drain it entirely.

## Likelihood Explanation

No privileged access is required. `log_metadata` is callable by any user for any mint whose `mint_authority` differs from the bridge authority. `init_transfer` is callable by any token holder. Token-2022 transfer fees are a standard, production-deployed extension on Solana mainnet. The attacker needs only to deploy or obtain a Token-2022 mint with a non-zero transfer fee and wait for other users to deposit into the same vault (or be the sole depositor and exploit the deficit accumulated across multiple victims' transfers).

## Recommendation

After `transfer_checked` completes in `init_transfer`, read the vault's actual post-transfer token balance and compute `net_deposited = vault_balance_after − vault_balance_before`. Use `net_deposited` — not `payload.amount` — when constructing the Wormhole message. Alternatively, in `log_metadata`, unpack the mint's Token-2022 extensions and reject registration if a `TransferFeeConfig` extension with a non-zero fee is present.

## Proof of Concept

1. Attacker deploys a Token-2022 mint `M` with a 5% transfer fee and mints 10,000 tokens to themselves.
2. Attacker calls `log_metadata` on `M`; the bridge creates a vault PDA and posts metadata. NEAR registers the token.
3. Other legitimate users call `init_transfer` on `M`, depositing tokens. Each deposit causes the vault to receive slightly less than the Wormhole-reported amount, but the deficit is small and unnoticed.
4. Attacker calls `init_transfer` with `payload.amount = 10,000`.
   - `transfer_checked(10,000)` → vault receives **9,500**; 500 withheld as fee.
   - Wormhole message carries `amount = 10,000`.
5. NEAR relayer submits the VAA; `fin_transfer_callback` mints **10,000** tokens to the attacker on NEAR.
6. Attacker calls NEAR `ft_transfer_call` to bridge **10,000** tokens back to Solana.
   - NEAR burns 10,000 tokens.
   - Solana `finalize_transfer` calls `transfer_checked(10,000)` from the vault to the attacker — drawing on other depositors' funds to cover the 500-token shortfall.
7. Repeating this loop drains the vault, stealing funds from legitimate depositors.

### Citations

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

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L31-33)
```rust
        // 4. amount
        self.amount.serialize(&mut writer)?;
        // 5. fee
```

**File:** near/omni-bridge/src/lib.rs (L725-725)
```rust
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L41-45)
```rust
    #[account(
        constraint = !mint.mint_authority.contains(authority.key),
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,
```

**File:** solana/SECURITY.md (L19-19)
```markdown
- **Token-2022 tokens with transfer hooks are not supported** — Transfer hook extra account metas are not included in instruction account sets. Affected tokens will fail at runtime (denial, not fund loss).
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
