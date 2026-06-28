### Title
Token-2022 Transfer Fee Extension Causes Vault Under-Crediting vs. Cross-Chain Message Amount — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

### Summary

`InitTransfer::process` calls `transfer_checked` with the caller-supplied `payload.amount` and then posts a Wormhole message containing that same `payload.amount`. When the mint has a Token-2022 **transfer fee** extension, `transfer_checked` silently withholds the fee in the vault's account, so the vault's usable balance increases by `amount - fee` while the cross-chain message reports `amount`. NEAR finalizes the release for the full `amount`, over-releasing assets relative to what is actually locked.

### Finding Description

In `InitTransfer::process`, the native-token branch executes:

```rust
transfer_checked(
    CpiContext::new(..., TransferChecked { from, to: vault, authority, mint }),
    payload.amount.try_into()...,
    self.mint.decimals,
)?;
``` [1](#0-0) 

Immediately after, the Wormhole message is posted with the unmodified `payload.amount`:

```rust
self.common.post_message(payload.serialize_for_near((
    self.common.sequence.sequence,
    self.user.key(),
    self.mint.key(),
))?)?;
``` [2](#0-1) 

The serialized message encodes `self.amount` directly:

```rust
self.amount.serialize(&mut writer)?;
``` [3](#0-2) 

Under the Token-2022 transfer fee extension, `transfer_checked` debits the sender by `amount` but credits the recipient (vault) by only `amount - withheld_fee`. The withheld portion is recorded inside the vault's token account as fee-authority-owned, not bridge-authority-owned. No code reads back the actual post-transfer vault balance; the message always carries the pre-fee `payload.amount`.

The vault is created permissionlessly via `log_metadata`, which has **no check** for transfer fee or transfer hook extensions on the mint: [4](#0-3) 

`log_metadata` only inspects metadata-pointer and metadata extensions; it never calls `get_extension::<TransferFeeConfig>()` or rejects mints that carry it. Any Token-2022 mint with a transfer fee can therefore be registered as a native vault token.

The `solana/SECURITY.md` acknowledges transfer **hooks** as a known non-issue (runtime denial, not fund loss) but makes no mention of transfer **fees**: [5](#0-4) 

Transfer fees are fundamentally different: `transfer_checked` succeeds without any extra accounts, so there is no runtime failure — only a silent balance discrepancy.

### Impact Explanation

For every `init_transfer` on a mint with a `f` basis-point transfer fee:

- Vault receives: `amount × (1 − f/10000)`
- NEAR message claims: `amount`
- NEAR releases: `amount`
- Protocol loss per transfer: `amount × f/10000`

At 10% fee and `amount = 1000`, NEAR releases 1000 while only 900 are locked. Repeated transfers drain the NEAR-side escrow relative to the Solana vault, enabling an attacker to extract more assets from NEAR than were ever deposited on Solana.

### Likelihood Explanation

The attack requires only:
1. Creating a Token-2022 mint with a transfer fee extension (permissionless on Solana).
2. Calling `log_metadata` to register the vault (permissionless, no fee-extension check).
3. Calling `init_transfer` repeatedly.

No admin access, key compromise, or external collusion is needed. The path is fully self-contained and locally testable.

### Recommendation

In `InitTransfer::process`, after `transfer_checked`, read back the vault's actual token balance (or compute the withheld fee via `TransferFeeConfig::calculate_epoch_fee`) and use the **net received amount** in the Wormhole message instead of `payload.amount`.

Alternatively, in `log_metadata`, reject mints that carry a `TransferFeeConfig` or `TransferHook` extension by unpacking the mint with `StateWithExtensions` and checking `get_extension::<TransferFeeConfig>()`.

### Proof of Concept

1. On localnet, create a Token-2022 mint with `TransferFeeConfig` at 1000 bps (10%).
2. Call `log_metadata` — succeeds, vault PDA created.
3. Call `init_transfer` with `amount = 1_000_000`.
4. Assert `vault.amount == 900_000` (actual) vs. Wormhole payload `amount == 1_000_000` (reported).
5. On the NEAR side, finalize the transfer — NEAR releases 1_000_000 units while only 900_000 are locked in the Solana vault.
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

**File:** solana/SECURITY.md (L19-19)
```markdown
- **Token-2022 tokens with transfer hooks are not supported** — Transfer hook extra account metas are not included in instruction account sets. Affected tokens will fail at runtime (denial, not fund loss).
```
