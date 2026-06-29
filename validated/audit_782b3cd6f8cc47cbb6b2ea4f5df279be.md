### Title
Token-2022 Transfer Fee Causes Vault Under-Crediting vs. Cross-Chain Message Over-Reporting — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

### Summary

`InitTransfer::process` calls `transfer_checked` with the caller-supplied `payload.amount`, then posts that same `payload.amount` to NEAR via Wormhole. When the mint is a Token-2022 mint with a `TransferFeeConfig` extension, the SPL runtime withholds a fee from the transfer, so the vault receives `amount - fee` tokens while the cross-chain message reports `amount`. NEAR then releases `amount` tokens worth of assets, permanently over-releasing relative to what is locked in the Solana vault.

---

### Finding Description

In `InitTransfer::process`, the native-token branch executes:

```rust
transfer_checked(
    CpiContext::new(..., TransferChecked {
        from: self.from.to_account_info(),
        to: vault.to_account_info(),
        authority: self.user.to_account_info(),
        mint: self.mint.to_account_info(),
    }),
    payload.amount.try_into()...,
    self.mint.decimals,
)?;
``` [1](#0-0) 

Immediately after, the Wormhole message is posted with the **input** `payload.amount`, not the amount actually credited to the vault:

```rust
self.common.post_message(payload.serialize_for_near((
    self.common.sequence.sequence,
    self.user.key(),
    self.mint.key(),
))?)?;
``` [2](#0-1) 

The serialized payload encodes `self.amount` directly:

```rust
self.amount.serialize(&mut writer)?;
``` [3](#0-2) 

The `token_program` field is typed as `Interface<'info, TokenInterface>`, which accepts both the classic SPL Token program and Token-2022. The `mint` field is `InterfaceAccount<'info, Mint>`, which accepts Token-2022 mints. Neither the `InitTransfer` account struct nor `process` inspects the mint's extensions for a `TransferFeeConfig`. [4](#0-3) 

The vault is created by `log_metadata`, which also performs no check for transfer fee extensions on the mint before creating the vault PDA: [5](#0-4) 

Under Token-2022's transfer fee semantics, when `transfer_checked(amount=1000, fee_rate=10%)` executes:
- Sender is debited 1000 tokens.
- Vault's spendable `amount` field increases by **900**.
- 100 tokens are withheld in the vault's `TransferFeeAmount` extension (not spendable until harvested by the fee authority).

The Wormhole message reports **1000**. NEAR finalizes a release of 1000 tokens worth of assets. The vault holds only 900 spendable tokens. The invariant `vault_balance_increase == cross_chain_amount` is broken.

---

### Impact Explanation

Every `init_transfer` call on a Token-2022 mint with a non-zero transfer fee causes NEAR to over-release assets by exactly the fee amount. Over many transfers, the Solana vault is progressively under-collateralized relative to NEAR's accounting. When users attempt to bridge back, `finalize_transfer` calls `transfer_checked` from the vault for the full reported amount, which will fail or drain the vault faster than it was filled, permanently locking or losing funds for later users. [6](#0-5) 

---

### Likelihood Explanation

Token-2022 is explicitly supported by the bridge (the code imports and uses `token_2022`, `token_interface`, and `TokenInterface` throughout). Any Token-2022 mint with a `TransferFeeConfig` extension — whether a legitimate DeFi token or an attacker-created mint — triggers this path. No special privilege is required; any user can call `init_transfer` with such a mint after `log_metadata` has registered it.

---

### Recommendation

After `transfer_checked` completes, read the vault's actual post-transfer spendable balance (or compute the fee-adjusted amount using `calculate_fee` from the `TransferFeeConfig` extension) and use **that** value in the Wormhole message instead of `payload.amount`. Alternatively, reject mints that have a `TransferFeeConfig` extension with a non-zero fee in both `log_metadata` and `init_transfer` by unpacking the mint's extension data and asserting the fee is zero, similar to how `log_metadata` already unpacks `MetadataPointer`: [7](#0-6) 

---

### Proof of Concept

1. On localnet, create a Token-2022 mint with `TransferFeeConfig` set to 1000 bps (10%), max fee = `u64::MAX`.
2. Mint 10,000 tokens to an attacker-controlled token account.
3. Call `log_metadata` to register the mint and create the vault PDA.
4. Call `init_transfer` with `payload.amount = 1000`, `payload.fee = 0`, `payload.native_fee = 0`.
5. Assert: `vault.amount == 900` (only 900 tokens credited due to transfer fee).
6. Assert: the Wormhole message payload contains `amount = 1000`.
7. Observe the invariant violation: `vault.amount (900) < payload.amount (1000)`.
8. Repeat N times; after N transfers the vault is under-collateralized by `N * 100` tokens while NEAR has released `N * 1000` tokens worth of assets.

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L20-69)
```rust
#[derive(Accounts)]
pub struct InitTransfer<'info> {
    #[account(
        seeds = [AUTHORITY_SEED],
        bump = common.config.bumps.authority,
    )]
    pub authority: SystemAccount<'info>,

    #[account(
        mut,
        mint::token_program = token_program,
    )]
    pub mint: Box<InterfaceAccount<'info, Mint>>,

    #[account(
        mut,
        token::mint = mint,
        token::token_program = token_program,
    )]
    pub from: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(
        mut,
        token::mint = mint,
        token::authority = authority,
        seeds = [
            VAULT_SEED,
            mint.key().as_ref(),
        ],
        bump,
        token::token_program = token_program,
    )]
    pub vault: Option<Box<InterfaceAccount<'info, TokenAccount>>>,

    #[account(
        mut,
        seeds = [SOL_VAULT_SEED],
        bump = common.config.bumps.sol_vault,
    )]
    pub sol_vault: SystemAccount<'info>,

    #[account(
        mut,
        owner = common.system_program.key(),
    )]
    pub user: Signer<'info>,

    pub common: WormholeCPI<'info>,

    pub token_program: Interface<'info, TokenInterface>,
}
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

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L51-62)
```rust
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

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L92-114)
```rust
        let (name, symbol) = if self.token_program.key() == token_2022::ID {
            let mint_account_info = self.mint.to_account_info();
            let mint_data = mint_account_info.try_borrow_data()?;
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
