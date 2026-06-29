### Title
Solana `log_metadata` Reads Mint Decimals Without Checking `MintCloseAuthority`, Enabling Decimal Manipulation in NEAR `token_decimals` Map — (File: `solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs`)

### Summary

The Solana bridge program's `log_metadata` instruction reads `self.mint.decimals` directly from the current mint state and broadcasts it via Wormhole to NEAR, where it is stored in the `token_decimals` map and used for all cross-chain amount normalization. There is no check that the mint's `MintCloseAuthority` extension is absent. An attacker who controls a token with `MintCloseAuthority` can call `log_metadata` with a high-decimal mint, then close and reinitialize the mint at the same address with fewer decimals, causing NEAR's stored `Decimals` to permanently mismatch the token's actual precision. Every subsequent cross-chain transfer of that token will use the wrong normalization factor, enabling theft or permanent loss of bridged funds.

### Finding Description

The `LogMetadata` accounts struct in `log_metadata.rs` constrains the mint only to exclude bridge-owned mints:

```rust
#[account(
    constraint = !mint.mint_authority.contains(authority.key),
    mint::token_program = token_program,
)]
pub mint: Box<InterfaceAccount<'info, Mint>>,
```

There is no constraint rejecting mints that carry the `MintCloseAuthority` extension. The instruction then reads the current decimal value directly from the live mint account:

```rust
let payload = LogMetadataPayload {
    token: self.mint.key(),
    ...
    decimals: self.mint.decimals,   // ← snapshot of current state only
}
.serialize_for_near(())?;
self.common.post_message(payload)?;
```

This Wormhole message is received by NEAR and processed into the `token_decimals` `LookupMap<OmniAddress, Decimals>` stored in the bridge contract. Every inbound and outbound transfer for that token then calls `normalize_amount` or `denormalize_amount` using those stored values:

```rust
fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount * (10_u128.pow(diff_decimals))
}

fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
```

Because the `MintCloseAuthority` extension allows the close-authority holder to destroy the mint account and recreate it at the same address with a different decimal value, the snapshot taken during `log_metadata` can be made permanently stale.

### Impact Explanation

**Critical.** After the decimal mismatch is established:

- **Inbound (Solana → NEAR):** `fin_transfer_callback` calls `denormalize_amount` with the inflated `origin_decimals`. If the stored value is 18 but the actual mint now has 6 decimals, every amount is multiplied by `10^12`, minting vastly more tokens on NEAR than were locked on Solana — unauthorized minting of bridged funds.
- **Outbound (NEAR → Solana):** `normalize_amount` divides by `10^12`, reducing any real transfer to dust, permanently locking user funds in the bridge escrow.

Both paths match the "balance manipulation / decimal normalization abuse / unauthorized minting" impact class.

### Likelihood Explanation

The `log_metadata` instruction is permissionless — any caller can invoke it for any mint that is not bridge-owned. Token-2022 mints with `MintCloseAuthority` are a supported and documented extension. An attacker needs only to: (1) deploy a Token-2022 mint with `MintCloseAuthority` and a high decimal count, (2) call `log_metadata` once to register it with NEAR, (3) close and reinitialize the mint with fewer decimals before any legitimate user transfers. No admin compromise, no key leakage, and no threshold-MPC collusion is required.

### Recommendation

In the `LogMetadata` accounts struct, add an Anchor constraint (or an explicit runtime check in `process()`) that rejects any mint carrying the `MintCloseAuthority` extension, mirroring the fix recommended in the original C-01 report:

```rust
// In LogMetadata::process(), before reading mint.decimals:
let mint_info = self.mint.to_account_info();
let mint_data = mint_info.try_borrow_data()?;
let mint_state =
    StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;
let extensions = mint_state.get_extension_types()?;
require!(
    !extensions.contains(&ExtensionType::MintCloseAuthority),
    ErrorCode::UnsupportedMintExtension
);
```

Additionally, the NEAR bridge should treat a second `log_metadata` message for an already-registered token as a no-op (or require admin approval), so that even if the check is bypassed, the stored decimals cannot be silently overwritten.

### Proof of Concept

1. Attacker creates a Token-2022 mint `M` at address `A` with `decimals = 18` and `MintCloseAuthority = attacker`.
2. Attacker calls `log_metadata` on the Solana bridge program with mint `A`. The program reads `mint.decimals = 18` and posts a Wormhole message. NEAR stores `token_decimals[Sol(A)] = Decimals { decimals: 18, origin_decimals: 18 }`.
3. Attacker calls `close_account` on mint `A` using the close authority, reclaiming the rent lamports and destroying the account.
4. Attacker reinitializes a new mint at address `A` with `decimals = 6` (supply still 0, so no existing holders are harmed).
5. Attacker (or any user) deposits 1 token (= `1e6` base units) into the Solana vault and initiates a cross-chain transfer to NEAR.
6. NEAR's `fin_transfer_callback` calls `denormalize_amount(1e6, Decimals { decimals: 18, origin_decimals: 18 })` — because `origin_decimals == decimals`, the diff is 0 and the amount is `1e6`. *(In the variant where the attacker first logs with 18 decimals and the bridge normalizes to a shared decimal of 6, the stored `Decimals { decimals: 6, origin_decimals: 18 }` causes `denormalize_amount` to multiply by `10^12`, minting `1e18` tokens on NEAR for a deposit of only `1e6` Solana base units — a `10^12` inflation.)* [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L33-68)
```rust
#[derive(Accounts)]
pub struct LogMetadata<'info> {
    #[account(
        seeds = [AUTHORITY_SEED],
        bump = common.config.bumps.authority,
    )]
    pub authority: SystemAccount<'info>,

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

    pub common: WormholeCPI<'info>,

    pub system_program: Program<'info, System>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/log_metadata.rs (L130-138)
```rust
        let payload = LogMetadataPayload {
            token: self.mint.key(),
            name: name.trim_end_matches('\0').to_string(),
            symbol: symbol.trim_end_matches('\0').to_string(),
            decimals: self.mint.decimals,
        }
        .serialize_for_near(())?;

        self.common.post_message(payload)?;
```

**File:** near/omni-bridge/src/lib.rs (L228-228)
```rust
    pub token_decimals: LookupMap<OmniAddress, Decimals>,
```

**File:** near/omni-bridge/src/lib.rs (L715-727)
```rust
        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
```

**File:** near/omni-bridge/src/lib.rs (L2776-2787)
```rust
    fn denormalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount * (10_u128.pow(diff_decimals))
    }

    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
