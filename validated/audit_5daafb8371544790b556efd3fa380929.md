The critical piece of evidence is in `solana/SECURITY.md` line 19, which acknowledges transfer hooks as a runtime denial (not fund loss), but says **nothing** about transfer fees. These are distinct Token-2022 extensions with fundamentally different behavior.

---

### Title
Token-2022 Transfer Fee Extension Causes Vault Under-Crediting vs. Cross-Chain Message Over-Reporting — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

### Summary

`InitTransfer::process` calls `transfer_checked` with the raw `payload.amount` and then posts a Wormhole message containing that same `payload.amount`. When the mint has a Token-2022 transfer fee extension, the vault receives `amount - fee` tokens while the cross-chain message reports `amount`. NEAR finalizes the transfer for the full reported amount, releasing more assets than were locked on Solana.

### Finding Description

In `InitTransfer::process`, the native-token path (vault exists) executes:

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

Immediately after, the Wormhole message is posted with the original `payload.amount`:

```rust
self.common.post_message(payload.serialize_for_near((
    self.common.sequence.sequence,
    self.user.key(),
    self.mint.key(),
))?)?;
``` [2](#0-1) 

The serialized message encodes `self.amount` directly: [3](#0-2) 

Under Token-2022's transfer fee extension, `transfer_checked(amount)` debits the sender by `amount` but credits the recipient (vault) only `amount - withheld_fee`. The withheld fee is stored as `withheld_amount` inside the vault's token account — it is **not** part of the vault's spendable balance. The Wormhole message still carries the pre-fee `amount`, so NEAR releases `amount` worth of assets while only `amount - fee` is actually locked.

There is no guard against this in the `InitTransfer` account constraints — the mint is only validated for `token_program` consistency: [4](#0-3) 

The `log_metadata` instruction (which creates the vault) also performs no check for a transfer fee extension on the mint: [5](#0-4) 

The SECURITY.md explicitly acknowledges that transfer hooks cause a runtime denial (not fund loss), but makes no mention of transfer fees: [6](#0-5) 

Transfer hooks and transfer fees are distinct extensions. Transfer hooks fail at runtime due to missing extra account metas. Transfer fees succeed silently, deducting from the recipient's spendable balance — exactly the condition that breaks the bridge invariant.

### Impact Explanation

For every `init_transfer` involving a Token-2022 mint with a transfer fee of `F` basis points:

- Solana vault receives `amount × (1 - F/10000)` tokens
- NEAR releases `amount` tokens to the recipient

The difference `amount × F/10000` is permanently over-released from NEAR's escrow. With a 10% fee and repeated transfers, the NEAR-side escrow is drained at 10% per transfer. This is a direct, quantifiable loss of bridged funds — Critical escrow mis-accounting.

### Likelihood Explanation

The attack is fully permissionless:
1. Any user can create a Token-2022 mint with a transfer fee extension.
2. Any user can call `log_metadata` to register it (no role check, no extension validation).
3. Any user can call `init_transfer` with that mint.

No admin compromise, no key leakage, no oracle manipulation required.

### Recommendation

In `InitTransfer::process` (native vault path), after `transfer_checked` completes, read the vault's actual post-transfer spendable balance and use the **delta** (balance after − balance before) as the amount encoded in the Wormhole message, rather than the caller-supplied `payload.amount`. Alternatively, reject mints that have a `TransferFeeConfig` extension by unpacking the mint's extension state and returning an error if the extension is present — consistent with how the program already rejects unsupported configurations.

### Proof of Concept

1. On localnet, create a Token-2022 mint with `TransferFeeConfig` set to 1000 basis points (10%).
2. Call `log_metadata` with that mint to register it and create the vault PDA.
3. Call `init_transfer` with `amount = 1000`.
4. Read the vault's token account `amount` field after the instruction.
5. Assert `vault.amount == 1000` — this assertion **fails**; vault holds 900.
6. Observe the Wormhole message payload encodes `amount = 1000`.
7. The invariant `vault_delta == message_amount` is violated by exactly the withheld fee.

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

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L32-32)
```rust
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

**File:** solana/SECURITY.md (L19-19)
```markdown
- **Token-2022 tokens with transfer hooks are not supported** — Transfer hook extra account metas are not included in instruction account sets. Affected tokens will fail at runtime (denial, not fund loss).
```
