### Title
Token-2022 Transfer Fee Causes Vault Under-Crediting vs. Cross-Chain Message Amount — (`solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs`)

---

### Summary

`InitTransfer::process` calls `transfer_checked` with `payload.amount` and then posts a Wormhole message containing that same `payload.amount`. When the mint is a Token-2022 token with a `TransferFeeConfig` extension, the SPL runtime withholds a fee from the recipient (the vault), so the vault receives strictly less than `payload.amount`. NEAR is told the full `payload.amount` was locked, minting or releasing that many wrapped tokens. The vault balance and the NEAR-side accounting permanently diverge, and the last users to bridge back cannot be made whole.

---

### Finding Description

**Vault creation — no transfer-fee guard**

`log_metadata` creates a vault PDA for any Token-2022 mint whose `mint_authority` is not the bridge authority. There is no inspection of the mint's extensions: [1](#0-0) 

**Transfer — amount posted equals amount requested, not amount received**

`InitTransfer::process` calls `transfer_checked` with the caller-supplied `payload.amount`, then immediately serialises that same value into the Wormhole message: [2](#0-1) [3](#0-2) 

With Token-2022 transfer fees, `transfer_checked(amount=N)` debits the sender `N` tokens but credits the vault only `N − fee`. The fee is withheld inside the vault's token account and is only recoverable by the fee-harvest authority — it is not spendable by the bridge. The Wormhole message still carries `N`.

**Payload serialisation — no post-transfer balance check**

`InitTransferPayload::serialize_for_near` encodes `self.amount` verbatim; there is no mechanism to substitute the actually-received amount: [4](#0-3) 

---

### Impact Explanation

For every `init_transfer` on a fee-bearing Token-2022 mint:

- Vault spendable balance increases by `amount × (1 − fee_rate)`
- NEAR-side wrapped supply increases by `amount`

The ratio diverges with each transfer. When users later bridge back, `finalize_transfer` attempts to release the full NEAR-reported amount from the vault. The vault runs short by the cumulative withheld fees, causing the last redeemers to receive nothing. An attacker who controls the fee-bearing mint can set the fee rate to maximise the discrepancy and drain other users' locked funds.

---

### Likelihood Explanation

- Token-2022 transfer fees are a standard, widely-used extension; legitimate tokens carry them.
- `log_metadata` imposes no extension whitelist, so any such token can be registered.
- The attacker path requires only two permissionless on-chain calls (`log_metadata`, then `init_transfer`); no admin access, key compromise, or oracle manipulation is needed.
- The discrepancy is deterministic and grows linearly with transfer volume.

---

### Recommendation

1. **Reject fee-bearing mints at registration.** In `log_metadata`, unpack the mint's extensions and return an error if `TransferFeeConfig` is present:

   ```rust
   // in log_metadata.rs, before posting the message
   if token_program == token_2022::ID {
       let data = mint.to_account_info().try_borrow_data()?;
       let state = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&data)?;
       require!(
           state.get_extension::<TransferFeeConfig>().is_err(),
           ErrorCode::UnsupportedMintExtension
       );
   }
   ```

2. **Alternatively, measure the vault delta.** Record the vault balance before and after `transfer_checked` and use the delta — not `payload.amount` — as the value posted in the Wormhole message. This is safer but more complex.

3. **Apply the same guard to `init_transfer`** as a defence-in-depth check, since a mint's fee config can be added after registration if the fee authority is not frozen.

---

### Proof of Concept

```
1. Create a Token-2022 mint with TransferFeeConfig: fee_rate=1000 bps (10%), max_fee=u64::MAX.
2. Call log_metadata with this mint → vault PDA is created, no error.
3. Mint 1000 tokens to attacker's ATA.
4. Call init_transfer(amount=1000, recipient="attacker.near", fee=0, native_fee=0).
   - transfer_checked moves 1000 from ATA to vault.
   - Token-2022 runtime withholds 100 in vault; vault spendable balance = 900.
   - Wormhole message payload.amount = 1000.
5. NEAR finalises the VAA and mints 1000 wrapped tokens to attacker.near.
6. Attacker bridges back 1000 wrapped tokens from NEAR.
   - NEAR burns 1000 wrapped tokens, posts finalize message with amount=1000.
   - Solana finalize_transfer tries to release 1000 from vault.
   - Vault only has 900 spendable → transaction fails or a different user's deposit is consumed.

Assert: vault.amount after step 4 < payload.amount in the Wormhole message.
Fuzz: vary fee_rate from 1 to 10000 bps; invariant breaks for any non-zero value.
```

### Citations

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
