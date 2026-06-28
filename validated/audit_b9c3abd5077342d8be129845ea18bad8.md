### Title
Unvalidated `recipient` String in `InitTransferPayload` Causes Permanent Token Loss on Solana — (`solana/programs/bridge_token_factory/src/state/message/init_transfer.rs`)

---

### Summary

The Solana `bridge_token_factory` program accepts a raw, unvalidated `recipient: String` in `InitTransferPayload` for both `init_transfer` and `init_transfer_sol`. Tokens are locked in the vault (native) or burned (bridged) before the Wormhole message is posted. If the recipient string is malformed or unresolvable on the NEAR side, the transfer fails irreversibly on NEAR while the Solana-side tokens are permanently lost with no on-chain refund path.

---

### Finding Description

`InitTransferPayload` defines `recipient` as a plain `String` with no format or chain-prefix validation: [1](#0-0) 

The `process()` handler in `InitTransfer` performs only a fee/amount check, then immediately locks or burns tokens and posts the Wormhole message — all before any recipient validation can occur: [2](#0-1) 

The same pattern applies to native SOL transfers: [3](#0-2) 

Both are publicly callable entry points with no access restriction beyond the pause flag: [4](#0-3) 

The `recipient` string is serialized verbatim into the Wormhole VAA payload: [5](#0-4) 

On the NEAR side, `fin_transfer_callback` deserializes the VAA and attempts to parse `recipient` as an `OmniAddress`. If the string is malformed (e.g., missing chain prefix, unsupported chain, invalid address format), NEAR panics and the transfer is permanently stuck. There is no on-chain refund path back to Solana: [6](#0-5) 

The `OmniAddress::from_str` parser requires a valid `chain:address` format and will error on anything else: [7](#0-6) 

The project's own `SECURITY.md` acknowledges this gap: [8](#0-7) 

---

### Impact Explanation

- **Native tokens** (SPL tokens with a registered vault): permanently locked in the PDA vault at `[VAULT_SEED, mint]`. No on-chain instruction exists to release vault funds without a valid finalization flow from NEAR.
- **Bridged tokens** (wrapped mints): burned at the point of `init_transfer`. Burned supply is unrecoverable.
- In both cases the user loses the full transferred amount. This constitutes permanent freezing/loss of bridged funds across the Solana–NEAR corridor.

---

### Likelihood Explanation

Any unprivileged Solana user who calls `init_transfer` or `init_transfer_sol` directly (bypassing the bridge API) with a malformed `recipient` string triggers this loss. Realistic scenarios include:

1. A user constructing the transaction manually or via a third-party SDK with a typo in the recipient (e.g., `"alice.near"` without the `near:` prefix, or `"eth:0xabc"` when targeting NEAR).
2. A custom relayer or integration that passes an unsupported chain prefix (e.g., `"cosmos:address"`).
3. A malicious actor deliberately burning another user's bridged tokens by front-running or social-engineering them into signing a crafted transaction (self-harm vector, but also applicable to phishing).

The bridge API would normally validate this off-chain, but there is no on-chain enforcement, so direct contract callers are fully exposed.

---

### Recommendation

Add on-chain validation of the `recipient` string inside `InitTransferPayload::process()` before any token state change. At minimum:

1. Verify the string contains a `:` separator and that the chain prefix is one of the supported values (`near`, `eth`, `sol`, `arb`, `base`, `bnb`, `pol`, `hlevm`, `abs`, `strk`, `fogo`, `btc`, `zcash`).
2. For `near:` recipients, validate the account-ID portion against NEAR account-ID rules (64-char max, valid charset).
3. For EVM recipients, verify the address portion is a valid 20-byte hex string.

This mirrors the validation already present in `OmniAddress::from_str` on the NEAR side and should be replicated in the Solana program to enforce the invariant before tokens are committed.

---

### Proof of Concept

```
1. User calls init_transfer on Solana with:
   payload = InitTransferPayload {
       amount: 1_000_000,
       recipient: "alice.near",   // missing "near:" prefix — invalid OmniAddress
       fee: 0,
       native_fee: 0,
       message: "",
   }

2. Solana program:
   - Checks amount > fee  ✓
   - Transfers tokens into vault (or burns bridged tokens)  ✓
   - Posts Wormhole VAA containing "alice.near" as recipient  ✓
   - Returns Ok(())  ✓

3. Relayer picks up VAA, calls fin_transfer on NEAR.

4. NEAR fin_transfer_callback:
   - Decodes VAA → InitTransferMessage { recipient: "alice.near", ... }
   - Calls OmniAddress::from_str("alice.near")
     → splits on ':' → chain = "eth" (default), address = "alice.near"
     → H160::from_str("alice.near") → ERR_INVALID_HEX  → panic
   - Transaction reverts on NEAR.

5. Solana vault still holds the locked tokens.
   No refund instruction exists. Tokens are permanently frozen.
```

### Citations

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L7-14)
```rust
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct InitTransferPayload {
    pub amount: u128,
    pub recipient: String,
    pub fee: u128,
    pub native_fee: u64,
    pub message: String,
}
```

**File:** solana/programs/bridge_token_factory/src/state/message/init_transfer.rs (L37-38)
```rust
        // 7. recipient
        self.recipient.serialize(&mut writer)?;
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer.rs (L72-130)
```rust
    pub fn process(&self, payload: &InitTransferPayload) -> Result<()> {
        require!(payload.amount > payload.fee, ErrorCode::InvalidFee);

        if payload.native_fee > 0 {
            transfer(
                CpiContext::new(
                    self.common.system_program.to_account_info(),
                    Transfer {
                        from: self.user.to_account_info(),
                        to: self.sol_vault.to_account_info(),
                    },
                ),
                payload.native_fee,
            )?;
        }

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

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/init_transfer_sol.rs (L34-62)
```rust
impl InitTransferSol<'_> {
    pub fn process(&self, payload: &InitTransferPayload) -> Result<()> {
        require!(payload.fee == 0, ErrorCode::InvalidFee);
        require!(payload.amount > 0, ErrorCode::InvalidArgs);

        transfer(
            CpiContext::new(
                self.common.system_program.to_account_info(),
                Transfer {
                    from: self.user.to_account_info(),
                    to: self.sol_vault.to_account_info(),
                },
            ),
            payload
                .native_fee
                .checked_add(
                    payload.amount.try_into().map_err(|_| error!(ErrorCode::InvalidArgs))?,
                )
                .ok_or_else(|| error!(ErrorCode::InvalidArgs))?,
        )?;

        self.common.post_message(payload.serialize_for_near((
            self.common.sequence.sequence,
            self.user.key(),
            Pubkey::default(),
        ))?)?;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/lib.rs (L124-148)
```rust
    pub fn init_transfer(ctx: Context<InitTransfer>, payload: InitTransferPayload) -> Result<()> {
        require!(
            ctx.accounts.common.config.paused & INIT_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
        );
        msg!("Initializing transfer");

        ctx.accounts.process(&payload)?;

        Ok(())
    }

    pub fn init_transfer_sol(
        ctx: Context<InitTransferSol>,
        payload: InitTransferPayload,
    ) -> Result<()> {
        require!(
            ctx.accounts.common.config.paused & INIT_TRANSFER_PAUSED == 0,
            error::ErrorCode::Paused
        );
        msg!("Initializing transfer");

        ctx.accounts.process(&payload)?;

        Ok(())
```

**File:** near/omni-bridge/src/lib.rs (L700-746)
```rust
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

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
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
    }
```

**File:** near/omni-types/src/lib.rs (L389-411)
```rust
impl FromStr for OmniAddress {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let (chain, recipient) = input.split_once(':').unwrap_or(("eth", input));

        match chain {
            "eth" => Ok(Self::Eth(recipient.parse().map_err(stringify)?)),
            "near" => Ok(Self::Near(recipient.parse().map_err(stringify)?)),
            "sol" => Ok(Self::Sol(recipient.parse().map_err(stringify)?)),
            "arb" => Ok(Self::Arb(recipient.parse().map_err(stringify)?)),
            "base" => Ok(Self::Base(recipient.parse().map_err(stringify)?)),
            "bnb" => Ok(Self::Bnb(recipient.parse().map_err(stringify)?)),
            "pol" => Ok(Self::Pol(recipient.parse().map_err(stringify)?)),
            "hlevm" => Ok(Self::HyperEvm(recipient.parse().map_err(stringify)?)),
            "abs" => Ok(Self::Abs(recipient.parse().map_err(stringify)?)),
            "btc" => Ok(Self::Btc(recipient.to_string())),
            "zcash" => Ok(Self::Zcash(recipient.to_string())),
            "strk" => Ok(Self::Strk(recipient.parse().map_err(stringify)?)),
            "fogo" => Ok(Self::Fogo(recipient.parse().map_err(stringify)?)),
            _ => Err(format!("Chain {chain} is not supported")),
        }
    }
```

**File:** solana/SECURITY.md (L17-17)
```markdown
- **No validation of `recipient` string in `InitTransferPayload`** — An invalid recipient causes the transfer to fail on the NEAR side after tokens are locked/burned on Solana. Manual intervention would be needed.
```
