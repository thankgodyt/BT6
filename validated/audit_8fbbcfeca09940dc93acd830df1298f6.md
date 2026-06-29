### Title
Solana `finalize_transfer` Recipient Account Not Verified Against MPC-Signed Payload, Enabling Token Theft — (`solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs`)

### Summary
The Solana `FinalizeTransfer` instruction accepts a caller-supplied `recipient` account that is never validated against the MPC-signed `FinalizeTransferPayload`. Because the signed payload contains no `recipient` field, any caller can submit a legitimate MPC signature with a substituted recipient, redirecting bridged tokens to an arbitrary address and permanently consuming the nonce.

### Finding Description
The `FinalizeTransferPayload` struct that the MPC network signs contains only `destination_nonce`, `transfer_id`, `amount`, and `fee_recipient`: [1](#0-0) 

The `recipient` is absent from this struct. In the `FinalizeTransfer` accounts struct, `recipient` is declared as a bare `UncheckedAccount` with no constraint tying it to any value in the signed payload: [2](#0-1) 

The `token_account` is derived as the ATA of whatever `recipient` is passed, so tokens flow to that account unconditionally: [3](#0-2) 

The `process()` handler marks the nonce used and transfers/mints tokens to `self.token_account` (the ATA of the caller-supplied `recipient`) without any check that `self.recipient.key()` matches the intended recipient recorded on NEAR: [4](#0-3) 

The `FinalizeTransferResponse` posted back to NEAR via Wormhole also omits the recipient, so NEAR cannot detect the misdirection: [5](#0-4) 

The same pattern exists for native SOL transfers in `FinalizeTransferSol`, where `recipient` is again an unconstrained `UncheckedAccount` and SOL is transferred directly to it: [6](#0-5) [7](#0-6) 

There is no authority constraint on who may call `finalize_transfer` — the accounts struct has no role check or relayer whitelist, making the instruction permissionless.

### Impact Explanation
An attacker who observes a valid MPC-signed `FinalizeTransferPayload` (available from NEAR transaction logs or the Wormhole VAA stream) can call `finalize_transfer` on Solana with the authentic signature but substitute their own public key as `recipient`. The nonce is consumed, the legitimate user's tokens are minted or transferred to the attacker's ATA, and the transfer cannot be replayed. This constitutes direct theft of bridged funds with no recovery path.

### Likelihood Explanation
The instruction is permissionless and the signed payload is publicly observable on-chain. Any actor monitoring NEAR or Wormhole for pending finalization payloads can front-run the legitimate relayer. No privileged access, key compromise, or validator collusion is required.

### Recommendation
Include the intended recipient's Solana public key inside `FinalizeTransferPayload` so it is covered by the MPC signature. Add an Anchor account constraint that enforces `recipient.key() == data.payload.recipient`, rejecting any transaction where the supplied account does not match the signed value. Apply the same fix to `FinalizeTransferSol`.

### Proof of Concept
1. Alice initiates a NEAR → Solana transfer specifying her Solana pubkey `ALICE` as recipient.
2. The MPC signs `FinalizeTransferPayload { destination_nonce: N, transfer_id: T, amount: A, fee_recipient: None }` — no recipient field.
3. Attacker observes the signed payload from NEAR logs.
4. Attacker calls `finalize_transfer` on Solana, passing the valid signature and payload but supplying `ATTACKER` as the `recipient` account.
5. Anchor derives `token_account` as the ATA of `ATTACKER` for the mint; `UsedNonces::use_nonce` marks nonce `N` as spent; tokens are minted/transferred to `ATTACKER`'s ATA.
6. Alice's transfer is permanently consumed. She receives nothing and cannot replay the transfer.

### Citations

**File:** solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs (L10-16)
```rust
#[derive(AnchorSerialize, AnchorDeserialize, Debug)]
pub struct FinalizeTransferPayload {
    pub destination_nonce: u64,
    pub transfer_id: TransferId,
    pub amount: u128,
    pub fee_recipient: Option<String>,
}
```

**File:** solana/programs/bridge_token_factory/src/state/message/finalize_transfer.rs (L46-52)
```rust
#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct FinalizeTransferResponse {
    pub token: Pubkey,
    pub amount: u128,
    pub fee_recipient: String,
    pub transfer_id: TransferId,
}
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L50-51)
```rust
    /// CHECK: this can be any type of account
    pub recipient: UncheckedAccount<'info>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L73-80)
```rust
    #[account(
        init_if_needed,
        payer = common.payer,
        associated_token::mint = mint,
        associated_token::authority = recipient,
        token::token_program = token_program,
    )]
    pub token_account: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L89-149)
```rust
impl FinalizeTransfer<'_> {
    pub fn process(&mut self, data: FinalizeTransferPayload) -> Result<()> {
        UsedNonces::use_nonce(
            data.destination_nonce,
            &self.used_nonces,
            &mut self.config,
            self.authority.to_account_info(),
            self.common.payer.to_account_info(),
            &Rent::get()?,
            self.system_program.to_account_info(),
        )?;

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
        } else {
            // Bridged version. May be a fake token with our authority set but it will be ignored on the near side
            require!(
                self.mint.mint_authority.contains(self.authority.key),
                ErrorCode::InvalidBridgedToken
            );

            mint_to(
                CpiContext::new_with_signer(
                    self.token_program.to_account_info(),
                    MintTo {
                        mint: self.mint.to_account_info(),
                        to: self.token_account.to_account_info(),
                        authority: self.authority.to_account_info(),
                    },
                    &[&[AUTHORITY_SEED, &[self.config.bumps.authority]]],
                ),
                data.amount.try_into().map_err(|_| error!(ErrorCode::AmountOverflow))?,
            )?;
        }

        let payload = FinalizeTransferResponse {
            token: self.mint.key(),
            amount: data.amount,
            fee_recipient: data.fee_recipient.unwrap_or_default(),
            transfer_id: data.transfer_id,
        }
        .serialize_for_near(())?;

        self.common.post_message(payload)?;

        Ok(())
    }
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer_sol.rs (L52-54)
```rust
    /// CHECK: this can be any type of account
    #[account(mut)]
    pub recipient: UncheckedAccount<'info>,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer_sol.rs (L79-89)
```rust
        transfer(
            CpiContext::new_with_signer(
                self.common.system_program.to_account_info(),
                Transfer {
                    from: self.sol_vault.to_account_info(),
                    to: self.recipient.to_account_info(),
                },
                &[&[SOL_VAULT_SEED, &[self.config.bumps.sol_vault]]],
            ),
            data.amount.try_into().map_err(|_| error!(ErrorCode::AmountOverflow))?,
        )?;
```
