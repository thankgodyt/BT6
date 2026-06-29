Now I have all the information needed. Let me analyze the exact execution order and mechanism.

### Title
Permanent Fund Freeze via u128→u64 Overflow in `FinalizeTransfer::process` with No NEAR-Side Guard — (`solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs`)

---

### Summary

`FinalizeTransferPayload.amount` is typed as `u128`, but Solana SPL token operations require `u64`. When NEAR signs a payload whose normalized amount exceeds `u64::MAX`, every Solana finalization attempt returns `AmountOverflow`. Due to Solana's transaction atomicity the nonce is rolled back and remains unused, but the transfer can never succeed, permanently locking the user's funds on NEAR.

**The question's stated mechanism is partially wrong**: it claims the error fires *before* `use_nonce`. In reality `use_nonce` is called *first* (lines 91–99), and the overflow fires *after* (lines 114/134). The nonce is not permanently consumed only because Solana rolls back the entire transaction on error — not because the check precedes `use_nonce`.

---

### Finding Description

`FinalizeTransferPayload` carries `amount: u128`: [1](#0-0) [2](#0-1) 

`FinalizeTransfer::process` calls `use_nonce` first, then attempts the narrowing cast: [3](#0-2) [4](#0-3) [5](#0-4) 

The same pattern exists in `FinalizeTransferSol::process`: [6](#0-5) 

On the NEAR side, `sign_transfer` normalizes the amount to `u128` and places it directly into the MPC-signed payload with **no check that the result fits in `u64`**: [7](#0-6) 

`normalize_amount` is pure floor-division returning `u128`: [8](#0-7) 

There is no `require!(amount_to_transfer <= u64::MAX as u128, ...)` guard anywhere in the signing path.

---

### Impact Explanation

If a user initiates a transfer whose normalized Solana-side amount exceeds `u64::MAX`:

1. NEAR locks the funds and MPC signs the payload.
2. Every call to `finalize_transfer` on Solana returns `AmountOverflow` (error code 6010, confirmed by the existing test).
3. Solana's transaction atomicity rolls back `use_nonce`, so the nonce is never consumed.
4. The transfer is permanently unfinalizeable; there is no NEAR-side timeout or refund path visible in the contract.
5. User funds are permanently frozen on NEAR.

This matches the Critical scope: *permanent freezing of bridged funds*.

---

### Likelihood Explanation

For a token with 18 origin decimals and 9 Solana decimals, normalization divides by 10⁹. Overflow requires a normalized amount > ~1.8 × 10¹⁹, meaning an original balance > ~1.8 × 10²⁸ base units (~18 billion tokens). For tokens with equal decimals on both sides (e.g., 9/9), the threshold is the same in token units. This is a very large amount for most tokens, making the likelihood low in practice. However, for high-supply tokens (meme coins, governance tokens with quadrillions of supply) or tokens where `origin_decimals == decimals` and supply is large, the threshold is reachable. No attacker action is required — a legitimate large transfer by the token holder suffices.

---

### Recommendation

Add a guard in `sign_transfer` (NEAR side) before MPC signing:

```rust
require!(
    amount_to_transfer <= u64::MAX as u128,
    BridgeError::AmountExceedsSolanaMax
);
```

Alternatively, add the check in `FinalizeTransfer::process` *before* `use_nonce` so that a bad payload is rejected without consuming any state, and ensure NEAR emits a refund event in that case.

---

### Proof of Concept

The existing test already confirms the failure path: [9](#0-8) 

To confirm permanent lock: call `finalize_transfer` with `amount = u64::MAX + 1`, observe `ProgramResult::Failure(ProgramError::Custom(6010))`, then verify the nonce account bit remains unset (rolled back). Repeat the call — it fails identically every time. No NEAR-side refund is triggered.

### Citations

**File:** near/omni-types/src/lib.rs (L1-1)
```rust
use std::string::ToString;
```

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

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L91-99)
```rust
        UsedNonces::use_nonce(
            data.destination_nonce,
            &self.used_nonces,
            &mut self.config,
            self.authority.to_account_info(),
            self.common.payer.to_account_info(),
            &Rent::get()?,
            self.system_program.to_account_info(),
        )?;
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L114-114)
```rust
                data.amount.try_into().map_err(|_| error!(ErrorCode::AmountOverflow))?,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L134-134)
```rust
                data.amount.try_into().map_err(|_| error!(ErrorCode::AmountOverflow))?,
```

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer_sol.rs (L69-89)
```rust
        UsedNonces::use_nonce(
            data.destination_nonce,
            &self.used_nonces,
            &mut self.config,
            self.authority.to_account_info(),
            self.common.payer.to_account_info(),
            &Rent::get()?,
            self.system_program.to_account_info(),
        )?;

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

**File:** near/omni-bridge/src/lib.rs (L475-496)
```rust
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );

        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );

        let message = DestinationChainMsg::from_json(&transfer_message.msg)
            .and_then(|s| s.destination_msg())
            .unwrap_or_default();

        let transfer_payload = TransferMessagePayload {
            prefix: PayloadType::TransferMessage,
            destination_nonce: transfer_message.destination_nonce,
            transfer_id,
            token_address,
            amount: U128(amount_to_transfer),
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```

**File:** solana/programs/bridge_token_factory/tests/mollusk/test_finalize_transfer_sol.rs (L212-223)
```rust
#[test]
fn finalize_transfer_sol_amount_overflow() {
    // Amount > u64::MAX can't be converted for SOL transfer
    let result = run_finalize_transfer_sol(TestParams {
        amount: u128::from(u64::MAX) + 1,
        ..Default::default()
    });

    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::Custom(6010))
    );
```
