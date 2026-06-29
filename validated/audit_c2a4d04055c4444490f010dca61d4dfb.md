Based on my code review, all technical claims in the submission are verified against the actual codebase. Here is my assessment:

**Code verification:**

- `FinalizeTransferPayload.amount: u128` confirmed. [1](#0-0) 
- `use_nonce` is called at lines 91–99, *before* the `try_into()` cast at lines 114 and 134. The submission's correction of the execution order is accurate. [2](#0-1) 
- The overflow cast at line 114 and 134 fires after `use_nonce`, but Solana atomicity rolls back the entire transaction on error, so the nonce bit is not permanently consumed. [3](#0-2) 
- `normalize_amount` is pure floor-division returning `u128` with no `u64::MAX` bound check. [4](#0-3) 
- `sign_transfer` only checks `amount_to_transfer > 0`, not `<= u64::MAX`. [5](#0-4) 
- The existing test `finalize_transfer_sol_amount_overflow` confirms `ProgramError::Custom(6010)` for `amount = u64::MAX + 1`. [6](#0-5) 
- The same pattern exists in `FinalizeTransferSol::process`. [7](#0-6) 

---

Audit Report

## Title
Permanent Fund Freeze via u128→u64 Overflow in `FinalizeTransfer::process` with No NEAR-Side Guard — (`solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs`)

## Summary
`FinalizeTransferPayload.amount` is typed as `u128`, but Solana SPL token operations require `u64`. When NEAR's `sign_transfer` normalizes and MPC-signs a payload whose amount exceeds `u64::MAX`, every Solana finalization attempt returns `AmountOverflow` (error 6010). Solana's transaction atomicity rolls back `use_nonce`, so the nonce is never consumed, but the transfer can never succeed. Because there is no NEAR-side timeout or refund path triggered by repeated Solana-side failures, the user's funds are permanently frozen on NEAR.

## Finding Description
`FinalizeTransferPayload` carries `amount: u128`. In `FinalizeTransfer::process`, `UsedNonces::use_nonce` is called first (lines 91–99), then `data.amount.try_into()` is attempted at lines 114 and 134. If `data.amount > u64::MAX`, the cast fails with `ErrorCode::AmountOverflow`, the transaction reverts (rolling back the nonce bit), and the instruction returns an error. The same pattern exists in `FinalizeTransferSol::process` at line 88.

On the NEAR side, `sign_transfer` calls `normalize_amount` (pure floor-division returning `u128`) and places the result directly into the MPC-signed `TransferMessagePayload` with only a `> 0` check — no `<= u64::MAX` guard. Once MPC signs the payload, the signed amount is immutable. Every subsequent call to `finalize_transfer` on Solana will fail identically. No NEAR-side mechanism triggers a refund or unlock based on Solana-side finalization failure.

## Impact Explanation
This matches the Critical scope item: *permanent freezing of bridged funds*. A user whose transfer produces a normalized amount exceeding `u64::MAX` has their funds locked on NEAR with no recovery path. The transfer is signed by MPC with an amount that Solana can never accept, and NEAR has no timeout or failure-callback mechanism to release the locked tokens.

## Likelihood Explanation
For overflow, the normalized Solana-side amount must exceed `u64::MAX` (~1.84 × 10¹⁹). For tokens with equal decimals on both sides (e.g., 9/9 or 18/18), `normalize_amount` divides by 1, so the threshold is `u64::MAX` in raw base units. High-supply tokens (meme coins, governance tokens with quadrillion-scale supplies) can have individual holders with balances exceeding this threshold. No attacker action is required — a legitimate large transfer by the token holder suffices. Likelihood is low in practice but non-negligible for specific token classes.

## Recommendation
Add a guard in `sign_transfer` on the NEAR side before MPC signing:
```rust
require!(
    amount_to_transfer <= u64::MAX as u128,
    BridgeError::AmountExceedsSolanaMax
);
```
This rejects the transfer before funds are locked and before MPC signs an unfinalizeable payload. Alternatively, add the check in `FinalizeTransfer::process` before `use_nonce` and ensure NEAR emits a refund event on rejection, but the NEAR-side guard is preferable as it prevents the lock entirely.

## Proof of Concept
The existing test `finalize_transfer_sol_amount_overflow` already demonstrates the failure path: passing `amount = u64::MAX + 1` produces `ProgramResult::Failure(ProgramError::Custom(6010))`. To confirm permanent lock: (1) call `finalize_transfer` with `amount = u64::MAX + 1`, observe error 6010, verify the nonce account bit is unset (rolled back); (2) repeat the call — it fails identically every time; (3) verify no NEAR-side refund event is emitted. The test at `solana/programs/bridge_token_factory/tests/mollusk/test_finalize_transfer_sol.rs:212–223` serves as the reproducible proof.

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

**File:** solana/programs/bridge_token_factory/src/instructions/user/finalize_transfer.rs (L114-134)
```rust
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
```

**File:** near/omni-bridge/src/lib.rs (L482-485)
```rust
        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
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
