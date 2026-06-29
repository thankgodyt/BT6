The code confirms all key claims. Let me verify the critical details:

1. **`normalize_amount`** (lines 2784-2787): Floor division confirmed. The developer comment at line 2781-2783 explicitly states: *"When fee = 0, dust stays locked/burned. See SECURITY.md for details."* — but SECURITY.md contains no such exclusion or documentation of this behavior.

2. **`init_transfer`** (lines 554-557): Only `fee < amount` is checked. No normalized-amount pre-validation.

3. **`sign_transfer`** (lines 482-485): The `amount_to_transfer > 0` guard will always revert for a dust transfer.

4. **`cancel_transfer`**: Zero matches anywhere in the repository. No recovery path exists.

5. The developer comment distinguishes *remainder* dust (fractional truncation from a valid transfer) from the case where the *entire* amount normalizes to zero — the latter is the vulnerability scenario and is not covered by the comment's "dust stays locked/burned" acknowledgment.

---

Audit Report

## Title
Missing Pre-Validation of Normalized Transfer Amount Permanently Locks User Funds - (File: near/omni-bridge/src/lib.rs)

## Summary
The `init_transfer` function locks user tokens without verifying that the normalized transfer amount (after decimal scaling) is greater than zero. For tokens with a large decimal gap (e.g., `origin_decimals=24` on NEAR, `decimals=18` on EVM), any amount below `10^6` base units normalizes to zero via floor division. The transfer is stored and tokens are locked, but the subsequent `sign_transfer` call always reverts on the zero-amount guard, and no `cancel_transfer` or refund path exists anywhere in the contract.

## Finding Description
`normalize_amount` uses floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

`init_transfer` only validates `fee < amount` before storing the transfer and locking tokens:

```rust
require!(
    transfer_message.fee.fee < transfer_message.amount,
    BridgeError::InvalidFee.as_ref()
);
``` [2](#0-1) 

When a relayer later calls `sign_transfer`, the zero-amount guard fires and reverts:

```rust
require!(
    amount_to_transfer > 0,
    BridgeError::InvalidAmountToTransfer.as_ref()
);
``` [3](#0-2) 

No `cancel_transfer` function exists anywhere in the codebase. The `pending_transfers` entry persists indefinitely with no user-accessible removal path. [4](#0-3) 

The developer comment at line 2781 acknowledges dust locking for *remainder* truncation but does not cover the case where the entire amount normalizes to zero, and SECURITY.md contains no exclusion for this scenario. [5](#0-4) 

## Impact Explanation
Any user who initiates a NEAR→EVM transfer with an amount below the decimal scaling threshold has their tokens permanently frozen in the bridge contract. The transfer can never be signed or finalized, and no refund path exists. This constitutes **permanent freezing of bridged funds**, matching the Critical allowed impact scope.

## Likelihood Explanation
The `ft_transfer_call` entry point is fully public and requires no special privileges. The condition is triggered by any user bridging a token with a non-trivial decimal gap (common for NEAR-native tokens going to EVM chains) who sends an amount below the scaling threshold — including UI rounding errors or small test transfers. No attacker action is required; a well-meaning user is sufficient.

## Recommendation
Add a pre-validation check inside `init_transfer` (or at the start of `init_transfer_internal`) that computes `normalize_amount(amount - fee, decimals)` and requires it to be greater than zero before storing the transfer message and locking tokens. This mirrors the guard already present in `sign_transfer` but must be enforced at deposit time to prevent irrecoverable locking.

## Proof of Concept
1. Register a token with `origin_decimals=24` on NEAR and `decimals=18` on Ethereum (scaling factor = `10^6`).
2. User calls `ft_transfer_call` on the token contract with `amount=500_000`, `fee=0`, targeting the bridge with an `InitTransfer` message to an Ethereum recipient.
3. `init_transfer` passes the `fee < amount` check (`0 < 500_000`), stores the `TransferMessage`, and locks 500,000 base units.
4. A relayer calls `sign_transfer` for this transfer ID.
5. `normalize_amount(500_000, Decimals { origin_decimals: 24, decimals: 18 })` returns `500_000 / 1_000_000 = 0`.
6. `require!(amount_to_transfer > 0, ...)` panics; the call reverts.
7. No `cancel_transfer` exists; the 500,000 tokens are permanently locked.

### Citations

**File:** near/omni-bridge/src/lib.rs (L482-485)
```rust
        require!(
            amount_to_transfer > 0,
            BridgeError::InvalidAmountToTransfer.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L523-557)
```rust
    fn init_transfer(
        &mut self,
        sender_id: AccountId,
        signer_id: AccountId,
        token_id: AccountId,
        amount: U128,
        init_transfer_msg: InitTransferMsg,
    ) -> PromiseOrPromiseIndexOrValue<U128> {
        require!(
            init_transfer_msg.recipient.get_chain() != ChainKind::Near,
            BridgeError::InvalidRecipientChain.as_ref()
        );

        self.current_origin_nonce += 1;
        let destination_nonce =
            self.get_next_destination_nonce(init_transfer_msg.get_destination_chain());

        let transfer_message = TransferMessage {
            origin_nonce: self.current_origin_nonce,
            token: OmniAddress::Near(token_id),
            amount,
            recipient: init_transfer_msg.recipient,
            fee: Fee {
                fee: init_transfer_msg.fee,
                native_fee: init_transfer_msg.native_token_fee,
            },
            sender: OmniAddress::Near(sender_id),
            msg: init_transfer_msg.msg.map(String::from).unwrap_or_default(),
            destination_nonce,
            origin_transfer_id: None,
        };
        require!(
            transfer_message.fee.fee < transfer_message.amount,
            BridgeError::InvalidFee.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L2781-2783)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
```

**File:** near/omni-bridge/src/lib.rs (L2784-2787)
```rust
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
