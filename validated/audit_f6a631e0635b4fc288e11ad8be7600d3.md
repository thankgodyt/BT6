### Title
Fee Sniping via Unrestricted `sign_transfer` — Any Trusted Relayer Can Claim Fees for Transfers They Did Not Initiate - (File: `near/omni-bridge/src/lib.rs`)

---

### Summary

`sign_transfer` in the NEAR omni-bridge contract allows **any** trusted relayer to sign **any** pending transfer and freely designate **any** account as `fee_recipient`. Because the transfer record is not removed or locked after signing when a fee is present, multiple trusted relayers can obtain independent, valid MPC signatures for the same transfer — each embedding a different `fee_recipient`. Whoever submits their signature to the destination chain first collects the full fee, enabling a malicious trusted relayer to systematically front-run legitimate relayers and steal their earned fees.

---

### Finding Description

`sign_transfer` is gated only by the `#[trusted_relayer]` macro, which verifies that the caller is *any* active trusted relayer. There is no binding between the caller and the specific pending transfer:

```rust
#[payable]
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn sign_transfer(
    &mut self,
    transfer_id: TransferId,
    fee_recipient: Option<AccountId>,   // ← fully caller-controlled
    fee: &Option<Fee>,
) -> Promise {
    let transfer_message = self.get_transfer_message(transfer_id);
    // No check: is env::predecessor_account_id() the relayer who submitted this transfer?
    ...
    let transfer_payload = TransferMessagePayload {
        ...
        fee_recipient,   // ← embedded verbatim into the MPC-signed payload
        ...
    };
``` [1](#0-0) 

After the MPC signs the payload, `sign_transfer_callback` only removes the transfer record when the fee is **zero**:

```rust
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
``` [2](#0-1) 

When a fee is non-zero the transfer remains in `pending_transfers`, fully open for any other trusted relayer to call `sign_transfer` again with a different `fee_recipient`, obtaining a second valid MPC signature for the same transfer.

The `claim_fee` path on NEAR enforces `fee_recipient == predecessor_account_id`, but that check is satisfied by whoever holds the matching proof from the destination chain — i.e., whoever submitted their own signature first:

```rust
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
``` [3](#0-2) 

---

### Impact Explanation

A malicious trusted relayer (Relayer M) can:

1. Monitor `pending_transfers` on NEAR for transfers with large fees.
2. Call `sign_transfer(transfer_id, fee_recipient = M, fee)` before or concurrently with the legitimate relayer (Relayer L).
3. Obtain a valid MPC signature embedding `fee_recipient = M`.
4. Submit that signature to the destination chain (EVM / Solana / Starknet) before Relayer L.
5. Call `claim_fee` on NEAR with the resulting proof and collect the entire fee.

Relayer L's signature — and any gas spent on the destination chain — is wasted. The fee is mis-accounted: it flows to M instead of L. Because the transfer record is not locked after the first `sign_transfer`, this race is repeatable across every fee-bearing pending transfer, allowing M to drain the fee income of all competing relayers systematically.

This is fee mis-accounting that directly changes relayer (user) balances, matching the "Balance manipulation / fee mis-accounting" critical impact class.

---

### Likelihood Explanation

Becoming a trusted relayer requires staking 1,000 NEAR and waiting the `waiting_period_ns` (default ~7 days):

```rust
assert_eq!(config["stake_required"], json!(default_stake));          // 1000 NEAR
assert_eq!(config["waiting_period_ns"], json!(U64(604_800_000_000_000)));  // 7 days
``` [4](#0-3) 

Once that barrier is cleared, the attack requires only monitoring the public NEAR chain state and issuing `sign_transfer` calls — no special capability beyond being a trusted relayer. The attacker recovers their stake on resignation, so the net cost is only the opportunity cost of the locked NEAR plus MPC signing gas. For a bridge handling significant volume, the expected fee income far exceeds this cost, making the attack economically rational.

---

### Recommendation

1. **Lock the transfer after the first `sign_transfer`**: record the `fee_recipient` chosen by the first signer and reject subsequent `sign_transfer` calls for the same `transfer_id` unless the fee is zero.
2. **Alternatively, bind `fee_recipient` to `env::predecessor_account_id()`**: remove the caller-supplied `fee_recipient` parameter and always use the signing relayer's account, preventing redirection to arbitrary accounts.
3. **Remove the transfer record immediately on signing** (regardless of fee), relying on the destination-chain proof submitted via `claim_fee` to settle the fee, so no second signer can race.

---

### Proof of Concept

1. User initiates a NEAR → EVM transfer with `fee = 1000` tokens via `ft_transfer_call` → `init_transfer`.
2. Legitimate Relayer L calls `sign_transfer(transfer_id, fee_recipient = L, fee)` → MPC signs payload with `fee_recipient = L`. Transfer record **remains** in `pending_transfers` because `fee != 0`.
3. Malicious Relayer M (also trusted) calls `sign_transfer(transfer_id, fee_recipient = M, fee)` → MPC signs a second payload with `fee_recipient = M`. This succeeds because there is no lock and no ownership check.
4. M submits their signed payload to the EVM `OmniBridge` contract before L, finalising the transfer with `fee_recipient = M` in the emitted event.
5. M calls `claim_fee` on NEAR with the EVM proof. The check `fee_recipient == predecessor_account_id` passes for M. M receives 1000 tokens.
6. L's signature is now useless (the transfer is already finalised on EVM). L receives nothing.

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-500)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn sign_transfer(
        &mut self,
        transfer_id: TransferId,
        fee_recipient: Option<AccountId>,
        fee: &Option<Fee>,
    ) -> Promise {
        let transfer_message = self.get_transfer_message(transfer_id);

        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }

        let token_address = self
            .get_token_address(
                transfer_message.get_destination_chain(),
                self.get_token_id(&transfer_message.token),
            )
            .unwrap_or_else(|| {
                env::panic_str(BridgeError::FailedToGetTokenAddress.to_string().as_str())
            });

        let decimals = self
            .token_decimals
            .get(&token_address)
            .near_expect(BridgeError::TokenDecimalsNotFound);
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
            recipient: transfer_message.recipient,
            fee_recipient,
            message,
        };
```

**File:** near/omni-bridge/src/lib.rs (L655-658)
```rust
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }
```

**File:** near/omni-bridge/src/lib.rs (L1083-1086)
```rust
        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
```

**File:** near/omni-tests/src/relayer_staking.rs (L507-509)
```rust
        let default_stake = (1_000u128 * 10u128.pow(24)).to_string();
        assert_eq!(config["stake_required"], json!(default_stake));
        assert_eq!(config["waiting_period_ns"], json!(U64(604_800_000_000_000)));
```
