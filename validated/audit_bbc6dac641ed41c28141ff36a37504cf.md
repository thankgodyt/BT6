Audit Report

## Title
Unconstrained `fee_recipient` in `sign_transfer` Allows Any Trusted Relayer to Steal Relayer Fees - (File: near/omni-bridge/src/lib.rs)

## Summary
The `sign_transfer` function accepts a fully caller-controlled `fee_recipient: Option<AccountId>` parameter that is embedded verbatim into the MPC-signed payload with no validation against the caller's identity. Because any active trusted relayer may call `sign_transfer` on any pending transfer, a malicious trusted relayer can front-run the legitimate relayer, inject their own account as `fee_recipient`, obtain a valid MPC signature, submit it to the destination chain first, and permanently claim the fee that was intended for the legitimate relayer.

## Finding Description
In `near/omni-bridge/src/lib.rs`, `sign_transfer` is gated by `#[trusted_relayer]` but that macro only verifies the caller is an active trusted relayer — it imposes no constraint on which relayer may act on which transfer, and no constraint on the `fee_recipient` argument:

```rust
pub fn sign_transfer(
    &mut self,
    transfer_id: TransferId,
    fee_recipient: Option<AccountId>,   // fully caller-controlled
    fee: &Option<Fee>,
) -> Promise {
``` [1](#0-0) 

The `fee_recipient` value is placed directly into `TransferMessagePayload` with no check against `env::predecessor_account_id()`:

```rust
let transfer_payload = TransferMessagePayload {
    ...
    fee_recipient,   // no validation
    ...
};
``` [2](#0-1) 

The resulting hash is signed by the MPC network and the signature is emitted as an event via `sign_transfer_callback`: [3](#0-2) 

On the EVM side, `finTransfer` marks the destination nonce as consumed on the first valid submission, making any competing signature permanently unusable. On the NEAR side, `claim_fee_callback` enforces that only the account named as `fee_recipient` in the on-chain proof can claim the fee:

```rust
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
``` [4](#0-3) 

Because the `fee_recipient` in the proof is whatever the attacker injected into the signed payload, the attacker is the only one who can claim the fee, and the legitimate relayer's competing signature is permanently rejected.

Additionally, when `fee` is passed as `None`, no fee-amount validation is performed at all: [5](#0-4) 

## Impact Explanation
This is a concrete fee mis-accounting impact: a malicious trusted relayer can redirect the relayer fee from any pending outgoing transfer (NEAR → EVM / Solana / Starknet) to themselves. The user's principal is delivered correctly, but the fee — which can be a meaningful fraction of the transfer amount — is permanently stolen. This falls squarely within the Critical impact class: "fee mis-accounting... that changes user or protocol balances."

## Likelihood Explanation
Becoming a trusted relayer requires staking 1,000 NEAR and waiting ~7 days (`waiting_period_ns` default ~604,800,000,000,000 ns): [6](#0-5) 

Once that barrier is cleared, the attack is mechanical and repeatable: monitor `pending_transfers`, call `sign_transfer(transfer_id, Some(attacker_account), None)` on every transfer before the legitimate relayer, and submit the resulting MPC signature to the destination chain. No additional privilege or secret is required beyond being an active trusted relayer.

## Recommendation
Enforce that `fee_recipient`, when provided, equals `env::predecessor_account_id()`. Alternatively, remove the parameter entirely and derive the fee recipient from the caller's account ID inside the function body, eliminating the attack surface entirely. The analogous UTXO path in `submit_transfer_to_utxo_chain_connector` already applies a safe default:

```rust
let fee_recipient = fee_recipient.unwrap_or(env::predecessor_account_id());
``` [7](#0-6) 

The same pattern should be applied in `sign_transfer`, with an additional `require!` that any explicitly provided value equals `env::predecessor_account_id()`.

## Proof of Concept
1. Legitimate relayer R1 expects to earn fee `F` on pending transfer `T` (NEAR → EVM).
2. Malicious trusted relayer R2 calls `sign_transfer(T.transfer_id, Some(R2_account), None)` before R1.
3. MPC signs a `TransferMessagePayload` with `fee_recipient = R2_account`.
4. R2 submits the signature to the EVM `OmniBridge.finTransfer`; the destination nonce is marked consumed.
5. R1's subsequent `sign_transfer` call produces a valid MPC signature, but when R1 submits it to the EVM bridge, the call reverts with `NonceAlreadyUsed`.
6. R2 calls `claim_fee` on NEAR with a proof of the EVM `FinTransfer` event (which names `fee_recipient = R2_account`).
7. `claim_fee_callback` confirms `fee_recipient == predecessor_account_id` (both are R2) and transfers fee `F` to R2.
8. R1 receives nothing; the fee is permanently lost to R2.

A local integration test can reproduce this by deploying two trusted relayer accounts, initiating a transfer, having R2 call `sign_transfer` with `fee_recipient = R2`, submitting the signature, and verifying that R1's subsequent claim attempt fails while R2's succeeds.

### Citations

**File:** near/omni-bridge/src/lib.rs (L444-452)
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
```

**File:** near/omni-bridge/src/lib.rs (L455-460)
```rust
        if let Some(fee) = &fee {
            require!(
                &transfer_message.fee == fee,
                BridgeError::InvalidFee.as_ref()
            );
        }
```

**File:** near/omni-bridge/src/lib.rs (L491-500)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L648-668)
```rust
    #[private]
    pub fn sign_transfer_callback(
        &mut self,
        #[callback_result] call_result: Result<SignatureResponse, PromiseError>,
        #[serializer(borsh)] message_payload: TransferMessagePayload,
        #[serializer(borsh)] fee: &Fee,
    ) {
        if let Ok(signature) = call_result {
            if fee.is_zero() {
                self.remove_transfer_message(message_payload.transfer_id);
            }

            env::log_str(
                &OmniBridgeEvent::SignTransferEvent {
                    signature,
                    message_payload,
                }
                .to_log_string(),
            );
        }
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

**File:** near/omni-bridge/src/btc.rs (L86-86)
```rust
        let fee_recipient = fee_recipient.unwrap_or(env::predecessor_account_id());
```
