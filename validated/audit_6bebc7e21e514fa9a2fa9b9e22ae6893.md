### Title
Permanent Irrecoverable Dust Loss from Decimal Normalization When Fee Is Zero — (File: near/omni-bridge/src/lib.rs)

---

### Summary

The bridge's `normalize_amount` function uses floor division when converting token amounts between chains with different decimal precisions. The truncated sub-unit remainder ("dust") is permanently locked or burned when the user sets `fee = 0`, with no recovery mechanism. Users are not informed of this behavior. This is a direct analog to the Yearn vault pitfall: the bridge abstracts over multiple chains with different decimal precisions, but the implementation detail of floor-division truncation leaks through, causing a silent, irrecoverable loss.

---

### Finding Description

`normalize_amount` at line 2784 performs integer floor division:

```rust
fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
    let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
    amount / (10_u128.pow(diff_decimals))
}
``` [1](#0-0) 

The code comment explicitly acknowledges the dust loss and states "See SECURITY.md for details," but `SECURITY.md` contains no such details — it is a generic bug bounty exclusion list with no mention of decimal normalization dust.

In `sign_transfer`, the normalized (dust-stripped) amount is what gets signed and sent to the destination chain:

```rust
let amount_to_transfer = Self::normalize_amount(
    transfer_message.amount_without_fee().near_expect(BridgeError::InvalidFee),
    decimals,
);
``` [2](#0-1) 

The critical branching point is in `sign_transfer_callback`:

```rust
if fee.is_zero() {
    self.remove_transfer_message(message_payload.transfer_id);
}
``` [3](#0-2) 

When `fee > 0`, the transfer message is **kept** until `claim_fee_callback` is called. There, the dust is computed as:

```rust
let fee = transfer_message.amount.0 - denormalized_amount;
self.send_fee_internal(&transfer_message, fee_recipient, fee)
``` [4](#0-3) 

So when `fee > 0`, the dust is recovered — but it goes to the **fee recipient (relayer)**, not the user. When `fee = 0`, the transfer message is deleted immediately after signing, and the dust is **permanently stranded**: locked forever in the bridge escrow for native tokens, or burned without a corresponding mint for deployed bridge tokens. There is no code path that ever returns this dust to the user.

The full amount (including dust) is locked/burned at `init_transfer_internal`:

```rust
self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);
self.lock_tokens_if_needed(transfer_message.get_destination_chain(), &token_id, transfer_message.amount.0);
``` [5](#0-4) 

But only the normalized (dust-stripped) amount is ever transferred to the destination chain.

---

### Impact Explanation

Every user who initiates a NEAR → foreign-chain transfer with `fee = 0` on a token whose NEAR decimal count exceeds the destination chain's decimal count silently and permanently loses the sub-unit remainder. For the common case of a 24-decimal NEAR token bridged to an 18-decimal EVM token, the maximum dust per transfer is `10^6 − 1 = 999,999` base units (i.e., up to `0.000001` of the token in human-readable terms). This dust is irrecoverable: it is either locked in the bridge contract forever or burned with no corresponding mint. The loss is small per transfer but is guaranteed, permanent, and completely invisible to the user. This matches the "decimal/normalization abuse that changes user or protocol balances" impact class.

---

### Likelihood Explanation

High. The most common bridging scenario is NEAR (24 decimals) → EVM (18 decimals). Any user who sends an amount that is not a multiple of `10^6` base units and sets `fee = 0` will experience this loss. Zero-fee transfers are a normal, supported user choice — the bridge explicitly allows `fee = 0` and the `sign_transfer_callback` handles it as a first-class case. No special conditions or attacker involvement are required; the loss is triggered by the ordinary `ft_on_transfer` → `init_transfer` → `sign_transfer` flow.

---

### Recommendation

1. **Short term:** Document the dust loss prominently in user-facing materials. Specifically, inform users that when `fee = 0` and the token has more decimals on NEAR than on the destination chain, the sub-unit remainder is permanently lost. Recommend users either set a non-zero fee (so the dust is at least recoverable via `claim_fee`) or ensure their transfer amount is a multiple of `10^(origin_decimals − dest_decimals)`.

2. **Long term:** Consider refunding the dust to the sender when `fee = 0` instead of leaving it stranded. Alternatively, enforce that `amount_without_fee` must be divisible by the normalization factor before accepting the transfer, so users receive an explicit error rather than a silent loss.

---

### Proof of Concept

1. Token: NEAR-native token with `origin_decimals = 24`, deployed on EVM with `decimals = 18`.
2. User calls `ft_transfer_call` sending `amount = 1_000_001` base units with `msg` containing `fee = 0`.
3. `init_transfer_internal` locks/burns the full `1_000_001` units.
4. Relayer calls `sign_transfer`.
5. `normalize_amount(1_000_001, {decimals:18, origin_decimals:24})` = `1_000_001 / 1_000_000` = **`1`** (floor division; dust = 1 unit).
6. MPC signs a payload for `amount = 1` on the destination chain.
7. `sign_transfer_callback` sees `fee.is_zero() == true` → calls `remove_transfer_message`, deleting the pending transfer record.
8. The 1 dust unit remains locked in the bridge contract (or burned) with no code path to recover it.
9. User receives `1` unit on the EVM chain; the `1` dust unit is gone forever.
10. The user was never informed this would happen; `SECURITY.md` contains no mention of this behavior despite the code comment at line 2782 claiming it does. [1](#0-0) [6](#0-5) [2](#0-1) [4](#0-3)

### Citations

**File:** near/omni-bridge/src/lib.rs (L475-480)
```rust
        let amount_to_transfer = Self::normalize_amount(
            transfer_message
                .amount_without_fee()
                .near_expect(BridgeError::InvalidFee),
            decimals,
        );
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

**File:** near/omni-bridge/src/lib.rs (L1128-1133)
```rust
        // Fee includes both the user-specified fee and any dust lost during decimal
        // normalization (see `normalize_amount`). Since `denormalize(normalize(x)) <= x`
        // due to floor division, the difference naturally captures the normalization remainder.
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```

**File:** near/omni-bridge/src/lib.rs (L1850-1857)
```rust
        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
```

**File:** near/omni-bridge/src/lib.rs (L2781-2787)
```rust
    /// Uses floor division — any sub-unit remainder ("dust") is truncated and not transferred
    /// to the destination chain. When fee > 0, dust is absorbed into the fee via `claim_fee`.
    /// When fee = 0, dust stays locked/burned. See SECURITY.md for details.
    fn normalize_amount(amount: u128, decimals: Decimals) -> u128 {
        let diff_decimals: u32 = (decimals.origin_decimals - decimals.decimals).into();
        amount / (10_u128.pow(diff_decimals))
    }
```
