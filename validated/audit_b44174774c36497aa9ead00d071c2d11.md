### Title
`claim_fee` Gated by `#[trusted_relayer]` Creates Single Point of Failure for Fee Recovery - (File: `near/omni-bridge/src/lib.rs`)

### Summary

The `claim_fee` function in the NEAR Omni Bridge is decorated with `#[trusted_relayer]`, restricting callers to accounts that currently hold trusted-relayer status. Combined with the inner `require!(fee_recipient == *predecessor_account_id, ...)` check in `claim_fee_callback`, the only account that can ever trigger fee delivery is the specific relayer who originally set themselves as `fee_recipient` in the foreign-chain event — and only while they remain a trusted relayer. This mirrors the `collectFees` vulnerability: a single privileged account is the sole key to unlocking funds, and if that key is lost or revoked, the fees are permanently frozen in the bridge contract.

### Finding Description

`claim_fee` is declared as:

```rust
#[payable]
#[trusted_relayer]
#[pause(except(roles(Role::DAO)))]
pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
``` [1](#0-0) 

The `#[trusted_relayer]` macro gates the entire function to accounts that currently hold trusted-relayer status. Inside `claim_fee_callback`, a second restriction is enforced:

```rust
require!(
    fee_recipient == *predecessor_account_id,
    BridgeError::OnlyFeeRecipientCanClaim.as_ref()
);
``` [2](#0-1) 

The `fee_recipient` is decoded from the submitted proof (the foreign-chain finalization event). The `predecessor_account_id` is the original caller of `claim_fee`. Together, these two checks mean:

- **Only** the exact NEAR account encoded as `fee_recipient` in the foreign-chain proof can call `claim_fee`.
- That account **must also** currently be a trusted relayer at the time of the call.

A relayer who submitted a transfer on a foreign chain and set themselves as `fee_recipient` can lose the ability to claim their earned fees if:
1. They unstake or their staking period expires (losing `#[trusted_relayer]` status), or
2. They lose access to their NEAR account.

In either case, no other account — not even the DAO or another trusted relayer — can trigger fee delivery, because the `fee_recipient == predecessor_account_id` check would reject them. The fee tokens remain locked in the bridge contract indefinitely.

### Impact Explanation

Fees earned by relayers are locked in the bridge contract permanently if the fee_recipient loses trusted-relayer status or account access. The fee amount is the difference between the amount locked on the foreign chain and the amount delivered to the recipient:

```rust
let fee = transfer_message.amount.0 - denormalized_amount;
self.send_fee_internal(&transfer_message, fee_recipient, fee)
``` [3](#0-2) 

This constitutes permanent freezing of bridged funds (the fee portion) in the bridge contract, matching the Critical/Medium impact class of the analog report.

### Likelihood Explanation

Trusted-relayer status is tied to staking. A relayer who completes a transfer and then unstakes (a normal lifecycle event) immediately loses the ability to claim fees for transfers they already finalized. This is a realistic, non-adversarial scenario that can occur in normal protocol operation. No attacker action is required — the relayer simply needs to unstake before claiming.

### Recommendation

Remove the `#[trusted_relayer]` attribute from `claim_fee`. The fee destination is fixed by the cryptographically verified proof (the `fee_recipient` field in the foreign-chain event), so allowing any caller to trigger fee delivery does not create a security risk — the funds will always be routed to the address encoded in the proof. This mirrors the fix applied in PR 315 of the referenced audit: remove the overly strict caller restriction so that anyone can trigger fee delivery at any time.

Optionally, also relax the `fee_recipient == predecessor_account_id` check to allow any caller to trigger delivery to the proof-encoded `fee_recipient`, enabling third-party "fee sweepers" to unblock stuck fees on behalf of relayers.

### Proof of Concept

1. Relayer R submits a finalization proof on a foreign chain, setting their NEAR account as `fee_recipient`. The transfer is stored in the bridge with a fee balance.
2. R unstakes from the relayer staking contract, losing `#[trusted_relayer]` status.
3. R calls `claim_fee` with the valid proof — the call is rejected by `#[trusted_relayer]` before even reaching the proof verification or fee-recipient check.
4. No other account can call `claim_fee` successfully: any trusted relayer T who tries will pass the `#[trusted_relayer]` gate but fail at `require!(fee_recipient == *predecessor_account_id)` since T ≠ R.
5. The fee is permanently locked in the bridge contract. [4](#0-3)

### Citations

**File:** near/omni-bridge/src/lib.rs (L1054-1086)
```rust
    #[payable]
    #[trusted_relayer]
    #[pause(except(roles(Role::DAO)))]
    pub fn claim_fee(&mut self, #[serializer(borsh)] args: ClaimFeeArgs) -> Promise {
        self.verify_proof(args.chain_kind, args.prover_args).then(
            Self::ext(env::current_account_id())
                .with_attached_deposit(env::attached_deposit())
                .with_static_gas(CLAIM_FEE_CALLBACK_GAS)
                .claim_fee_callback(&env::predecessor_account_id()),
        )
    }

    #[private]
    #[payable]
    pub fn claim_fee_callback(
        &mut self,
        #[serializer(borsh)] predecessor_account_id: &AccountId,
        #[callback_result]
        #[serializer(borsh)]
        call_result: Result<ProverResult, PromiseError>,
    ) -> PromiseOrValue<()> {
        let Ok(ProverResult::FinTransfer(fin_transfer)) = call_result else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };

        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
```

**File:** near/omni-bridge/src/lib.rs (L1131-1133)
```rust
        let fee = transfer_message.amount.0 - denormalized_amount;

        self.send_fee_internal(&transfer_message, fee_recipient, fee)
```
