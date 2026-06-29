### Title
Any Trusted Relayer Can Steal Another Relayer's Fee by Setting Arbitrary `fee_recipient` in `sign_transfer` - (File: `near/omni-bridge/src/lib.rs`)

### Summary
The `sign_transfer` function accepts a caller-controlled `fee_recipient: Option<AccountId>` parameter with no binding to the caller's identity. Any trusted relayer can call `sign_transfer` on any pending transfer and designate any account — including their own — as the fee recipient, stealing the fee from the legitimate relayer who performed the bridging work.

### Finding Description
`sign_transfer` is gated by `#[trusted_relayer]` but is otherwise callable by **any** trusted relayer on **any** pending `TransferMessage`. The `fee_recipient` argument is passed directly into the `TransferMessagePayload` that the MPC network signs: [1](#0-0) 

The signed payload permanently encodes `fee_recipient` as the sole account authorized to later call `claim_fee`. In `claim_fee_callback`, the only identity check is: [2](#0-1) 

There is no check that `fee_recipient` equals `env::predecessor_account_id()` at the time of `sign_transfer`, and no check that the caller of `sign_transfer` is the same relayer who is designated as `fee_recipient`. The `TransferMessage` is not removed after signing when the fee is non-zero: [3](#0-2) 

This means the window for a competing trusted relayer to race in and sign with their own `fee_recipient` remains open until `claim_fee` is successfully called.

The `FastFinTransferMsg` struct also carries a caller-controlled `relayer: AccountId` field: [4](#0-3) 

This `relayer` field is stored verbatim in `FastTransferStatus` and is later used to repay the fast-transfer fronter when the slow proof arrives. A trusted relayer executing a fast transfer can set `relayer` to any account, misdirecting the repayment.

### Impact Explanation
A malicious trusted relayer observes a pending `TransferMessage` on-chain (all state is public), races to call `sign_transfer` with `fee_recipient` set to their own account, obtains the MPC signature, and then calls `claim_fee` to collect the fee. The legitimate relayer who monitored the source chain and initiated the transfer receives nothing. This constitutes direct fee theft — a fee mis-accounting that changes relayer balances and undermines the economic incentive model of the bridge.

### Likelihood Explanation
The attack requires the attacker to be a registered trusted relayer (requires staking per `apply_for_trusted_relayer`), but once that threshold is met, the attack is trivially repeatable on every pending transfer. All pending transfers are publicly readable from contract state. No mempool monitoring is needed — the attacker simply polls `pending_transfers` and races to call `sign_transfer` before the legitimate relayer does. [5](#0-4) 

### Recommendation
Bind `fee_recipient` to the caller's identity inside `sign_transfer`: replace the free `fee_recipient: Option<AccountId>` parameter with `Some(env::predecessor_account_id())`, or at minimum add a `require!(fee_recipient == env::predecessor_account_id())` guard. This ensures only the relayer who actually calls `sign_transfer` can designate themselves as the beneficiary, eliminating the race condition.

### Proof of Concept
1. User calls `ft_transfer_call` → `ft_on_transfer` → `init_transfer`, creating a `TransferMessage` with `fee = 1000` stored in `pending_transfers` under `transfer_id = T`.
2. Legitimate Relayer A observes `T` and prepares to call `sign_transfer(T, fee_recipient=A, fee)`.
3. Malicious Trusted Relayer B (also a registered trusted relayer) observes `T` on-chain and calls `sign_transfer(T, fee_recipient=B, fee)` first.
4. MPC signs the `TransferMessagePayload` with `fee_recipient=B` encoded inside.
5. B submits the signed payload to the destination chain (EVM/Solana/etc.), completing the transfer.
6. B calls `claim_fee` on NEAR with a proof of the destination-chain finalization; `claim_fee_callback` verifies `fee_recipient(=B) == predecessor_account_id(=B)` ✓ and sends the 1000-token fee to B.
7. Relayer A's subsequent `sign_transfer` call either produces a second MPC signature (which cannot be used to claim fee again since `remove_transfer_message` already ran) or fails — A earns nothing. [6](#0-5) [7](#0-6)

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

**File:** near/omni-bridge/src/lib.rs (L1079-1086)
```rust
        let fee_recipient = fin_transfer.fee_recipient.unwrap_or_else(|| {
            env::panic_str(BridgeError::FeeRecipientNotSetOrEmpty.to_string().as_str());
        });

        require!(
            fee_recipient == *predecessor_account_id,
            BridgeError::OnlyFeeRecipientCanClaim.as_ref()
        );
```

**File:** near/omni-types/src/lib.rs (L504-513)
```rust
#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct FastFinTransferMsg {
    pub transfer_id: UnifiedTransferId,
    pub recipient: OmniAddress,
    pub fee: Fee,
    pub msg: String,
    pub amount: U128,
    pub storage_deposit_amount: Option<U128>,
    pub relayer: AccountId,
}
```
