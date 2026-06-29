### Title
Any Trusted Relayer Can Redirect Fee to Arbitrary Account via Unconstrained `fee_recipient` in `sign_transfer` - (File: near/omni-bridge/src/lib.rs)

### Summary
The `sign_transfer` function accepts a fully caller-controlled `fee_recipient: Option<AccountId>` parameter that is embedded verbatim into the MPC-signed payload. Because any trusted relayer can call `sign_transfer` on any pending transfer, a malicious trusted relayer can front-run the legitimate relayer, inject their own account as `fee_recipient`, obtain a valid MPC signature, submit it to the destination chain, and claim the fee that was intended for the legitimate relayer.

### Finding Description
In `near/omni-bridge/src/lib.rs`, `sign_transfer` is decorated with `#[trusted_relayer]` but imposes no constraint on which trusted relayer may act on which pending transfer, and no constraint on the `fee_recipient` argument:

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
``` [1](#0-0) 

The `fee_recipient` value is placed directly into the `TransferMessagePayload` that is sent to the MPC signer with no validation:

```rust
let transfer_payload = TransferMessagePayload {
    ...
    fee_recipient,   // ← no check against env::predecessor_account_id()
    ...
};
``` [2](#0-1) 

The resulting hash is signed by the MPC network and the signature is emitted as an event: [3](#0-2) 

On the EVM side, `finTransfer` accepts any valid MPC-signed payload and marks the destination nonce as consumed, making it impossible for a competing signature to be accepted afterward: [4](#0-3) 

Later, `claim_fee_callback` enforces that only the account named as `fee_recipient` in the on-chain proof can claim the fee: [5](#0-4) 

Because the `fee_recipient` in the proof is whatever the attacker injected into the signed payload, the attacker is the only one who can claim the fee.

The `fee` parameter is also optional — if passed as `None`, no fee-amount validation is performed at all: [6](#0-5) 

### Impact Explanation
A malicious trusted relayer can steal the relayer fee from any pending outgoing transfer (NEAR → EVM / Solana / Starknet). The user's principal is delivered correctly, but the fee — which can be a meaningful fraction of the transfer amount — is redirected to the attacker. Because the EVM bridge marks the destination nonce consumed on the first valid submission, the legitimate relayer's competing signature is permanently rejected, and the legitimate relayer loses the fee with no recourse.

### Likelihood Explanation
Becoming a trusted relayer requires staking NEAR (`stake_required`, default 1 000 NEAR) and waiting through a `waiting_period_ns` (default ~7 days). [7](#0-6) 

Once that barrier is cleared, the attack is mechanical: monitor `pending_transfers`, call `sign_transfer` with `fee_recipient = attacker` on every transfer before the legitimate relayer, and submit the resulting signature to the destination chain. No additional privilege or secret is required.

### Recommendation
Enforce that `fee_recipient`, when provided, equals `env::predecessor_account_id()`. Alternatively, remove the parameter entirely and derive the fee recipient from the caller's account ID inside the function, eliminating the attack surface.

### Proof of Concept
1. Legitimate relayer R1 expects to earn fee `F` on pending transfer `T` (NEAR → EVM).
2. Malicious trusted relayer R2 calls `sign_transfer(T.transfer_id, Some(R2_account), None)` before R1.
3. MPC signs a `TransferMessagePayload` with `fee_recipient = R2_account`.
4. R2 submits the signature to the EVM `OmniBridge.finTransfer`; the nonce is marked consumed.
5. R1's subsequent `sign_transfer` call produces a valid signature, but when R1 tries to submit it to the EVM bridge, the call reverts with `NonceAlreadyUsed`.
6. R2 calls `claim_fee` on NEAR with a proof of the EVM `FinTransfer` event (which names `fee_recipient = R2_account`).
7. `claim_fee_callback` confirms `fee_recipient == predecessor_account_id` (both are R2) and transfers fee `F` to R2.
8. R1 receives nothing; the fee is permanently lost to R2.

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

**File:** near/omni-bridge/src/lib.rs (L502-520)
```rust
        let payload = near_sdk::env::keccak256_array(
            transfer_payload
                .encode_hashable()
                .near_expect(BridgeError::Borsh),
        );

        ext_signer::ext(self.mpc_signer.clone())
            .with_static_gas(MPC_SIGNING_GAS)
            .with_attached_deposit(env::attached_deposit())
            .sign(SignRequest {
                payload,
                path: SIGN_PATH.to_owned(),
                key_version: 0,
            })
            .then(
                Self::ext(env::current_account_id())
                    .with_static_gas(SIGN_TRANSFER_CALLBACK_GAS)
                    .sign_transfer_callback(transfer_payload, &transfer_message.fee),
            )
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L283-313)
```text
        if (completedTransfers[payload.destinationNonce]) {
            revert NonceAlreadyUsed(payload.destinationNonce);
        }

        completedTransfers[payload.destinationNonce] = true;

        bytes memory borshEncoded = bytes.concat(
            bytes1(uint8(BridgeTypes.PayloadType.TransferMessage)),
            Borsh.encodeUint64(payload.destinationNonce),
            bytes1(payload.originChain),
            Borsh.encodeUint64(payload.originNonce),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.tokenAddress),
            Borsh.encodeUint128(payload.amount),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(payload.recipient),
            bytes(payload.feeRecipient).length == 0 // None or Some(String) in rust
                ? bytes("\x00")
                : bytes.concat(
                    bytes("\x01"),
                    Borsh.encodeString(payload.feeRecipient)
                ),
            bytes(payload.message).length == 0
                ? bytes("")
                : Borsh.encodeBytes(payload.message)
        );
        bytes32 hashed = keccak256(borshEncoded);

        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** near/omni-tests/src/relayer_staking.rs (L79-110)
```rust
    #[rstest]
    #[tokio::test]
    async fn test_apply_auto_promote_relayer(
        #[from(locker_wasm)] locker: Vec<u8>,
        #[from(mock_prover_wasm)] prover: Vec<u8>,
    ) -> anyhow::Result<()> {
        let env = TestEnv::new(locker, prover).await?;

        // Set a short waiting period for testing (1 second in nanoseconds)

        env.bridge_contract
            .call("set_relayer_config")
            .args_json(json!({
                "stake_required": U128(1_000 * 10u128.pow(24)),
                "waiting_period_ns": U64(1_000_000_000),
            }))
            .max_gas()
            .transact()
            .await?
            .into_result()?;

        let applicant = env.create_funded_account("applicant", 2000).await?;

        // Apply
        let result = applicant
            .call(env.bridge_contract.id(), "apply_for_trusted_relayer")
            .deposit(NearToken::from_near(1000))
            .max_gas()
            .transact()
            .await?;
        result.into_result()?;

```
