The code confirms the claim. Both the missing check in `update_transfer_fee` and the guard in `init_transfer` are exactly as described.

- `update_transfer_fee` (lines 388–436) performs no `NativeFeeRestricted` check anywhere. [1](#0-0) 
- `init_transfer` gates the direct-execution path on `native_token_fee.0 == 0 || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())`. [2](#0-1) 
- The existing integration tests in `native_fee_role.rs` only exercise the `init_transfer` path and never test `update_transfer_fee` with a restricted account. [3](#0-2) 

---

Audit Report

## Title
`NativeFeeRestricted` Role Bypass via `update_transfer_fee` — (File: `near/omni-bridge/src/lib.rs`)

## Summary
The `NativeFeeRestricted` role prevents designated accounts from setting a non-zero `native_token_fee` during `init_transfer`. However, `update_transfer_fee` — which modifies the fee on an already-stored pending transfer — contains no equivalent role check. A restricted account can initiate a transfer with `native_token_fee = 0` (passing the `init_transfer` guard), then call `update_transfer_fee` to raise the native fee to any value, fully circumventing the DAO's access-control policy.

## Finding Description
In `init_transfer`, the direct-execution branch is gated on:
```rust
init_transfer_msg.native_token_fee.0 == 0
    || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())
```
This blocks restricted accounts from storing a transfer with a non-zero native fee.

`update_transfer_fee` validates only that: the transfer has no `origin_transfer_id`; the new token fee is ≥ current and < amount; only the original sender can raise the token fee; and the attached NEAR deposit equals the native fee delta. There is no `Role::NativeFeeRestricted` check anywhere in the function. Because `update_transfer_fee` is a separate public entry point that modifies the stored `fee.native_fee` field directly, the guard in `init_transfer` is entirely ineffective against a two-step attack.

**Exploit flow:**
1. Restricted account calls `ft_transfer_call` → `init_transfer` with `native_token_fee = 0`. The role check passes.
2. Transfer is stored with `fee = { fee: X, native_fee: 0 }`.
3. Restricted account calls `update_transfer_fee(transfer_id, UpdateFee::Fee(Fee { fee: X, native_fee: Y }))` attaching `Y` yoctoNEAR. No role check — update accepted.
4. Transfer now carries `native_fee = Y`. When `sign_transfer` finalises the transfer, the relayer receives `Y` yoctoNEAR as if the restriction never existed.

## Impact Explanation
This is a concrete role/authorization bypass — one of the explicitly listed critical impact categories. The `NativeFeeRestricted` role is a DAO-controlled access-control mechanism. Its bypass allows a restricted actor to set arbitrary native fees on outbound transfers, manipulating relayer incentives in ways the protocol operators explicitly prohibited and undermining the integrity of the access-control system.

## Likelihood Explanation
The bypass requires no special privileges beyond holding the `NativeFeeRestricted` role (which is the exact population the control targets). It requires no flash loans, no external dependencies, and no victim mistakes — only two sequential, publicly callable transactions. Any restricted account can execute it deterministically and repeatedly.

## Recommendation
Add a `NativeFeeRestricted` role check inside `update_transfer_fee` whenever the native fee is being increased:
```rust
if diff_native_fee > 0 {
    require!(
        !self.acl_has_role(
            Role::NativeFeeRestricted.into(),
            env::predecessor_account_id()
        ),
        BridgeError::NativeFeeRestricted.as_ref()
    );
}
```
Place this check immediately after `diff_native_fee` is computed (after line 415), mirroring the guard already present in `init_transfer`.

## Proof of Concept
```
1. DAO grants NativeFeeRestricted to "restricted.near".

2. "restricted.near" calls:
     token.ft_transfer_call(
         receiver_id: "omni.bridge.near",
         amount: 1000,
         msg: InitTransferMsg { native_token_fee: 0, fee: 10, recipient: "0x...", ... }
     )
   → init_transfer passes (native_token_fee == 0).
   → Transfer stored: fee = { fee: 10, native_fee: 0 }.

3. "restricted.near" calls:
     omni.bridge.near.update_transfer_fee(
         transfer_id: <id from step 2>,
         fee: UpdateFee::Fee(Fee { fee: 10, native_fee: 1_000_000_000_000_000_000_000_000 })
     )
     attached_deposit: 1_000_000_000_000_000_000_000_000 yoctoNEAR
   → No NativeFeeRestricted check → update accepted.
   → Transfer now carries native_fee = 1 NEAR.

4. Relayer calls sign_transfer → relayer receives 1 NEAR native fee.
   → NativeFeeRestricted policy fully bypassed.
```
A sandbox integration test extending `near/omni-tests/src/native_fee_role.rs` can reproduce this by: granting the role, calling `initialize_transfer` with `native_fee = 0`, then calling `update_transfer_fee` with a non-zero native fee, and asserting the stored transfer's `native_fee` is non-zero.

### Citations

**File:** near/omni-bridge/src/lib.rs (L388-436)
```rust
    pub fn update_transfer_fee(&mut self, transfer_id: TransferId, fee: UpdateFee) {
        match fee {
            UpdateFee::Fee(fee) => {
                let mut transfer = self.get_transfer_message_storage(transfer_id);

                require!(
                    transfer.message.origin_transfer_id.is_none(),
                    BridgeError::UpdateFeeNotAllowedForTransfer.as_ref()
                );

                let current_fee = transfer.message.fee;
                require!(
                    fee.fee >= current_fee.fee && fee.fee < transfer.message.amount,
                    BridgeError::InvalidFee.as_ref()
                );

                require!(
                    fee.fee == current_fee.fee
                        || OmniAddress::Near(env::predecessor_account_id())
                            == transfer.message.sender,
                    BridgeError::SenderCanUpdateTokenFeeOnly.as_ref()
                );

                let diff_native_fee = fee
                    .native_fee
                    .0
                    .checked_sub(current_fee.native_fee.0)
                    .near_expect(BridgeError::LowerFee);

                require!(
                    NearToken::from_yoctonear(diff_native_fee) == env::attached_deposit(),
                    BridgeError::InvalidAttachedDeposit.as_ref()
                );

                transfer.message.fee = fee;
                self.insert_raw_transfer(transfer.message.clone(), transfer.owner);

                env::log_str(
                    &OmniBridgeEvent::UpdateFeeEvent {
                        transfer_message: transfer.message,
                    }
                    .to_log_string(),
                );
            }
            UpdateFee::Proof(_) => {
                env::panic_str(BridgeError::UnsupportedFeeUpdateProof.to_string().as_str())
            }
        }
    }
```

**File:** near/omni-bridge/src/lib.rs (L579-580)
```rust
            ) && (init_transfer_msg.native_token_fee.0 == 0
                || !self.acl_has_role(Role::NativeFeeRestricted.into(), signer_id.clone())))
```

**File:** near/omni-tests/src/native_fee_role.rs (L283-368)
```rust
    #[rstest]
    #[tokio::test]
    async fn test_native_fee_restriction(
        mock_token_wasm: Vec<u8>,
        mock_prover_wasm: Vec<u8>,
        locker_wasm: Vec<u8>,
    ) -> anyhow::Result<()> {
        let env = TestEnv::new(mock_token_wasm, mock_prover_wasm, locker_wasm).await?;

        // 1. Test that an account can set a native fee when not restricted
        let transfer_amount = 100;
        let native_fee = NearToken::from_near(1).as_yoctonear();
        let token_fee = 10;

        let transfer_message = env
            .initialize_transfer(
                transfer_amount,
                native_fee,
                token_fee,
                true, // Should succeed
            )
            .await?
            .unwrap();

        assert_eq!(
            transfer_message.fee.native_fee.0, native_fee,
            "Native fee was not set correctly"
        );

        // 2. Grant NativeFeeRestricted role to the sender account
        env.grant_native_fee_restricted_role(env.sender_account.id())
            .await?;

        // 3. Test that the account cannot set a native fee when restricted
        let result = env
            .initialize_transfer(
                transfer_amount,
                native_fee,
                token_fee,
                false, // Should fail
            )
            .await;

        assert!(
            result.is_ok(),
            "Transfer should have failed with the expected error"
        );

        // 4. Test that the account can still transfer with zero native fee
        let transfer_message = env
            .initialize_transfer(
                transfer_amount,
                0, // Zero native fee
                token_fee,
                true, // Should succeed
            )
            .await?
            .unwrap();

        assert_eq!(
            transfer_message.fee.native_fee.0, 0,
            "Native fee should be zero"
        );

        // 5. Revoke the NativeFeeRestricted role
        env.revoke_native_fee_restricted_role(env.sender_account.id())
            .await?;

        // 6. Test that the account can set a native fee after role revocation
        let transfer_message = env
            .initialize_transfer(
                transfer_amount,
                native_fee,
                token_fee,
                true, // Should succeed
            )
            .await?
            .unwrap();

        assert_eq!(
            transfer_message.fee.native_fee.0, native_fee,
            "Native fee was not set correctly after role revocation"
        );

        Ok(())
    }
```
