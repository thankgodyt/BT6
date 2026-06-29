### Title
Fee-on-Transfer Token Causes Escrow Mis-Accounting in `initTransfer` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` on the EVM side pulls `amount` tokens from the caller via `safeTransferFrom`, then unconditionally emits `InitTransfer(amount=amount)`. For fee-on-transfer ERC20 tokens the bridge actually receives `amount − fee_on_transfer`, yet the emitted event records the full `amount`. The NEAR relayer parses this event and credits the recipient with the full `amount`, creating a permanent escrow shortfall that grows with every such deposit and eventually makes the EVM vault insolvent.

---

### Finding Description

In `initTransfer`, the regular-ERC20 branch (the `else` path that handles any token that is neither a bridge token nor a custom-minter token) does:

```solidity
// evm/src/omni-bridge/contracts/OmniBridge.sol  lines 407-411
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount
);
```

Immediately after, the function emits:

```solidity
// lines 427-436
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // ← always the requested amount, never the actual received amount
    fee,
    nativeFee,
    recipient,
    message
);
```

No `balanceOf` snapshot is taken before or after the transfer to verify that exactly `amount` tokens arrived. `SafeERC20.safeTransferFrom` only guarantees the call did not silently return `false`; it does not guarantee the contract received `amount` tokens.

The NEAR side parses this event in `fin_transfer_callback` (`near/omni-bridge/src/lib.rs` lines 705–745), constructs a `TransferMessage` with `amount` taken directly from the event, and then mints or unlocks that full `amount` to the recipient on NEAR. The EVM vault is now short by `fee_on_transfer` per deposit.

The same structural flaw exists in the Starknet `init_transfer` (`starknet/src/omni_bridge.cairo` lines 303–306 and 320–323): `transfer_from` is called, its boolean return is checked, but the emitted `InitTransfer` event always carries the caller-supplied `amount`, not the actual received balance.

---

### Impact Explanation

**Critical — escrow mis-accounting / insolvency of the EVM vault.**

Each deposit of a fee-on-transfer token inflates the NEAR-side credit by `fee_on_transfer`. When those NEAR-side tokens are later bridged back to EVM, `finTransfer` calls `safeTransfer(recipient, amount)` (line 351–354) against a vault that holds less than `amount`. Either:

- The transfer reverts, permanently freezing the user's funds on NEAR, or  
- The shortfall is covered by other users' deposits, draining the vault and causing losses for honest depositors.

Because the shortfall accumulates with every fee-on-transfer deposit, a sustained campaign of small deposits can drain the entire EVM vault.

---

### Likelihood Explanation

**Medium.** The `initTransfer` regular-ERC20 path imposes no token whitelist; any ERC20 address is accepted. Fee-on-transfer tokens exist on mainnet (e.g., PAXG, STA, and various reflection tokens). A single user who deposits such a token — even unintentionally — triggers the accounting error. A motivated attacker can amplify the shortfall by repeating deposits.

---

### Recommendation

1. **Measure actual received amount** using a `balanceOf` snapshot:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 received = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
require(received == amount, "FeeOnTransferToken");
```

2. Alternatively, **reject fee-on-transfer tokens explicitly** by reverting when `received < amount`, and document this restriction clearly.

3. Apply the same fix to the Starknet `init_transfer` (`starknet/src/omni_bridge.cairo` lines 303–306).

---

### Proof of Concept

1. Deploy or use any ERC20 that deducts a 10 % fee on every `transferFrom` (e.g., a reflection token).  
2. Register the token with the bridge so NEAR has its decimal metadata.  
3. Call `initTransfer(feeToken, 1000, 0, 0, nearRecipient, "")` on EVM.  
   - `safeTransferFrom` succeeds; vault receives **900**.  
   - `InitTransfer(amount=1000)` is emitted.  
4. NEAR relayer calls `fin_transfer` with the proof; NEAR credits `nearRecipient` with **1000** tokens.  
5. `nearRecipient` calls `ft_transfer_call` on NEAR to bridge **1000** tokens back to EVM.  
6. EVM `finTransfer` calls `safeTransfer(recipient, 1000)` — vault only holds **900** → reverts or drains other depositors' funds.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L351-354)
```text
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L407-411)
```text
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-436)
```text
        emit BridgeTypes.InitTransfer(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
```

**File:** starknet/src/omni_bridge.cairo (L303-306)
```text
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
```

**File:** starknet/src/omni_bridge.cairo (L316-330)
```text
            self
                .emit(
                    Event::InitTransfer(
                        InitTransfer {
                            sender: caller,
                            token_address,
                            origin_nonce,
                            amount,
                            fee,
                            native_fee,
                            recipient,
                            message,
                        },
                    ),
                )
```

**File:** near/omni-bridge/src/lib.rs (L705-745)
```rust
        let Ok(ProverResult::InitTransfer(init_transfer)) = Self::decode_prover_result(0) else {
            env::panic_str(BridgeError::InvalidProofMessage.to_string().as_str())
        };
        require!(
            self.factories
                .get(&init_transfer.emitter_address.get_chain())
                == Some(init_transfer.emitter_address),
            BridgeError::UnknownFactory.as_ref()
        );

        let decimals = self
            .token_decimals
            .get(&init_transfer.token)
            .near_expect(BridgeError::TokenDecimalsNotFound);

        let destination_nonce =
            self.get_next_destination_nonce(init_transfer.recipient.get_chain());
        let transfer_message = TransferMessage {
            origin_nonce: init_transfer.origin_nonce,
            token: init_transfer.token,
            amount: Self::denormalize_amount(init_transfer.amount.0, decimals).into(),
            recipient: init_transfer.recipient,
            fee: Self::denormalize_fee(&init_transfer.fee, decimals),
            sender: init_transfer.sender,
            msg: init_transfer.msg,
            destination_nonce,
            origin_transfer_id: None,
        };

        if let OmniAddress::Near(recipient) = transfer_message.recipient.clone() {
            self.process_fin_transfer_to_near(
                recipient,
                &predecessor_account_id,
                transfer_message,
                storage_deposit_actions,
            )
            .into()
        } else {
            self.process_fin_transfer_to_other_chain(predecessor_account_id, transfer_message);
            PromiseOrValue::Value(destination_nonce)
        }
```
