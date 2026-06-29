### Title
User Can Initiate Transfer of Any Unregistered Token, Causing Permanent Fund Freezing — (File: `starknet/src/omni_bridge.cairo`)

---

### Summary

The Starknet `init_transfer` function accepts any arbitrary ERC20 `token_address` without verifying that the token is registered in the bridge's token registry. Tokens sent for an unregistered token are immediately burned or locked in the Starknet bridge contract, but the corresponding NEAR finalization will always fail because the token has no registered decimals or address mapping. There is no refund path, so the funds are permanently frozen.

---

### Finding Description

`init_transfer` in `starknet/src/omni_bridge.cairo` performs only two checks on `token_address`:

```cairo
if self.is_bridge_token(token_address) {
    IBridgeTokenDispatcher { contract_address: token_address }
        .burn(caller, amount.into());
} else {
    let success = IERC20Dispatcher { contract_address: token_address }
        .transfer_from(caller, get_contract_address(), amount.into());
    assert(success, 'ERR_TRANSFER_FROM_FAILED');
}
```

`is_bridge_token` only distinguishes between bridge-deployed tokens (burn path) and everything else (lock path). It does **not** verify that the token has a corresponding entry in the bridge's `near_to_starknet_token` / `starknet_to_near_token` registry. Any ERC20 token — registered or not — passes this gate.

After the tokens are burned or locked, an `InitTransfer` event is emitted and the nonce is incremented. A relayer then submits the proof to the NEAR `omni-bridge` contract. In `fin_transfer_callback`, NEAR immediately panics:

```rust
let decimals = self
    .token_decimals
    .get(&init_transfer.token)
    .near_expect(BridgeError::TokenDecimalsNotFound);
```

Because the token was never registered, `token_decimals` has no entry for it, and the NEAR-side finalization is permanently rejected. The Starknet contract has no refund or rescue function for tokens that were locked or burned in this way, so the funds are irrecoverably frozen.

The identical structural gap exists in the EVM `initTransfer` (`evm/src/omni-bridge/contracts/OmniBridge.sol`, lines 373–437): any `tokenAddress` that is neither a `customMinter` nor a `isBridgeToken` entry is silently locked via `safeTransferFrom` with no registration check, and the NEAR side will equally reject the proof.

On the NEAR side itself, `ft_on_transfer` → `init_transfer` → `init_transfer_internal` also accepts any predecessor token without a registration check, returning `U128(0)` (keeping the tokens) even for unregistered tokens, after which `sign_transfer` will panic at the `get_token_address` lookup.

---

### Impact Explanation

Any user who calls `init_transfer` (Starknet/EVM) or `ft_transfer_call` (NEAR) with a token that has not been registered in the bridge will have their tokens permanently frozen inside the bridge contract. There is no admin rescue function, no refund callback, and no timeout-based recovery. This satisfies the allowed impact criterion of **permanent freezing of bridged funds** on Starknet, EVM, and NEAR.

---

### Likelihood Explanation

Medium. The bridge is a public, permissionless interface. A user who attempts to bridge a token before it has been formally registered (e.g., before `deploy_token` / `bind_token` completes), or who mistakenly supplies the wrong token address, will trigger this path. No special privilege or prior knowledge is required; a single `init_transfer` call suffices.

---

### Recommendation

Add an explicit registry check at the top of `init_transfer` (and the EVM/NEAR equivalents) before accepting any tokens:

```cairo
// Starknet example
let near_token_id = self.starknet_to_near_token.read(token_address);
assert(near_token_id != "", 'ERR_TOKEN_NOT_REGISTERED');
```

For the EVM contract, verify that `tokenAddress` is either in `isBridgeToken`, `customMinters`, or a separately maintained allowlist of registered native tokens before executing any transfer. For the NEAR `ft_on_transfer` path, verify that `token_id` has an entry in `token_id_to_address` for the requested destination chain before returning `U128(0)`.

---

### Proof of Concept

1. Deploy any ERC20 token on Starknet that has **not** been registered via `deploy_token`.
2. Approve the Starknet bridge to spend `N` tokens.
3. Call `init_transfer(unregistered_token, N, 0, 0, "victim.near", "")`.
4. The bridge executes `transfer_from`, locking `N` tokens; nonce increments; `InitTransfer` event is emitted.
5. A relayer submits the Starknet proof to the NEAR `fin_transfer` endpoint.
6. NEAR's `fin_transfer_callback` panics at `TokenDecimalsNotFound` — the proof is rejected.
7. The `N` tokens remain locked in the Starknet bridge contract with no recovery path. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** starknet/src/omni_bridge.cairo (L281-331)
```text
        fn init_transfer(
            ref self: ContractState,
            token_address: ContractAddress,
            amount: u128,
            fee: u128,
            native_fee: u128,
            recipient: ByteArray,
            message: ByteArray,
        ) {
            assert(!_is_paused(@self, PAUSE_INIT_TRANSFER), 'ERR_INIT_TRANSFER_PAUSED');

            assert(amount > 0, 'ERR_ZERO_AMOUNT');
            assert(fee < amount, 'ERR_INVALID_FEE');

            let origin_nonce = self.current_origin_nonce.read() + 1;
            self.current_origin_nonce.write(origin_nonce);

            let caller = get_caller_address();

            if self.is_bridge_token(token_address) {
                IBridgeTokenDispatcher { contract_address: token_address }
                    .burn(caller, amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }

            if native_fee > 0 {
                let native_token = self.strk_token_address.read();
                let success = IERC20Dispatcher { contract_address: native_token }
                    .transfer_from(caller, get_contract_address(), native_fee.into());
                assert(success, 'ERR_FEE_TRANSFER_FAILED');
            }

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
        }
```

**File:** near/omni-bridge/src/lib.rs (L252-283)
```rust
    #[pause(except(roles(Role::DAO, Role::UnrestrictedDeposit)))]
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) {
        let token_id = env::predecessor_account_id();
        let parsed_msg: BridgeOnTransferMsg = serde_json::from_str(&msg)
            .or_else(|_| serde_json::from_str(&msg).map(BridgeOnTransferMsg::InitTransfer))
            .near_expect(BridgeError::ParseMsg);

        // We can't trust sender_id to pay for storage as it can be spoofed.
        let signer_id = env::signer_account_id();
        let promise_or_promise_index_or_value = match parsed_msg {
            BridgeOnTransferMsg::InitTransfer(init_transfer_msg) => {
                self.init_transfer(sender_id, signer_id, token_id, amount, init_transfer_msg)
            }
            BridgeOnTransferMsg::FastFinTransfer(fast_fin_transfer_msg) => {
                self.fast_fin_transfer(token_id, amount, signer_id, fast_fin_transfer_msg)
            }
            BridgeOnTransferMsg::UtxoFinTransfer(utxo_fin_transfer_msg) => self.utxo_fin_transfer(
                token_id,
                amount,
                &signer_id,
                &sender_id,
                utxo_fin_transfer_msg,
            ),
            BridgeOnTransferMsg::SwapMigratedToken => {
                self.swap_migrated_token(sender_id, token_id, amount)
                    .detach();
                PromiseOrPromiseIndexOrValue::Value(U128(0))
            }
        };

        promise_or_promise_index_or_value.as_return();
    }
```

**File:** near/omni-bridge/src/lib.rs (L700-718)
```rust
    pub fn fin_transfer_callback(
        &mut self,
        #[serializer(borsh)] storage_deposit_actions: &Vec<StorageDepositAction>,
        #[serializer(borsh)] predecessor_account_id: AccountId,
    ) -> PromiseOrValue<Nonce> {
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
```

**File:** near/omni-bridge/src/lib.rs (L1829-1865)
```rust
    fn init_transfer_internal(
        &mut self,
        transfer_message: TransferMessage,
        storage_owner: AccountId,
    ) -> U128 {
        let required_storage_balance = self
            .add_transfer_message(transfer_message.clone(), storage_owner.clone())
            .saturating_add(NearToken::from_yoctonear(transfer_message.fee.native_fee.0));

        if self
            .try_update_storage_balance(
                storage_owner,
                required_storage_balance,
                NearToken::from_yoctonear(0),
            )
            .is_err()
        {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        if let OmniAddress::Near(token_id) = transfer_message.token.clone() {
            self.burn_tokens_if_needed(token_id.clone(), transfer_message.amount);

            self.lock_tokens_if_needed(
                transfer_message.get_destination_chain(),
                &token_id,
                transfer_message.amount.0,
            );
        } else {
            self.remove_transfer_message_without_refund(transfer_message.get_transfer_id());
            return transfer_message.amount;
        }

        env::log_str(&OmniBridgeEvent::InitTransferEvent { transfer_message }.to_log_string());
        U128(0)
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-437)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
        if (fee >= amount) {
            revert InvalidFee();
        }

        uint256 extensionValue;
        if (tokenAddress == address(0)) {
            if (fee != 0) {
                revert InvalidFee();
            }
            extensionValue = msg.value - amount - nativeFee;
        } else {
            extensionValue = msg.value - nativeFee;
            if (customMinters[tokenAddress] != address(0)) {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    customMinters[tokenAddress],
                    amount
                );
                ICustomMinter(customMinters[tokenAddress]).burn(
                    tokenAddress,
                    amount
                );
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
        }

        initTransferExtension(
            msg.sender,
            tokenAddress,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message,
            extensionValue
        );

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
    }
```
