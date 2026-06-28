### Title
Fee-on-Transfer ERC-20 Token Escrow Mis-Accounting in `initTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.initTransfer` calls `safeTransferFrom` with the caller-supplied `amount` and then emits `InitTransfer` with that same `amount`, without performing a before/after balance check. For fee-on-transfer ERC-20 tokens, the bridge receives fewer tokens than `amount`, but the emitted event records the full `amount`. The NEAR bridge finalizes the inbound transfer for the full `amount`, minting or unlocking more tokens than the EVM bridge actually holds, creating a permanent escrow deficit.

---

### Finding Description

In `OmniBridge.initTransfer`, the non-bridge-token branch (the `else` path) performs:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // caller-supplied
);
```

and immediately emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,         // same caller-supplied value, no balance diff check
    fee,
    nativeFee,
    recipient,
    message
);
``` [1](#0-0) [2](#0-1) 

There is no `balanceOf(address(this))` snapshot before and after the transfer. For a fee-on-transfer ERC-20 (e.g., a token that deducts 1% on every transfer), `safeTransferFrom(user, bridge, 1000)` deposits only 990 tokens into the bridge, but the event records `amount = 1000`.

A relayer then submits this event as a proof to the NEAR `omni-bridge` contract. The NEAR side's `fin_transfer` / `process_fin_transfer_to_near` trusts the amount from the verified proof and sends the full recorded amount to the recipient: [3](#0-2) 

The same pattern exists in the Starknet bridge's `init_transfer`: [4](#0-3) 

---

### Impact Explanation

Every `initTransfer` call with a fee-on-transfer token causes the EVM bridge to hold `amount - fee_taken` tokens while the NEAR side releases `amount` tokens. The shortfall accumulates with each transfer. Eventually the EVM bridge cannot honor legitimate withdrawals (i.e., `finTransfer` calls from NEAR→EVM), permanently freezing or losing funds for honest users. This is a **critical escrow mis-accounting** vulnerability. [5](#0-4) 

---

### Likelihood Explanation

Any ERC-20 token whose `transfer`/`transferFrom` deducts a fee (e.g., reflection tokens, tokens with protocol fees, or tokens that can have fees toggled on by their owner) triggers this path. The `initTransfer` function has no token whitelist; any address can be passed as `tokenAddress`. A user only needs to hold a fee-on-transfer token that has been bound on the NEAR side (via `bind_token`, an admin action that is routine for new token listings). Once bound, any holder can exploit the discrepancy on every transfer. [6](#0-5) 

---

### Recommendation

Replace the direct `safeTransferFrom` call with a balance-diff pattern:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
require(actualReceived > 0, "ZERO_RECEIVED");
// use actualReceived instead of amount in the event and downstream logic
```

Apply the same fix to the Starknet `init_transfer` in `starknet/src/omni_bridge.cairo`. [1](#0-0) [4](#0-3) 

---

### Proof of Concept

1. A fee-on-transfer ERC-20 token `FeeToken` (1% fee on every transfer) is listed on the bridge: admin calls `bind_token` on NEAR and the token is mapped.
2. Alice calls `OmniBridge.initTransfer(FeeToken, 1000, 0, 0, "alice.near", "")`.
3. `safeTransferFrom(Alice, bridge, 1000)` executes; `FeeToken` deducts 1% → bridge receives **990** tokens.
4. `InitTransfer` event is emitted with `amount = 1000`.
5. Relayer submits the event proof to the NEAR `omni-bridge` `fin_transfer`.
6. NEAR bridge verifies the MPC/light-client proof and sends **1000** tokens to `alice.near`.
7. The EVM bridge is now short by **10 tokens** per transfer. Repeated transfers drain the bridge's reserves, eventually preventing legitimate `finTransfer` (NEAR→EVM) withdrawals for other users. [7](#0-6) [8](#0-7)

### Citations

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

**File:** near/omni-bridge/src/lib.rs (L253-283)
```rust
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

**File:** near/omni-bridge/src/lib.rs (L1957-1965)
```rust
        self.send_tokens(
            token.clone(),
            recipient,
            U128(
                transfer_message
                    .amount_without_fee()
                    .near_expect(BridgeError::InvalidFee),
            ),
            &msg,
```

**File:** starknet/src/omni_bridge.cairo (L303-307)
```text
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }
```
