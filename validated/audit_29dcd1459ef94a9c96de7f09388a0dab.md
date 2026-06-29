### Title
Missing Token Registration Validation in `initTransfer` Allows Permanent Freezing of User Funds - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

The `initTransfer` function in `OmniBridge.sol` accepts and locks any ERC20 token without verifying that the token is registered in the bridge. If a user initiates a transfer with an unregistered token, the funds are permanently locked in the EVM contract with no recovery path, because the NEAR `fin_transfer_callback` will panic when it cannot find the token's decimal metadata.

---

### Finding Description

`OmniBridge.sol::initTransfer` handles four token cases: native ETH, custom-minter tokens, bridge tokens (burned), and a catch-all `else` branch for regular ERC20s (locked). The `else` branch performs no check that the token is actually registered in the bridge before accepting and locking it:

```solidity
} else {
    IERC20(tokenAddress).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
}
``` [1](#0-0) 

There is no guard such as `require(bytes(nearToEthToken[tokenAddress]).length > 0, ...)` before this transfer. The `nearToEthToken` mapping is only populated when a token is deployed via `deployToken` or registered via `addCustomToken`. [2](#0-1) 

On the NEAR side, `fin_transfer_callback` unconditionally calls `near_expect` on the token decimals lookup. If the token was never registered on NEAR, this panics and the transfer is never finalized:

```rust
let decimals = self
    .token_decimals
    .get(&init_transfer.token)
    .near_expect(BridgeError::TokenDecimalsNotFound);
``` [3](#0-2) 

There is no cancel or refund function on the EVM side. Once tokens are locked via `initTransfer`, the only release path is a successful `finTransfer` call backed by a valid NEAR MPC signature — which can never be produced for an unregistered token. [4](#0-3) 

---

### Impact Explanation

A user who calls `initTransfer` with an ERC20 token that is not registered in the bridge (i.e., `nearToEthToken[tokenAddress]` is empty) will have their tokens permanently locked in the EVM `OmniBridge` contract. There is no on-chain recovery mechanism. This constitutes permanent freezing of bridged funds, matching the critical impact tier.

---

### Likelihood Explanation

The EVM `log_metadata` function only emits an event and updates no on-chain state: [5](#0-4) 

There is therefore no on-chain indicator a user can query to confirm their token is registered before calling `initTransfer`. A user who sees a token listed on a UI, or who calls `initTransfer` before the NEAR-side `deploy_token` completes (a race condition analogous to the jailed-validator scenario in the reference report), will have their funds locked. The `removeCustomToken` admin function also creates a window where in-flight transfers for a recently deregistered token become unrecoverable. [6](#0-5) 

---

### Recommendation

Add a registration guard in the `else` branch of `initTransfer` before accepting the ERC20 transfer:

```solidity
} else {
    require(
        bytes(nearToEthToken[tokenAddress]).length > 0,
        "ERR_TOKEN_NOT_REGISTERED"
    );
    IERC20(tokenAddress).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
}
```

This mirrors the short-term recommendation in the reference report: add a check that reverts any operation targeting an entity in an invalid state (jailed validator / unregistered token).

---

### Proof of Concept

1. `tokenX` is a valid ERC20 on Ethereum but has never been registered in the bridge (i.e., `nearToEthToken[tokenX] == ""`).
2. Alice calls `initTransfer(tokenX, 1000e18, 0, 0, "near:alice.near", "")`.
3. The `else` branch executes: `IERC20(tokenX).safeTransferFrom(alice, bridge, 1000e18)` — tokens are locked. An `InitTransfer` event is emitted.
4. A relayer submits the event proof to NEAR `fin_transfer`.
5. NEAR `fin_transfer_callback` reaches `self.token_decimals.get(&init_transfer.token).near_expect(BridgeError::TokenDecimalsNotFound)` and panics.
6. Alice's 1000 `tokenX` remain permanently locked in the EVM `OmniBridge` contract with no recovery path. [7](#0-6) [8](#0-7)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L36-38)
```text
    mapping(address => string) public ethToNearToken;
    mapping(string => address) public nearToEthToken;
    mapping(address => bool) public isBridgeToken;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L120-127)
```text
    function removeCustomToken(
        address tokenAddress
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        delete isBridgeToken[tokenAddress];
        delete nearToEthToken[ethToNearToken[tokenAddress]];
        delete ethToNearToken[tokenAddress];
        delete customMinters[tokenAddress];
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L224-232)
```text
    function logMetadata(address tokenAddress) external payable {
        string memory name = IERC20Metadata(tokenAddress).name();
        string memory symbol = IERC20Metadata(tokenAddress).symbol();
        uint8 decimals = IERC20Metadata(tokenAddress).decimals();

        logMetadataExtension(tokenAddress, name, symbol, decimals);

        emit BridgeTypes.LogMetadata(tokenAddress, name, symbol, decimals);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-367)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
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

        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
        } else if (customMinters[payload.tokenAddress] != address(0)) {
            ICustomMinter(customMinters[payload.tokenAddress]).mint(
                payload.tokenAddress,
                payload.recipient,
                payload.amount
            );
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }

        finTransferExtension(payload);

        emit BridgeTypes.FinTransfer(
            payload.originChain,
            payload.originNonce,
            payload.tokenAddress,
            payload.amount,
            payload.recipient,
            payload.feeRecipient
        );
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

**File:** near/omni-bridge/src/lib.rs (L700-746)
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
    }
```
