### Title
Reentrancy in `initTransfer1155` via Malicious ERC1155 `safeTransferFrom` Causes Nonce Collision and Double Minting on NEAR - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary

`initTransfer1155` in `OmniBridge.sol` increments `currentOriginNonce` before calling `safeTransferFrom` on an attacker-controlled ERC1155 token, but reads `currentOriginNonce` again when emitting `InitTransfer` **after** the external call returns. A malicious ERC1155 token can reenter `initTransfer1155` during `safeTransferFrom`, causing both the inner and outer execution frames to emit `InitTransfer` events carrying the **same** `originNonce`. The NEAR side has no deduplication on `origin_nonce`, so both events are finalized independently, minting bridged tokens twice for a single (or zero) EVM-side lock.

### Finding Description

In `initTransfer1155`:

```
Line 448: currentOriginNonce += 1;          // nonce = N+1
...
Line 458: IERC1155(tokenAddress).safeTransferFrom(   // ← external call to attacker-controlled token
              msg.sender, address(this), tokenId, amount, ""
          );
...
Line 483: emit BridgeTypes.InitTransfer(
              msg.sender, deterministicToken,
              currentOriginNonce,             // ← read AFTER the external call
              ...
          );
``` [1](#0-0) 

The nonce is captured into the event **after** the external call, not before it. There is no reentrancy guard on the function.

**Reentrancy trace (single level):**

| Step | `currentOriginNonce` | Action |
|------|----------------------|--------|
| Outer call enters | N → **N+1** | `currentOriginNonce += 1` |
| Outer call hits `safeTransferFrom` | N+1 | Calls malicious ERC1155 |
| Malicious token reenters `initTransfer1155` | N+1 → **N+2** | Inner `currentOriginNonce += 1` |
| Inner call hits `safeTransferFrom` | N+2 | Completes normally |
| Inner call emits `InitTransfer` | **N+2** | `currentOriginNonce` read = N+2 |
| Inner call returns | N+2 | — |
| Outer call resumes after `safeTransferFrom` | N+2 | — |
| Outer call emits `InitTransfer` | **N+2** | `currentOriginNonce` read = N+2 ← **collision** |

Nonce N+1 is silently skipped; nonce N+2 appears in two distinct log entries in the same transaction. Both are valid Merkle-provable events.

The `tokenAddress` parameter is fully attacker-controlled — `initTransfer1155` performs no whitelist check on the ERC1155 contract. [2](#0-1) 

The bridge's `onERC1155Received` guard (`operator != address(this)`) is irrelevant here: the reentrancy occurs inside the malicious token's `safeTransferFrom` implementation, not through the bridge's own receiver hook. [3](#0-2) 

The same structural flaw exists in `initTransfer` for ERC20 tokens (ERC-777 / hook-bearing tokens), where `currentOriginNonce` is also read post-external-call. [4](#0-3) 

In the `OmniBridgeWormhole` variant, `initTransferExtension` receives `currentOriginNonce` as the `originNonce` argument at call time — which is already N+2 for the outer frame — so both Wormhole messages carry the same nonce as well. [5](#0-4) 

On the NEAR side, `fin_transfer_callback` checks the emitter factory and token decimals but performs **no deduplication on `origin_nonce`**. Each submitted proof generates a fresh `destination_nonce` and proceeds to mint/unlock independently. [6](#0-5) 

The NEAR security invariant documented in `evm/CLAUDE.md` — *"State before external calls: Always mutate state before any external call"* — is violated here because the event emission (the state observable by NEAR) happens after the external call. [7](#0-6) 

### Impact Explanation

An attacker can mint an unbounded multiple of bridged tokens on NEAR without locking a corresponding amount of ERC1155 tokens on EVM. Each reentrant level doubles the number of valid `InitTransfer` proofs that can be submitted to NEAR. This is unauthorized minting and escrow mis-accounting: the NEAR-side token supply grows beyond what is backed by EVM-side collateral, enabling the attacker to drain liquidity from any pool or bridge that accepts the minted token.

### Likelihood Explanation

The attack requires only:
1. Deploying a malicious ERC1155 contract (permissionless, ~50 lines of Solidity).
2. Calling the permissionless `logMetadata1155` to register the token so NEAR accepts the event.
3. Calling `initTransfer1155` — a public, unpermissioned function — with the malicious token address.

No admin access, no leaked keys, no front-running, and no collusion are required. The entry path is fully reachable by any unprivileged EVM user.

### Recommendation

1. **Capture the nonce in a local variable before the external call** and use that local variable in `initTransferExtension` and `emit

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L381-436)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-490)
```text
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
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

        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );

        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
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
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L522-535)
```text
    function onERC1155Received(
        address operator,
        address,
        uint256,
        uint256,
        bytes calldata
    ) external view override returns (bytes4) {
        // Only accept transfers that were initiated by this contract itself
        if (operator != address(this)) {
            revert ERC1155DirectSendNotAllowed();
        }

        return this.onERC1155Received.selector;
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridgeWormhole.sol (L118-150)
```text
    function initTransferExtension(
        address sender,
        address tokenAddress,
        uint64 originNonce,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message,
        uint256 value
    ) internal override {
        bytes memory payload = bytes.concat(
            bytes1(uint8(MessageType.InitTransfer)),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(sender),
            bytes1(omniBridgeChainId),
            Borsh.encodeAddress(tokenAddress),
            Borsh.encodeUint64(originNonce),
            Borsh.encodeUint128(amount),
            Borsh.encodeUint128(fee),
            Borsh.encodeUint128(nativeFee),
            Borsh.encodeString(recipient),
            Borsh.encodeString(message)
        );
        // slither-disable-next-line reentrancy-eth
        _wormhole.publishMessage{value: value}(
            wormholeNonce,
            payload,
            _consistencyLevel
        );

        wormholeNonce++;
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

**File:** evm/CLAUDE.md (L34-34)
```markdown
- **State before external calls**: Always mutate state (e.g. mark nonce used) before any external call (token transfer, ETH send, custom minter). This is the primary reentrancy defense
```
