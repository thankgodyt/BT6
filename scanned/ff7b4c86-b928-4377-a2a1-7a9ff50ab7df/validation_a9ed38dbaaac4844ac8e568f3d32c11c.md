### Title
Users Can Permanently Lock Funds by Initiating Transfers of Unregistered Tokens — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

The `initTransfer` function in `OmniBridge.sol` accepts any ERC-20 token without validating that the token has been registered in the bridge system. A user who calls `initTransfer` with an unregistered token will have their funds permanently locked in the EVM contract, because the off-chain relayer cannot process the transfer without a corresponding NEAR-side token registration. The same structural flaw exists in the Starknet `init_transfer` in `starknet/src/omni_bridge.cairo`.

---

### Finding Description

`initTransfer` dispatches on three cases for a non-zero `tokenAddress`: [1](#0-0) 

```solidity
if (customMinters[tokenAddress] != address(0)) {
    // custom-minter burn path
} else if (isBridgeToken[tokenAddress]) {
    BridgeToken(tokenAddress).burn(msg.sender, amount);   // bridge-deployed burn path
} else {
    IERC20(tokenAddress).safeTransferFrom(               // ← native lock path
        msg.sender,
        address(this),
        amount
    );
}
```

The third branch — the **native lock path** — is reached for every ERC-20 that is neither a bridge-deployed token nor a custom-minter token. There is **no check** that the token has been registered in the bridge (i.e., that `ethToNearToken[tokenAddress]` is populated, which only happens after `logMetadata` + NEAR-side `deployToken` have both completed). [2](#0-1) 

The registration lifecycle for a native ERC-20 is:
1. `logMetadata(tokenAddress)` emits a `LogMetadata` event on EVM.
2. A relayer submits the proof to NEAR; NEAR calls `deployToken`, which populates `token_address_to_id` and `token_id_to_address` on the NEAR bridge.
3. Only after step 2 can the relayer process an `InitTransfer` event for that token.

`initTransfer` enforces none of these preconditions. Any ERC-20 — including one that has never had `logMetadata` called, or one whose NEAR-side `deployToken` has not yet been processed — is silently accepted and locked.

The identical pattern exists on Starknet: [3](#0-2) 

```cairo
if self.is_bridge_token(token_address) {
    IBridgeTokenDispatcher { contract_address: token_address }.burn(caller, amount.into());
} else {
    let success = IERC20Dispatcher { contract_address: token_address }
        .transfer_from(caller, get_contract_address(), amount.into());
    assert(success, 'ERR_TRANSFER_FROM_FAILED');
}
```

`is_bridge_token` only checks whether `starknet_to_near_token` has a non-empty entry for the address — it does not validate that the token is supported by the bridge at all. [4](#0-3) 

Neither the EVM contract nor the Starknet contract exposes an admin rescue/withdrawal function for arbitrary stuck ERC-20 tokens. The EVM contract is UUPS-upgradeable, so recovery would require a contract upgrade — a manual, centralized intervention with no guarantee of execution.

The `evm/SECURITY.md` explicitly acknowledges that `logMetadata` and `deployToken` are permissionless by design, but does **not** acknowledge or accept the absence of a registration check in `initTransfer`. [5](#0-4) 

---

### Impact Explanation

Any user who calls `initTransfer` (EVM) or `init_transfer` (Starknet) with a token that is not yet registered on the NEAR side will have their tokens permanently locked in the bridge contract. The off-chain relayer observes the `InitTransfer` event but cannot find a NEAR token mapping for the address, so it cannot mint anything on NEAR. The user receives nothing on the destination chain and cannot recover their funds without admin intervention. This is permanent freezing of bridged funds.

---

### Likelihood Explanation

Medium. The bridge is explicitly advertised as permissionless — `logMetadata` can be called for any ERC-20, and users may reasonably assume that calling `initTransfer` is sufficient to bridge any token. A user can trigger this by:

- Calling `initTransfer` before `logMetadata` has been submitted or before the NEAR-side `deployToken` has been processed (a race condition that is easy to hit on a busy network).
- Calling `initTransfer` for a token that was never registered at all, believing the bridge will handle it.

No special privileges are required; any unprivileged token holder can trigger this.

---

### Recommendation

Add a registration guard in the native lock path of `initTransfer`. On the EVM side, maintain a mapping (e.g., `registeredNativeTokens[tokenAddress]`) that is set when NEAR confirms token deployment, and revert if the token is not present:

```solidity
} else {
    require(registeredNativeTokens[tokenAddress], "ERR_TOKEN_NOT_REGISTERED");
    IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
}
```

Apply the equivalent guard in the Starknet `init_transfer` `else` branch. Alternatively, emit a `LogMetadata` event and require that the NEAR-side deployment is confirmed (via a proof or a signed acknowledgement) before `initTransfer` is accepted for that token.

---

### Proof of Concept

1. Deploy or obtain any ERC-20 token `X` that has never had `logMetadata` called on the EVM bridge, so no NEAR-side token exists.
2. Approve the `OmniBridge` contract: `X.approve(omniBridgeAddress, 1000e18)`.
3. Call `initTransfer(address(X), 1000e18, 0, 0, "victim.near", "")`.
4. The `else` branch executes `safeTransferFrom`, locking `1000e18` of token `X` in the contract.
5. `InitTransfer` is emitted with `tokenAddress = address(X)`.
6. The relayer queries its NEAR-side registry: no entry for `address(X)` exists in `token_address_to_id`.
7. The relayer cannot call `fin_transfer` on NEAR — there is no token to mint.
8. The `1000e18` tokens remain locked in `OmniBridge` indefinitely with no automated recovery path.

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

**File:** starknet/src/omni_bridge.cairo (L300-307)
```text
            if self.is_bridge_token(token_address) {
                IBridgeTokenDispatcher { contract_address: token_address }
                    .burn(caller, amount.into());
            } else {
                let success = IERC20Dispatcher { contract_address: token_address }
                    .transfer_from(caller, get_contract_address(), amount.into());
                assert(success, 'ERR_TRANSFER_FROM_FAILED');
            }
```

**File:** starknet/src/omni_bridge.cairo (L378-380)
```text
        fn is_bridge_token(self: @ContractState, token_address: ContractAddress) -> bool {
            self.starknet_to_near_token.read(token_address).len() > 0
        }
```

**File:** evm/SECURITY.md (L7-8)
```markdown
- **Fee-on-transfer tokens not supported**: `initTransfer` emits the requested `amount`, not the actual received balance. Fee-on-transfer and rebasing tokens are intentionally unsupported
- **`logMetadata` and `deployToken` are permissionless**: Anyone can call `logMetadata` for any ERC20, and anyone can submit a valid MPC signature to `deployToken`. This is by design — the bridge is fully permissionless
```
