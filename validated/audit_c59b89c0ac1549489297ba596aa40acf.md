### Title
Unregistered ERC20 Token Deposits in `initTransfer` Permanently Lock User Funds - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.initTransfer` accepts any ERC20 token address without verifying that the token is registered in the bridge's token registry. When a user calls `initTransfer` with an ERC20 token that has no corresponding NEAR-side registration, the tokens are transferred into the bridge contract and permanently locked with no recovery path.

### Finding Description

`initTransfer` in `OmniBridge.sol` handles three token cases: custom minters, bridge-deployed tokens (`isBridgeToken`), and a catch-all `else` branch for all other ERC20s. [1](#0-0) 

The `else` branch at lines 406–412 executes `safeTransferFrom(msg.sender, address(this), amount)` for **any** ERC20 that is neither a custom minter nor a bridge-deployed token — including tokens that have never been registered with the bridge at all. There is no check against `ethToNearToken[tokenAddress]` or any other registry membership guard before accepting the transfer. [2](#0-1) 

The bridge's token registry is populated only through the `deployToken` flow (requires a valid MPC signature) or `addCustomToken` (admin-only). A token that has not gone through `logMetadata` → NEAR-side deployment → `deployToken` is unknown to both the EVM contract's `ethToNearToken` mapping and the NEAR contract's `token_decimals` / `token_address_to_id` maps.

When the NEAR-side relayer attempts to finalize the transfer by calling `fin_transfer`, the callback immediately panics: [3](#0-2) 

`token_decimals.get(&init_transfer.token)` returns `None` for an unregistered EVM token address, causing `ERR_TOKEN_DECIMALS_NOT_FOUND`. The NEAR finalization is permanently blocked. The EVM contract holds no rescue or admin-withdrawal function for stuck ERC20 tokens, so the funds are irrecoverable.

### Impact Explanation

Any user who calls `initTransfer` with an ERC20 token that is not yet registered in the bridge (i.e., `ethToNearToken[tokenAddress]` is empty and `isBridgeToken[tokenAddress]` is false) will have their tokens permanently locked in the `OmniBridge` contract. There is no owner-callable rescue function, no refund path, and no way for the NEAR side to finalize the transfer. This constitutes permanent freezing of bridged funds.

### Likelihood Explanation

The bridge is explicitly designed to be permissionless — `logMetadata` can be called by anyone for any ERC20, and the README documents `initTransfer` as the standard user-facing entry point. A user who calls `initTransfer` before completing the `logMetadata` → `deployToken` registration flow, or who uses a token address that was never registered, will silently lose funds. The `initTransfer` function emits a valid-looking `InitTransfer` event with no on-chain indication that the token is unsupported, making this a realistic user error with no warning. [4](#0-3) 

### Recommendation

Add a registry membership check at the top of `initTransfer` before accepting any token transfer:

```solidity
function initTransfer(
    address tokenAddress,
    uint128 amount,
    ...
) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
+   require(
+       tokenAddress == address(0) ||
+       customMinters[tokenAddress] != address(0) ||
+       isBridgeToken[tokenAddress] ||
+       bytes(ethToNearToken[tokenAddress]).length > 0,
+       "Token not registered"
+   );
    ...
}
```

This ensures that only tokens with a known NEAR-side counterpart can be locked in the bridge, mirroring the intent of the permissionless registration flow.

### Proof of Concept

1. Deploy any ERC20 token that has never had `logMetadata` called for it (i.e., `ethToNearToken[token] == ""` and `isBridgeToken[token] == false`).
2. Approve `OmniBridge` to spend `amount` of the token.
3. Call `OmniBridge.initTransfer(token, amount, 0, 0, "victim.near", "")`.
4. The `else` branch executes `safeTransferFrom(msg.sender, address(this), amount)` — tokens are now held by the bridge.
5. An `InitTransfer` event is emitted.
6. The NEAR relayer calls `fin_transfer` with a proof of the event. `fin_transfer_callback` calls `self.token_decimals.get(&init_transfer.token).near_expect(BridgeError::TokenDecimalsNotFound)` and panics with `ERR_TOKEN_DECIMALS_NOT_FOUND`.
7. No further finalization is possible. The EVM contract has no rescue function. Tokens are permanently locked. [5](#0-4) [6](#0-5)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L36-48)
```text
    mapping(address => string) public ethToNearToken;
    mapping(string => address) public nearToEthToken;
    mapping(address => bool) public isBridgeToken;

    address public tokenImplementationAddress;
    address public nearBridgeDerivedAddress;
    uint8 public omniBridgeChainId;

    mapping(uint64 => bool) public completedTransfers;
    uint64 public currentOriginNonce;

    mapping(address => address) public customMinters;
    mapping(address => MultiTokenInfo) public multiTokens;
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

**File:** evm/SECURITY.md (L7-8)
```markdown
- **Fee-on-transfer tokens not supported**: `initTransfer` emits the requested `amount`, not the actual received balance. Fee-on-transfer and rebasing tokens are intentionally unsupported
- **`logMetadata` and `deployToken` are permissionless**: Anyone can call `logMetadata` for any ERC20, and anyone can submit a valid MPC signature to `deployToken`. This is by design — the bridge is fully permissionless
```
