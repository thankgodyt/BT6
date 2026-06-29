### Title
Unregistered ERC20 Tokens Accepted by `initTransfer()` Are Permanently Locked With No Recovery Path - (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

### Summary
`OmniBridge.initTransfer()` accepts any arbitrary ERC20 token address without verifying that the token is registered in the bridge's `ethToNearToken` mapping. Tokens from unregistered contracts are transferred into the bridge and permanently locked: the NEAR side panics on `TokenDecimalsNotFound` when it tries to finalize the transfer, and no admin rescue function exists in the EVM contract.

### Finding Description
`initTransfer` in `OmniBridge.sol` routes token handling through three branches: `customMinters`, `isBridgeToken`, and a catch-all `else`. The catch-all branch performs a plain `safeTransferFrom` into `address(this)` for any token that is not in either of the first two mappings — including tokens that have never been registered with the bridge at all. [1](#0-0) 

There is no guard of the form `require(bytes(ethToNearToken[tokenAddress]).length > 0, "token not supported")` before the transfer. After the tokens are pulled in, an `InitTransfer` event is emitted unconditionally. [2](#0-1) 

On the NEAR side, `fin_transfer_callback` attempts to look up the token's decimal configuration. For any token that was never registered via `log_metadata` + `deployToken`, this lookup panics with `BridgeError::TokenDecimalsNotFound`, causing the NEAR transaction to fail. [3](#0-2) 

The NEAR failure does not trigger any cross-chain refund. The EVM tokens remain locked in the bridge contract forever. A search of all EVM contract source files confirms there is no `rescueToken`, `withdrawToken`, `emergencyWithdraw`, or equivalent admin function — unlike the Gravity.sol case where `withdrawERC20` at least allowed an admin to recover funds. Here, no recovery path exists for anyone. [4](#0-3) 

The same pattern exists in the Starknet bridge: `init_transfer` accepts any ERC20 token in its `else` branch without checking `starknet_to_near_token`. [5](#0-4) 

### Impact Explanation
Any user who calls `initTransfer` with an ERC20 token that has not been registered through the `logMetadata` → `deployToken` flow loses their tokens permanently. The tokens are transferred into the bridge contract, the `InitTransfer` event is emitted (consuming the user's nonce), the NEAR finalization panics, and no on-chain mechanism exists to return the funds. This is a direct, permanent loss of bridged funds triggered by a single unprivileged user action.

### Likelihood Explanation
The bridge is described as fully permissionless. `initTransfer` is a public, non-paused entry point callable by any EVM address. A user who holds a legitimate ERC20 token that has not yet been registered (e.g., a newly launched token, a token whose `logMetadata` call was never submitted, or a token on a chain where the bridge was recently deployed) can trigger this loss accidentally. The `logMetadata` function is itself permissionless and separate from `initTransfer`, so there is no coupling that prevents a user from calling `initTransfer` before `logMetadata` + `deployToken` have been executed for their token. [6](#0-5) [7](#0-6) 

### Recommendation
Add a registration check at the top of `initTransfer` before any token transfer occurs:

```solidity
require(
    tokenAddress == address(0) ||
    isBridgeToken[tokenAddress] ||
    customMinters[tokenAddress] != address(0) ||
    bytes(ethToNearToken[tokenAddress]).length > 0,
    "ERR_TOKEN_NOT_SUPPORTED"
);
```

Apply the same guard to `initTransfer1155`. Apply an equivalent check in the Starknet `init_transfer` against `starknet_to_near_token`.

### Proof of Concept
1. Alice holds 1000 units of `NEWTOKEN`, a legitimate ERC20 that has not yet had `logMetadata` called on the OmniBridge.
2. Alice calls `OmniBridge.initTransfer(NEWTOKEN_ADDRESS, 1000, 0, 0, "alice.near", "")`.
3. The `else` branch executes: `IERC20(NEWTOKEN_ADDRESS).safeTransferFrom(alice, address(this), 1000)` — Alice's tokens are now in the bridge.
4. `InitTransfer` event is emitted with `tokenAddress = NEWTOKEN_ADDRESS`.
5. A relayer submits the proof to the NEAR `fin_transfer` function.
6. `fin_transfer_callback` calls `self.token_decimals.get(&init_transfer.token).near_expect(BridgeError::TokenDecimalsNotFound)` — this panics because `NEWTOKEN` was never registered.
7. The NEAR transaction reverts. Alice's 1000 `NEWTOKEN` remain locked in the EVM bridge contract with no recovery path. [8](#0-7) [9](#0-8)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L394-412)
```text
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-437)
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
    }
```

**File:** near/omni-bridge/src/lib.rs (L705-718)
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

**File:** evm/SECURITY.md (L7-8)
```markdown
- **Fee-on-transfer tokens not supported**: `initTransfer` emits the requested `amount`, not the actual received balance. Fee-on-transfer and rebasing tokens are intentionally unsupported
- **`logMetadata` and `deployToken` are permissionless**: Anyone can call `logMetadata` for any ERC20, and anyone can submit a valid MPC signature to `deployToken`. This is by design — the bridge is fully permissionless
```
