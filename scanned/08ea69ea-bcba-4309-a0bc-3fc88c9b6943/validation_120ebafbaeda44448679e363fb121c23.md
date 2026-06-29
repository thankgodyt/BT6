### Title
Missing Token Registration Check in `initTransfer` Allows Permanent Locking of User Funds — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary
`OmniBridge.sol`'s `initTransfer` function accepts any ERC20 token address without verifying that the token is registered with the bridge. If a user calls `initTransfer` with an unregistered token, the tokens are locked in the EVM bridge and an `InitTransfer` event is emitted, but the NEAR side will panic and reject the transfer because the token has no registered decimals mapping. There is no EVM-side recovery mechanism, so the user's tokens are permanently frozen.

### Finding Description
The `initTransfer` function uses `isBridgeToken[tokenAddress]` only as a **branch selector** (burn vs. lock), not as a registration gate. For any token where `isBridgeToken[tokenAddress]` is `false` and `customMinters[tokenAddress]` is `address(0)`, execution falls into the `else` branch and locks the token via `safeTransferFrom` — including completely unregistered tokens that have no corresponding NEAR-side entry.

```solidity
// OmniBridge.sol lines 394–412
if (customMinters[tokenAddress] != address(0)) {
    ...
} else if (isBridgeToken[tokenAddress]) {
    BridgeToken(tokenAddress).burn(msg.sender, amount);
} else {
    // ← any arbitrary ERC20 reaches here, no registration check
    IERC20(tokenAddress).safeTransferFrom(
        msg.sender,
        address(this),
        amount
    );
}
``` [1](#0-0) 

After locking, `InitTransfer` is emitted and a relayer submits the event to the NEAR bridge. In `fin_transfer_callback`, the NEAR side immediately panics:

```rust
// near/omni-bridge/src/lib.rs lines 715–718
let decimals = self
    .token_decimals
    .get(&init_transfer.token)
    .near_expect(BridgeError::TokenDecimalsNotFound);
``` [2](#0-1) 

The panic causes the NEAR callback to fail. The EVM bridge has no mechanism to detect this failure or refund the locked tokens. No `rescueTokens` or equivalent admin function exists in `OmniBridge.sol`.

This is the direct analog to M-03: `initTransfer` checks `isBridgeToken` (a set-membership branch) but never checks that the token is positively registered in the bridge's token registry (`ethToNearToken` / NEAR-side `token_decimals`). An unregistered token passes all checks silently and proceeds to lock.

### Impact Explanation
**Critical — permanent freezing of bridged funds.** Any ERC20 token locked via `initTransfer` with an unregistered address is irrecoverable. The EVM bridge holds the tokens indefinitely with no admin escape hatch. The NEAR side's rejection is invisible to the EVM contract.

### Likelihood Explanation
**Medium.** The bridge is permissionless and widely used. A user who mistakenly supplies an unregistered token address (e.g., a token whose NEAR-side registration was never completed, or a token address typo) will silently lose funds. No warning or revert is produced on the EVM side.

### Recommendation
Add a positive registration check before accepting the token in `initTransfer`. The simplest fix is to require that the token has a known NEAR mapping:

```solidity
require(
    tokenAddress == address(0) ||
    isBridgeToken[tokenAddress] ||
    customMinters[tokenAddress] != address(0) ||
    bytes(ethToNearToken[tokenAddress]).length > 0,
    "ERR_TOKEN_NOT_REGISTERED"
);
``` [3](#0-2) 

This mirrors the fix recommended in M-03: replace a branch-only membership test with an explicit gate that rejects unregistered entities before any state change occurs.

### Proof of Concept
1. User calls `OmniBridge.initTransfer(unregisteredERC20, 1000, 0, 0, "victim.near", "")`.
2. `isBridgeToken[unregisteredERC20]` is `false`, `customMinters[unregisteredERC20]` is `address(0)` → `safeTransferFrom` locks 1000 tokens in the bridge. `currentOriginNonce` increments. `InitTransfer` event emitted.
3. A relayer submits the event proof to NEAR `fin_transfer`.
4. `fin_transfer_callback` calls `self.token_decimals.get(&init_transfer.token).near_expect(BridgeError::TokenDecimalsNotFound)` → panics.
5. NEAR callback fails. EVM bridge retains the 1000 tokens with no refund path. User's funds are permanently frozen. [4](#0-3) [5](#0-4)

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-413)
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
