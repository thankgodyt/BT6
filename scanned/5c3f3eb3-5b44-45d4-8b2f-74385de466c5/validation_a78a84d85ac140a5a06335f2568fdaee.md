The exploit is traceable and real. Here is the full analysis:

---

### Title
Missing Self-Address Guard in `ACTION_TRANSFER` Allows Permanent Token Stranding at `address(this)` — (`evm/src/omni-bridge/contracts/HlBridgeToken.sol`)

### Summary

`coreReceiveWithData` dispatches `ACTION_TRANSFER` without checking whether the decoded `recipient` equals `address(this)`. A HyperCore user can craft a `sendToEvmWithData` payload that routes tokens into the token contract itself. A subsequent `ACTION_INIT_TRANSFER` call burns only its own `amount` from `address(this)`, leaving the earlier deposit permanently stranded with no recovery path.

### Finding Description

`coreReceiveWithData` accepts two action types. For `ACTION_TRANSFER` (tag `0x00`), it decodes an `address recipient` from the tail of `data` and calls `_update(_systemAddress, recipient, amount)` with no guard against `recipient == address(this)`: [1](#0-0) 

For `ACTION_INIT_TRANSFER` (tag `0x01`), it moves `amount` from `_systemAddress` to `address(this)`, then calls `OmniBridge.initTransfer(address(this), amount128, ...)`: [2](#0-1) 

`OmniBridge.initTransfer` recognises the token as a `BridgeToken` and calls `BridgeToken(tokenAddress).burn(msg.sender, amount)`, where `msg.sender` is the HlBridgeToken contract itself: [3](#0-2) 

`BridgeToken.burn` calls `_burn(account, value)` for exactly `value = amount`, not for the full balance of `address(this)`: [4](#0-3) 

**Exploit sequence:**

1. HyperCore user A calls `sendToEvmWithData` with `data = 0x00 || abi.encode(tokenContractAddress)` and `amount = X`. The HyperLiquid system address relays this to `coreReceiveWithData`, executing `_update(_systemAddress, address(this), X)`. The token contract now holds X tokens.

2. HyperCore user B (or A again) calls `sendToEvmWithData` with `data = 0x01 || abi.encode(fee, recipient, message)` and `amount = Y` where `Y ≠ X`. The system address relays this, executing `_update(_systemAddress, address(this), Y)` (contract now holds `X + Y`), then `burn(address(this), Y)` (contract now holds `X`).

After both calls, X tokens are permanently locked in the HlBridgeToken contract. There is no sweep, rescue, or admin-withdrawal function anywhere in `HlBridgeToken` or `BridgeToken`. [5](#0-4) 

### Impact Explanation

X tokens are permanently frozen at `address(this)`. They cannot be recovered without a UUPS proxy upgrade. The HyperCore-side pool (`_systemAddress`) has already been debited, so the accounting drift is permanent: HyperCore believes X tokens were transferred to HyperEVM, but they are locked in the contract with no corresponding user credit. This is a direct, irrecoverable loss of bridged funds.

### Likelihood Explanation

The only gate is `msg.sender != _systemAddress`. The system address is a trusted relay that forwards whatever `data` a HyperCore user supplies via `sendToEvmWithData`. A malicious (or mistaken) user can supply `recipient = tokenContractAddress` trivially. No special privilege is required beyond being a HyperCore user. The two calls do not need to be from the same user or in the same transaction.

### Recommendation

Add a self-address guard in the `ACTION_TRANSFER` branch:

```solidity
if (action == ACTION_TRANSFER) {
    address recipient = abi.decode(tail, (address));
    require(recipient != address(this), "InvalidRecipient");
    _update(_systemAddress, recipient, amount);
}
```

Additionally, consider making `ACTION_INIT_TRANSFER` burn the full balance of `address(this)` rather than exactly `amount128`, so any pre-existing balance is not silently stranded.

### Proof of Concept

```solidity
// Setup: token is a HyperliquedBridgeToken with _systemAddress seeded with 1500 tokens
// tokenAddress = address(token)

// Step 1: system address calls ACTION_TRANSFER with recipient = tokenAddress, amount = 500
bytes memory data1 = abi.encodePacked(
    uint8(0), // ACTION_TRANSFER
    abi.encode(tokenAddress)
);
vm.prank(systemAddress);
token.coreReceiveWithData(attacker, bytes32(0), 0, 500, 0, data1);
// token.balanceOf(tokenAddress) == 500

// Step 2: system address calls ACTION_INIT_TRANSFER with amount = 1000
bytes memory data2 = abi.encodePacked(
    uint8(1), // ACTION_INIT_TRANSFER
    abi.encode(uint128(10), "near:alice.near", "")
);
vm.prank(systemAddress);
token.coreReceiveWithData(attacker, bytes32(0), 0, 1000, 0, data2);
// OmniBridge.initTransfer burns 1000 from tokenAddress
// token.balanceOf(tokenAddress) == 500  <-- permanently stranded
// token.totalSupply() == 500            <-- 500 tokens unaccounted for
assertEq(token.balanceOf(tokenAddress), 500);
```

### Citations

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L106-141)
```text
    function coreReceiveWithData(
        address from,
        bytes32 /*destinationRecipient*/,
        uint32 /*destinationChainId*/,
        uint256 amount,
        uint64 /*coreNonce*/,
        bytes calldata data
    ) external override {
        if (msg.sender != _systemAddress) revert NotSystemAddress();
        if (data.length == 0) revert EmptyActionData();

        uint8 action = uint8(data[0]);
        bytes calldata tail = data[1:];

        if (action == ACTION_TRANSFER) {
            address recipient = abi.decode(tail, (address));
            _update(_systemAddress, recipient, amount);
        } else if (action == ACTION_INIT_TRANSFER) {
            (uint128 fee, string memory recipient, string memory message) = abi
                .decode(tail, (uint128, string, string));
            uint128 amount128 = amount.toUint128();
            _update(_systemAddress, address(this), amount);
            IOmniBridgeInitTransfer(owner()).initTransfer(
                address(this),
                amount128,
                fee,
                0,
                recipient,
                message
            );
        } else {
            revert UnknownAction(action);
        }

        emit CoreReceived(from, action, amount, data);
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L404-405)
```text
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
```

**File:** evm/src/omni-bridge/contracts/BridgeToken.sol (L62-64)
```text
    function burn(address account, uint256 value) external onlyOwner {
        _burn(account, value);
    }
```
