### Title
`ENearProxy.burn` Hardcodes Empty NEAR Recipient, Causing Permanent Fund Loss — (`evm/src/eNear/contracts/ENearProxy.sol`)

### Summary

`ENearProxy.burn` unconditionally calls `eNear.transferToNear(amount, string(""))` with a hardcoded empty NEAR recipient string. Because the `ICustomMinter.burn` interface does not carry a `recipient` parameter, the user's intended NEAR account ID supplied to `OmniBridge.initTransfer` is structurally unreachable inside `ENearProxy.burn`. Any eNear bridging attempt through OmniBridge burns the user's tokens on EVM while emitting a `transferToNear` event with an empty recipient, resulting in permanent loss of the bridged amount.

### Finding Description

**Call chain:**

1. User calls `OmniBridge.initTransfer(eNearAddress, amount, fee, nativeFee, recipient, message)`.
2. Because `customMinters[eNearAddress] == ENearProxy`, the bridge executes: [1](#0-0) 

```solidity
IERC20(tokenAddress).safeTransferFrom(msg.sender, customMinters[tokenAddress], amount);
ICustomMinter(customMinters[tokenAddress]).burn(tokenAddress, amount);
```

3. `ENearProxy.burn` is invoked. Its implementation is: [2](#0-1) 

```solidity
function burn(address token, uint128 amount) public onlyRole(MINTER_ROLE) {
    require(token == address(eNear), "ERR_INCORRECT_ENEAR_ADDRESS");
    eNear.transferToNear(amount, string(""));   // ← hardcoded empty recipient
}
```

**Root cause — interface mismatch:** The `ICustomMinter` interface defines `burn` as: [3](#0-2) 

```solidity
function burn(address token, uint128 amount) external;
```

There is no `recipient` parameter. The user's NEAR account ID, passed as `recipient` to `initTransfer`, is forwarded only to `initTransferExtension` and the `InitTransfer` event — it is **never reachable** inside `ENearProxy.burn`. The function therefore always calls `eNear.transferToNear` with `""`. [4](#0-3) 

The `InitTransfer` event carries the correct recipient for the new omni-bridge relayer, but the legacy eNear NEAR-side connector listens to the `transferToNear` event emitted by the eNear contract — which carries the empty string. The NEAR connector will either reject the transfer (funds stuck/burned with no credit) or attempt to credit an empty account ID (invalid, funds lost).

### Impact Explanation

User eNear tokens are transferred from the user to ENearProxy and then burned via `eNear.transferToNear(amount, "")`. The EVM-side burn is irreversible. The NEAR-side credit never reaches the user's account because the recipient field is empty. Funds are permanently lost.

### Likelihood Explanation

This is triggered by any user calling `OmniBridge.initTransfer` for the eNear token once ENearProxy is registered as its custom minter — a standard, documented deployment configuration. No special permissions or attacker-controlled state are required beyond a normal user interaction. The precondition (eNear registered with ENearProxy as custom minter, OmniBridge granted `MINTER_ROLE` on ENearProxy) is the intended production setup.

### Recommendation

The `ICustomMinter` interface must be extended to include the NEAR recipient:

```solidity
function burn(address token, uint128 amount, string calldata recipient) external;
```

`OmniBridge.initTransfer` must pass `recipient` through to `ICustomMinter.burn`, and `ENearProxy.burn` must forward it to `eNear.transferToNear`:

```solidity
function burn(address token, uint128 amount, string calldata recipient) public onlyRole(MINTER_ROLE) {
    require(token == address(eNear), "ERR_INCORRECT_ENEAR_ADDRESS");
    eNear.transferToNear(amount, recipient);
}
```

### Proof of Concept

```solidity
// Precondition: eNear registered in OmniBridge with ENearProxy as customMinter,
//               OmniBridge has MINTER_ROLE on ENearProxy.

// 1. User approves OmniBridge to spend eNear
eNear.approve(address(omniBridge), 1e18);

// 2. User initiates bridge transfer to their NEAR account
omniBridge.initTransfer(
    address(eNear),
    1e18,
    0,
    0,
    "alice.near",   // intended recipient — never reaches eNear.transferToNear
    ""
);

// 3. ENearProxy.burn calls eNear.transferToNear(1e18, "")
//    → transferToNear event emitted with empty nearReceiverAccountId
//    → NEAR-side connector receives transfer to "" — invalid account
//    → User's 1e18 eNear burned on EVM, no credit on NEAR
``` [2](#0-1) [3](#0-2) [1](#0-0)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L394-403)
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
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L415-426)
```text
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

```

**File:** evm/src/eNear/contracts/ENearProxy.sol (L75-78)
```text
    function burn(address token, uint128 amount) public onlyRole(MINTER_ROLE) {
        require(token == address(eNear), "ERR_INCORRECT_ENEAR_ADDRESS");
        eNear.transferToNear(amount, string(""));
    }
```

**File:** evm/src/common/ICustomMinter.sol (L4-7)
```text
interface ICustomMinter {
    function mint(address token, address to, uint128 amount) external;
    function burn(address token, uint128 amount) external;
}
```
