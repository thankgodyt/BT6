### Title
Reentrancy via Malicious ERC-1155 Token in `initTransfer1155` Allows Minting on NEAR Without Locking Tokens on EVM — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`initTransfer1155` reads the storage variable `currentOriginNonce` **after** an external call to an untrusted ERC-1155 token's `safeTransferFrom`. A malicious ERC-1155 token can reenter `initTransfer1155` during that call, causing both the reentrant and the original invocation to emit `InitTransfer` with the **same nonce** while locking **zero tokens**. The NEAR bridge processes the event once and mints tokens on NEAR with no corresponding collateral locked on EVM.

---

### Finding Description

In `initTransfer1155`, the nonce is incremented at the top of the function, but `currentOriginNonce` is a **storage variable** that is read again — after the external ERC-1155 call — when it is passed to `initTransferExtension` and to `emit BridgeTypes.InitTransfer`. [1](#0-0) 

```solidity
currentOriginNonce += 1;          // storage written: nonce = N
``` [2](#0-1) 

```solidity
IERC1155(tokenAddress).safeTransferFrom(   // ← untrusted external call
    msg.sender, address(this), tokenId, amount, ""
);
``` [3](#0-2) 

```solidity
initTransferExtension(
    msg.sender, deterministicToken,
    currentOriginNonce,            // ← storage read AFTER external call
    ...
);
emit BridgeTypes.InitTransfer(
    msg.sender, deterministicToken,
    currentOriginNonce,            // ← storage read AFTER external call
    ...
);
```

There is **no `nonReentrant` guard** on this function. The two `slither-disable` comments in the file suppress static-analysis warnings but provide no runtime protection. [4](#0-3) 

**Attack trace (storage starts at `currentOriginNonce = 0`):**

| Step | Who | Action | `currentOriginNonce` |
|---|---|---|---|
| 1 | Bridge (original call) | `+= 1` | **1** |
| 2 | Malicious ERC-1155 | reenter `initTransfer1155` | — |
| 3 | Bridge (reentrant call) | `+= 1` | **2** |
| 4 | Malicious ERC-1155 | does NOT reenter; transfers 0 tokens | — |
| 5 | Bridge (reentrant call) | reads `currentOri

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L44-45)
```text
    mapping(uint64 => bool) public completedTransfers;
    uint64 public currentOriginNonce;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L448-448)
```text
        currentOriginNonce += 1;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L458-464)
```text
        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L468-489)
```text
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
```
