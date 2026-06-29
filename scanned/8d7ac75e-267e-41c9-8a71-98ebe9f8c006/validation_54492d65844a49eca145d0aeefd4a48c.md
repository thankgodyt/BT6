### Title
Fee-on-Transfer Token Deposit Overstates Locked Amount in `InitTransfer` Event — (`File: evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

The EVM `OmniBridge.sol` `initTransfer` function emits the caller-supplied `amount` in the `InitTransfer` event rather than the actual tokens received by the contract. For fee-on-transfer (deflationary) ERC20 tokens, the contract receives fewer tokens than `amount`, but the NEAR bridge processes the event and credits the full `amount`. This creates a persistent escrow shortfall: the EVM bridge holds less than it has promised to release, causing later withdrawers to lose funds.

---

### Finding Description

In `initTransfer`, for a plain ERC20 token (not a bridge token and not a custom minter), the contract executes:

```solidity
IERC20(tokenAddress).safeTransferFrom(
    msg.sender,
    address(this),
    amount          // nominal amount, actual credit may be less
);
``` [1](#0-0) 

Immediately after, the event is emitted with the same caller-supplied `amount`:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,          // not the actual received balance delta
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

No balance-before / balance-after measurement is performed. For a token that deducts a percentage on every transfer, `address(this)` receives `amount * (1 - fee_rate)`, but the event records `amount`. The NEAR bridge reads this event and credits the full `amount` to the recipient on NEAR.

The `initTransferExtension` call also forwards the unchecked `amount`: [3](#0-2) 

---

### Impact Explanation

**Critical — escrow mis-accounting / loss of bridged funds.**

Each deposit of a fee-on-transfer token inflates the NEAR-side credit by the fee percentage. The EVM bridge accumulates a growing shortfall. When users later bridge back (EVM `finTransfer` unlocks tokens), the contract will eventually be unable to pay out the full amount to all users. The first withdrawers receive their full amount; later withdrawers receive less or nothing, exactly mirroring the Alice/Bob/Eve scenario in the report. Funds are permanently lost for later withdrawers.

---

### Likelihood Explanation

Any fee-on-transfer ERC20 token that has been registered via `log_metadata` and has a corresponding NEAR token mapping is exploitable by any unprivileged user simply calling `initTransfer`. No special role or admin access is required. The attacker does not need to be malicious — ordinary users of such a token trigger the bug automatically.

---

### Recommendation

Measure the actual received amount using a balance snapshot:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
// use actualReceived in the event and extension call, not amount
```

Alternatively, explicitly disallow fee-on-transfer tokens by requiring `actualReceived == amount` and reverting otherwise.

---

### Proof of Concept

1. Register a fee-on-transfer ERC20 token (e.g., 1% fee per transfer) through the normal `log_metadata` → `deploy_token` flow on NEAR.
2. Alice calls `initTransfer(tokenAddress, 1000, 0, 0, "alice.near", "")`. Contract receives 990 tokens. Event emits `amount = 1000`. NEAR credits Alice 1000.
3. Bob calls `initTransfer(tokenAddress, 1000, 0, 0, "bob.near", "")`. Contract receives 990 tokens. Event emits `amount = 1000`. NEAR credits Bob 1000.
4. Eve calls `initTransfer(tokenAddress, 1000, 0, 0, "eve.near", "")`. Contract receives 990 tokens. Event emits `amount = 1000`. NEAR credits Eve 1000.
5. EVM bridge now holds 2970 tokens but has promised 3000.
6. Alice bridges back 1000 → receives 1000 (bridge holds 1970).
7. Bob bridges back 1000 → receives 1000 (bridge holds 970).
8. Eve bridges back 1000 → bridge only holds 970, Eve loses 30 tokens.

The shortfall grows with each additional depositor, and the loss is borne entirely by later withdrawers.

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L407-412)
```text
                IERC20(tokenAddress).safeTransferFrom(
                    msg.sender,
                    address(this),
                    amount
                );
            }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L415-425)
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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L427-436)
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
```
