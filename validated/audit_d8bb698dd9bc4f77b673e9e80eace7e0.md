### Title
Fee-on-Transfer Token Escrow Mis-Accounting in `initTransfer` - (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge::initTransfer` locks native ERC20 tokens by calling `safeTransferFrom(msg.sender, address(this), amount)` and then unconditionally emits `InitTransfer` with the caller-supplied `amount`. For fee-on-transfer tokens, the bridge receives fewer tokens than `amount`, but the emitted event — which the NEAR hub uses to credit the recipient — records the full `amount`. This creates a permanent escrow shortfall: the bridge is undercollateralized for that token from the moment of the first such deposit.

---

### Finding Description

In `OmniBridge::initTransfer`, the branch handling ordinary (non-bridge, non-custom-minter) ERC20 tokens is:

```solidity
} else {
    IERC20(tokenAddress).safeTransferFrom(
        msg.sender,
        address(this),
        amount          // requested amount, not actual received
    );
}
``` [1](#0-0) 

Immediately after, the function emits:

```solidity
emit BridgeTypes.InitTransfer(
    msg.sender,
    tokenAddress,
    currentOriginNonce,
    amount,             // ← always the caller-supplied value
    fee,
    nativeFee,
    recipient,
    message
);
``` [2](#0-1) 

The `InitTransfer` event definition confirms `amount` is a plain `uint128` field with no on-chain verification that it equals what was actually received: [3](#0-2) 

For a fee-on-transfer token (e.g., one that deducts 1% on every transfer), `safeTransferFrom` succeeds but deposits only `amount * 0.99` into the bridge. The emitted event still carries `amount`. The NEAR hub reads this event and mints/credits the full `amount` to the recipient on NEAR. No balance-before/after check exists anywhere in the call path to detect the discrepancy.

The same mis-accounting applies to the `OmniBridgeWormhole` subclass, which publishes the caller-supplied `amount` into the Wormhole message payload via `initTransferExtension`: [4](#0-3) 

---

### Impact Explanation

Every deposit of a fee-on-transfer token creates a gap between the bridge's actual ERC20 balance and the total amount credited on NEAR. An attacker who controls or uses such a token can:

1. Repeatedly call `initTransfer` with `amount = X`, depositing only `X*(1-fee_rate)` each time but receiving credit for `X` on NEAR.
2. Bridge the NEAR-side tokens back to EVM via `finTransfer`, which releases the full credited amount from the bridge's reserves.
3. Net gain per round-trip equals the fee amount; the bridge's ERC20 reserve is drained proportionally.

Eventually, legitimate users who deposited the same token cannot withdraw because the bridge holds insufficient collateral. This is a permanent, irreversible loss of bridged funds — matching the **escrow mis-accounting** impact class.

---

### Likelihood Explanation

The attack requires a fee-on-transfer ERC20 token to be registered and supported by the bridge (i.e., deployed on NEAR via `deployToken`, which requires an MPC signature). However:

- Several real tokens have had or currently have transfer fees (PAXG charges a fee; USDT has a dormant fee switch; many DeFi tokens implement fee-on-transfer mechanics).
- The bridge is designed to support arbitrary ERC20 tokens as "native" assets (the `else` branch is the general-purpose lock path).
- Once any such token is onboarded, every user interacting with it triggers the mis-accounting — no special attacker setup is needed beyond normal bridge usage.

Likelihood is **medium-high** given the breadth of tokens the bridge is intended to support.

---

### Recommendation

After calling `safeTransferFrom`, measure the actual received amount using a before/after balance check, and use that value in the emitted event and any downstream accounting:

```solidity
uint256 balanceBefore = IERC20(tokenAddress).balanceOf(address(this));
IERC20(tokenAddress).safeTransferFrom(msg.sender, address(this), amount);
uint256 actualReceived = IERC20(tokenAddress).balanceOf(address(this)) - balanceBefore;
require(actualReceived > 0, "Transfer produced no tokens");
// use actualReceived (cast to uint128) in the emit and extension calls
```

Alternatively, explicitly disallow fee-on-transfer tokens by requiring `actualReceived == amount` and documenting this as a protocol invariant.

---

### Proof of Concept

1. Deploy a fee-on-transfer ERC20 (1% fee) on EVM; have the bridge admin register it on NEAR via `deployToken`.
2. Attacker holds 1000 tokens. Calls `initTransfer(tokenAddress, 1000, 0, 0, "attacker.near", "")`.
3. Bridge receives 990 tokens (`safeTransferFrom` deducts 1% fee). Bridge emits `InitTransfer(..., amount=1000, ...)`.
4. NEAR prover/hub reads the event; mints 1000 tokens to `attacker.near`.
5. Attacker calls the NEAR bridge to send 1000 tokens back to EVM (`fin_transfer`). NEAR burns 1000 tokens and issues an MPC-signed `finTransfer` payload with `amount=1000`.
6. Attacker calls `finTransfer` on EVM; bridge releases 1000 tokens from its reserve.
7. Net result: attacker started with 1000 tokens, ends with 1000 tokens, but bridge reserve decreased by 10 tokens. Repeating this drains the reserve, making the bridge insolvent for that token. [5](#0-4)

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

**File:** evm/src/omni-bridge/contracts/BridgeTypes.sol (L23-32)
```text
    event InitTransfer(
        address indexed sender,
        address indexed tokenAddress,
        uint64 indexed originNonce,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string recipient,
        string message
    );
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
