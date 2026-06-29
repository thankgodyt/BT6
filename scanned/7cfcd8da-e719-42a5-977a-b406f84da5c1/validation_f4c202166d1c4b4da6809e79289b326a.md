### Title
Missing Storage Gap in `BridgeToken` Corrupts `HyperliquedBridgeToken._systemAddress` on Upgrade — (File: `evm/src/omni-bridge/contracts/BridgeToken.sol`)

---

### Summary

`BridgeToken` is a UUPS-upgradeable contract that declares three storage variables without a trailing `__gap`. `HyperliquedBridgeToken` inherits `BridgeToken` and places its critical `_systemAddress` field immediately after those variables. If `BridgeToken` is ever upgraded to add a new storage variable, `_systemAddress` shifts to an uninitialised slot (reads as `address(0)`), causing every subsequent 3-arg `mint` call to burn the bridged tokens instead of parking them at the HyperCore system address — a permanent loss of bridged funds.

---

### Finding Description

**Root cause — `BridgeToken` has no storage gap:**

`BridgeToken` declares three storage variables and ends there with no `__gap`:

```
slot 0  string internal _name
slot 1  string internal _symbol
slot 2  uint8  internal _decimals
        (no __gap)
``` [1](#0-0) 

`HyperliquedBridgeToken` inherits `BridgeToken` and appends `_systemAddress` at the very next slot:

```
slot 3  address internal _systemAddress   ← HyperliquedBridgeToken
``` [2](#0-1) 

**What happens on upgrade:**

If `BridgeToken` is upgraded to a new implementation that adds even one new storage variable (e.g., `address _newVar` at slot 3), the storage layout of every `HyperliquedBridgeToken` proxy becomes:

```
slot 0  _name          (BridgeToken v2)
slot 1  _symbol        (BridgeToken v2)
slot 2  _decimals      (BridgeToken v2)
slot 3  _newVar        (BridgeToken v2)   ← collides with old _systemAddress
slot 4  _systemAddress (HyperliquedBridgeToken) ← shifted, reads as 0
```

The proxy's storage is not re-initialised on upgrade, so `_systemAddress` now reads from slot 4, which was never written and contains `address(0)`.

**Upgrade path that triggers this:**

The admin calls `OmniBridge.upgradeToken()`, which calls `proxy.upgradeToAndCall(newImpl, "")` on any registered bridge-token proxy: [3](#0-2) 

**Concrete impact on `mint(address, uint256, bytes)`:**

The 3-arg `mint` is the HyperCore inbound path. It mints tokens to `account` and then moves them to `_systemAddress` to track the HyperCore-side balance:

```solidity
_mint(account, value);
_update(account, _systemAddress, value);   // _systemAddress == address(0) after corruption
``` [4](#0-3) 

`ERC20._update(src, address(0), amount)` is a **burn**. Every token minted for a NEAR→HyperCore transfer is immediately destroyed. The user's bridged funds are permanently lost.

**`coreReceiveWithData` is also broken:**

The guard `if (msg.sender != _systemAddress)` always reverts when `_systemAddress == 0` (no EOA or contract can have `msg.sender == address(0)`), permanently freezing the HyperCore→HyperEVM withdrawal path as well. [5](#0-4) 

**Contrast with `OmniBridge` (correctly implemented):**

`OmniBridge` itself correctly reserves 49 slots with `uint256[49] private __gap`, demonstrating the team is aware of the pattern — but this protection was not applied to `BridgeToken`. [6](#0-5) 

---

### Impact Explanation

Any NEAR→HyperCore transfer finalised after a `BridgeToken` upgrade that adds storage results in the bridged tokens being burned on arrival. The user's funds are permanently destroyed. This matches the allowed critical impact: *"loss … of bridged funds"* and *"balance manipulation … that changes user or protocol balances."*

---

### Likelihood Explanation

The trigger is a legitimate admin upgrade of `BridgeToken` — a routine maintenance action explicitly supported by `OmniBridge.upgradeToken()`. No attacker action is required; the loss occurs automatically for every `finTransfer` that routes through the 3-arg `mint` path after the upgrade. The admin need not be malicious or compromised; acting in good faith is sufficient to trigger the bug.

---

### Recommendation

Add a storage gap to `BridgeToken` immediately after `_decimals`:

```solidity
// BridgeToken.sol
string  internal _name;
string  internal _symbol;
uint8   internal _decimals;
uint256[47] private __gap;   // reserve slots 3–49 for future BridgeToken storage
```

This mirrors the pattern already used in `OmniBridge` and ensures that any future storage additions to `BridgeToken` consume from the gap rather than colliding with child-contract variables.

---

### Proof of Concept

1. Deploy a `HyperliquedBridgeToken` proxy via `OmniBridge.deployToken()`. `_systemAddress` is written to storage slot 3 during `initialize()`.
2. Upgrade `BridgeToken` implementation to `BridgeTokenV2` which adds `address _newVar` as a fourth field.
3. Admin calls `OmniBridge.upgradeToken(proxyAddr, bridgeTokenV2Impl)`.
4. The proxy now uses the `BridgeTokenV2` layout; slot 3 is `_newVar` (zero), slot 4 is `_systemAddress` (zero — never written).
5. A relayer calls `OmniBridge.finTransfer()` for a NEAR→HyperCore transfer; this calls `HyperliquedBridgeToken.mint(recipient, amount, message)`.
6. `_mint(recipient, amount)` succeeds; `_update(recipient, address(0), amount)` burns the tokens.
7. `recipient` receives zero tokens; the bridged funds are permanently lost.

### Citations

**File:** evm/src/omni-bridge/contracts/BridgeToken.sol (L17-19)
```text
    string internal _name;
    string internal _symbol;
    uint8 internal _decimals;
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L32-36)
```text
contract HyperliquedBridgeToken is BridgeToken, ICoreReceiveWithData {
    using SafeCast for uint256;

    address internal _systemAddress;
    bytes32 constant HYPER_CORE_DEPLOYER_SLOT = keccak256("HyperCore deployer");
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L76-83)
```text
    function mint(
        address account,
        uint256 value,
        bytes memory
    ) external override onlyOwner {
        _mint(account, value);
        _update(account, _systemAddress, value);
    }
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L113-115)
```text
    ) external override {
        if (msg.sender != _systemAddress) revert NotSystemAddress();
        if (data.length == 0) revert EmptyActionData();
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L559-566)
```text
    function upgradeToken(
        address tokenAddress,
        address implementation
    ) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(isBridgeToken[tokenAddress], "ERR_NOT_BRIDGE_TOKEN");
        BridgeToken proxy = BridgeToken(tokenAddress);
        proxy.upgradeToAndCall(implementation, bytes(""));
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L598-598)
```text
    uint256[49] private __gap;
```
