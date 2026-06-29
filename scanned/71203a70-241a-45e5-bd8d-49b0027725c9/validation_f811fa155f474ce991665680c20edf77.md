### Title
Missing Storage Gap in `BridgeToken` Corrupts `HyperliquedBridgeToken._systemAddress` on Upgrade — (`evm/src/omni-bridge/contracts/BridgeToken.sol`)

---

### Summary

`BridgeToken` is an upgradeable parent contract with three state variables (`_name`, `_symbol`, `_decimals`) but **no `__gap`** storage reserve. `HyperliquedBridgeToken` inherits from `BridgeToken` and appends `_systemAddress` immediately after those variables. Because no gap exists, any future upgrade that adds a new variable to `BridgeToken` will overwrite `_systemAddress` in `HyperliquedBridgeToken`, breaking the sole authorization gate in `coreReceiveWithData` and enabling unauthorized token transfers.

---

### Finding Description

The inheritance chain is:

```
HyperliquedBridgeToken
    └── BridgeToken          ← has state vars, NO __gap
            ├── ERC20Upgradeable      (has __gap via OZ)
            ├── Ownable2StepUpgradeable (has __gap via OZ)
            └── UUPSUpgradeable       (has __gap via OZ)
```

`BridgeToken` declares three storage variables with no trailing gap: [1](#0-0) 

`HyperliquedBridgeToken` inherits `BridgeToken` and appends `_systemAddress` directly after those variables: [2](#0-1) 

`_systemAddress` is the **sole authorization gate** for the `coreReceiveWithData` entry point: [3](#0-2) 

`OmniBridge` (the other branch of the hierarchy) correctly reserves a gap: [4](#0-3) 

`BridgeToken` has no equivalent gap. The `CLAUDE.md` security invariant explicitly acknowledges the upgrade storage safety requirement: [5](#0-4) 

Yet `BridgeToken` violates this invariant by omitting the gap entirely.

---

### Impact Explanation

If the admin upgrades a `HyperliquedBridgeToken` proxy to a new implementation where `BridgeToken` has gained even one new storage variable (e.g., a `paused` flag or a metadata version counter), the storage slot previously occupied by `_systemAddress` is now occupied by that new variable. The value read from `_systemAddress` becomes whatever was written to that slot by the new variable's initializer — most likely `address(0)` or an attacker-controlled value.

With `_systemAddress` corrupted to `address(0)`:
- Any caller can pass `msg.sender == address(0)` — impossible in practice — but more critically, if corrupted to a non-zero attacker-controlled value, the attacker can call `coreReceiveWithData` directly.
- `ACTION_TRANSFER` path: `_update(_systemAddress, recipient, amount)` drains the system address token pool to an arbitrary recipient.
- `ACTION_INIT_TRANSFER` path: initiates an unauthorized cross-chain bridge transfer, burning tokens from the pool.

This constitutes **unauthorized token transfer / balance manipulation** of bridged funds.

---

### Likelihood Explanation

The trigger is a legitimate admin upgrade of `BridgeToken` that adds a new state variable — a routine protocol maintenance action. The admin may not realize the storage collision because `BridgeToken` appears self-contained. The `upgradeToken` function on `OmniBridge` is the direct entry point: [6](#0-5) 

No attacker action is required to trigger the corruption; the admin's own upgrade causes it. Exploitation of the corrupted state is then open to any external caller.

---

### Recommendation

Add a `__gap` to `BridgeToken` to reserve storage space for future variables, reducing the gap size when new variables are added:

```solidity
// In BridgeToken.sol, after _decimals:
uint256[47] private __gap;
```

The gap size should be chosen so that `BridgeToken`'s total storage footprint (own slots + gap) is a fixed round number (e.g., 50 slots), matching the pattern used in `OmniBridge`.

---

### Proof of Concept

**Current storage layout of a `HyperliquedBridgeToken` proxy (simplified, after OZ parent slots):**

| Slot (relative) | Variable | Contract |
|---|---|---|
| N | `_name` | `BridgeToken` |
| N+1 | `_symbol` | `BridgeToken` |
| N+2 | `_decimals` (packed) | `BridgeToken` |
| N+3 | `_systemAddress` | `HyperliquedBridgeToken` |

**After upgrading to a new `BridgeToken` implementation that adds `uint256 _version` after `_decimals`:**

| Slot (relative) | Variable | Contract |
|---|---|---|
| N | `_name` | `BridgeToken` |
| N+1 | `_symbol` | `BridgeToken` |
| N+2 | `_decimals` (packed) | `BridgeToken` |
| N+3 | `_version` ← **new** | `BridgeToken` |
| N+4 | `_systemAddress` ← **shifted** | `HyperliquedBridgeToken` |

Slot N+3 now holds `_version = 0` (default), while the proxy's storage at N+3 still holds the old `_systemAddress` value — which is now read as `_version`. Meanwhile, `_systemAddress` is read from N+4, which holds `0` (never written), effectively zeroing out the authorization check.

An attacker then calls:
```solidity
// msg.sender == address(0) is impossible, but if _systemAddress == address(0):
// The check `if (msg.sender != _systemAddress)` becomes `if (msg.sender != address(0))`
// which passes for any non-zero caller — i.e., every real caller.
hyperliquedToken.coreReceiveWithData(
    attacker, 0, 0, amount, 0,
    abi.encodePacked(uint8(0), abi.encode(attacker)) // ACTION_TRANSFER to attacker
);
```

This drains the system address token pool to the attacker.

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

**File:** evm/CLAUDE.md (L37-37)
```markdown
- **Upgrade storage safety**: Never reorder or remove existing storage variables. Add new variables only before the `__gap` and decrease gap size accordingly
```
