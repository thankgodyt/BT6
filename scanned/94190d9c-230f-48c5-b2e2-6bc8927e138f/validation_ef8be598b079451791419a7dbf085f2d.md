### Title
Missing Storage Gap in `BridgeToken` Corrupts `HyperliquedBridgeToken._systemAddress` on Upgrade — (`File: evm/src/omni-bridge/contracts/BridgeToken.sol`)

---

### Summary

`BridgeToken` is an upgradeable contract that declares three storage variables but defines no `__gap`. `HyperliquedBridgeToken` inherits from `BridgeToken` and appends its own critical storage variable `_systemAddress`. If `BridgeToken` is ever upgraded to introduce a new storage variable, the storage layout of every deployed `HyperliquedBridgeToken` proxy is silently corrupted, overwriting `_systemAddress` with an unintended value and causing permanent loss of bridged funds.

---

### Finding Description

`BridgeToken` is a UUPS-upgradeable ERC-20 implementation that declares three storage variables in its linear storage layout:

```
_name    (string)   — slot N
_symbol  (string)   — slot N+1
_decimals (uint8)   — slot N+2
``` [1](#0-0) 

It does **not** declare a `__gap` array. The only contract in the codebase that does declare a gap is `OmniBridge` itself. [2](#0-1) 

`HyperliquedBridgeToken` inherits `BridgeToken` and appends one additional storage variable immediately after `_decimals`:

```
_systemAddress (address) — slot N+3
``` [3](#0-2) 

Because `BridgeToken` has no `__gap`, any future upgrade that adds even a single new variable to `BridgeToken` shifts `_systemAddress` from slot `N+3` to slot `N+4`. The proxy's storage still holds the real system address at slot `N+3`, but the new implementation reads `_systemAddress` from slot `N+4`, which is zero (`address(0)`).

---

### Impact Explanation

`_systemAddress` is used in two security-critical paths inside `HyperliquedBridgeToken`:

**1. Token accounting in `mint(address, uint256, bytes)`:**

```solidity
function mint(address account, uint256 value, bytes memory) external override onlyOwner {
    _mint(account, value);
    _update(account, _systemAddress, value);   // <-- _systemAddress corrupted to address(0)
}
``` [4](#0-3) 

`_update(account, address(0), value)` is an ERC-20 burn. Every inbound bridge transfer that routes through the HyperCore mint path would silently burn the minted tokens instead of parking them at the system address. Users receive nothing; funds are permanently destroyed.

**2. Access control in `coreReceiveWithData`:**

```solidity
if (msg.sender != _systemAddress) revert NotSystemAddress();
``` [5](#0-4) 

With `_systemAddress == address(0)`, this check always reverts for any real caller, permanently bricking the HyperCore → HyperEVM withdrawal path.

Both outcomes constitute **permanent freezing or loss of bridged funds**, satisfying the critical impact threshold.

---

### Likelihood Explanation

The Omni Bridge EVM contracts are explicitly designed to be upgradeable (UUPS pattern, `_disableInitializers` in constructors, `_authorizeUpgrade` guards). `BridgeToken` is the shared implementation for all deployed bridge tokens. Adding a new feature variable to `BrodgeToken` (e.g., a fee flag, a metadata field, a permit nonce) is a routine protocol evolution. The missing gap makes every such upgrade silently dangerous for all `HyperliquedBridgeToken` proxies without any on-chain warning.

---

### Recommendation

Add a `__gap` to `BridgeToken` to reserve upgrade headroom, sized so that the total storage footprint of `BridgeToken` reaches a round number (e.g., 50 slots):

```solidity
// BridgeToken.sol — after _decimals
uint256[47] private __gap;  // 3 existing vars + 47 gap = 50 slots reserved
``` [1](#0-0) 

Similarly, add a `__gap` to `HyperliquedBridgeToken` itself so that it too can be extended safely in the future:

```solidity
// HlBridgeToken.sol — after _systemAddress
uint256[49] private __gap;
``` [6](#0-5) 

---

### Proof of Concept

**Inheritance chain (no gap highlighted):**

```mermaid
graph BT
    "HyperliquedBridgeToken" --> "BridgeToken (NO GAP)"
    "BridgeToken (NO GAP)" --> "ERC20Upgradeable (has gap)"
    "BridgeToken (NO GAP)" --> "Ownable2StepUpgradeable (has gap)"
    "BridgeToken (NO GAP)" --> "UUPSUpgradeable (has gap)"
```

**Storage layout before upgrade:**

| Slot | Variable | Contract |
|------|----------|----------|
| N | `_name` | BridgeToken |
| N+1 | `_symbol` | BridgeToken |
| N+2 | `_decimals` | BridgeToken |
| N+3 | `_systemAddress` | HyperliquedBridgeToken |

**Storage layout after `BridgeToken` adds `address newFeatureVar`:**

| Slot | Variable read by new impl | Proxy storage (unchanged) |
|------|--------------------------|--------------------------|
| N | `_name` | `_name` |
| N+1 | `_symbol` | `_symbol` |
| N+2 | `_decimals` | `_decimals` |
| N+3 | `newFeatureVar` | **old `_systemAddress` value** |
| N+4 | `_systemAddress` | **zero (uninitialized)** |

The new implementation reads `_systemAddress` as `address(0)`. Every subsequent call to `mint(address, uint256, bytes)` burns the minted tokens via `_update(account, address(0), value)`, and every call to `coreReceiveWithData` reverts, permanently freezing the HyperCore bridge path. [7](#0-6) [8](#0-7)

### Citations

**File:** evm/src/omni-bridge/contracts/BridgeToken.sol (L10-24)
```text
contract BridgeToken is
    Initializable,
    UUPSUpgradeable,
    ERC20Upgradeable,
    Ownable2StepUpgradeable,
    IBridgeToken
{
    string internal _name;
    string internal _symbol;
    uint8 internal _decimals;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L598-598)
```text
    uint256[49] private __gap;
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L32-36)
```text
contract HyperliquedBridgeToken is BridgeToken, ICoreReceiveWithData {
    using SafeCast for uint256;

    address internal _systemAddress;
    bytes32 constant HYPER_CORE_DEPLOYER_SLOT = keccak256("HyperCore deployer");
```

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L53-74)
```text
    function initialize(
        string memory name_,
        string memory symbol_,
        uint8 decimals_,
        address systemAddress_,
        address hyperCoreDeployer_
    ) external initializer {
        __ERC20_init(name_, symbol_);
        __UUPSUpgradeable_init();
        __Ownable_init(_msgSender());

        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
        _systemAddress = systemAddress_;

        bytes32 hyperCoreDeployerSlot = HYPER_CORE_DEPLOYER_SLOT;
        assembly {
            sstore(hyperCoreDeployerSlot, hyperCoreDeployer_)
        }
        emit HyperCoreDeployerSet(hyperCoreDeployer_);
    }
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

**File:** evm/src/omni-bridge/contracts/HlBridgeToken.sol (L114-114)
```text
        if (msg.sender != _systemAddress) revert NotSystemAddress();
```
