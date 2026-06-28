### Title
Missing Zero-Address Validation for `_adminAddress` in `ENearProxy.initialize` - (File: `evm/src/eNear/contracts/ENearProxy.sol`)

### Summary
`ENearProxy.initialize` grants `DEFAULT_ADMIN_ROLE` to a caller-supplied `_adminAddress` with no zero-address guard. If initialized with `address(0)`, admin control is permanently burned: no account can ever hold `DEFAULT_ADMIN_ROLE`, making `MINTER_ROLE` grants, UUPS upgrades, and fine-grained pause control permanently inaccessible. Because `ENearProxy` is registered as the `customMinter` for the eNear token in `OmniBridge`, this permanently freezes cross-chain eNear minting.

### Finding Description
In `ENearProxy.initialize`, the call

```solidity
_grantRole(DEFAULT_ADMIN_ROLE, _adminAddress);
```

is executed without any non-zero check on `_adminAddress`. [1](#0-0) 

`DEFAULT_ADMIN_ROLE` is the OpenZeppelin role that gates three critical capabilities:

1. **Role management** – only `DEFAULT_ADMIN_ROLE` holders can call `grantRole`/`revokeRole`, including granting `MINTER_ROLE`.
2. **UUPS upgrade authorization** – `_authorizeUpgrade` is `onlyRole(DEFAULT_ADMIN_ROLE)`.
3. **Fine-grained pause** – `pause(uint256 flags)` is `onlyRole(DEFAULT_ADMIN_ROLE)`. [2](#0-1) 

If `_adminAddress == address(0)`, OpenZeppelin's `AccessControl` records the role as held by `address(0)`. No EOA or contract can ever satisfy `onlyRole(DEFAULT_ADMIN_ROLE)` because `_msgSender()` is never `address(0)` in a live transaction. The `initializer` modifier prevents re-initialization, so there is no recovery path.

Contrast this with `OmniBridge.initialize`, which avoids the problem by using `_msgSender()` directly instead of a parameter: [3](#0-2) 

`ENearProxy` uniquely exposes the vulnerability because it accepts `_adminAddress` as an external parameter with no validation.

### Impact Explanation
`MINTER_ROLE` can only be granted by a `DEFAULT_ADMIN_ROLE` holder. With admin burned to `address(0)`, `MINTER_ROLE` can never be assigned to any account, making `mint` and `burn` permanently inaccessible. [4](#0-3) 

`ENearProxy` is designed to be registered as the `customMinter` for the eNear token inside `OmniBridge` (via `addCustomToken`). When `OmniBridge` finalizes a NEAR→EVM transfer for eNear, it calls `ICustomMinter(customMinter).mint(...)`. If `mint` permanently reverts due to missing `MINTER_ROLE`, every NEAR→EVM eNear transfer is permanently unfinalizeable — bridged eNear funds are frozen on the NEAR side with no recovery. The contract also cannot be upgraded to fix the state, since `_authorizeUpgrade` is also gated on `DEFAULT_ADMIN_ROLE`.

**Impact class**: Permanent freezing of bridged funds; authorization bypass (no account can ever hold admin).

### Likelihood Explanation
The `initialize` function is `public` and callable by any deployer or deployment script. A misconfigured deployment (e.g., a script that passes a zero-initialized address variable, a deployment tool that omits the argument, or a factory that forwards a zero address) would silently succeed — there is no on-chain revert to signal the error. Because `initializer` prevents re-initialization, the mistake is irreversible. The likelihood is **low** in a careful manual deployment but non-negligible in scripted or factory-based deployments.

### Recommendation
Add a non-zero address guard before granting `DEFAULT_ADMIN_ROLE` in `ENearProxy.initialize`:

```solidity
require(_adminAddress != address(0), "ENearProxy: admin is zero address");
_grantRole(DEFAULT_ADMIN_ROLE, _adminAddress);
```

Apply the same guard to `_eNear` and `_prover` parameters, which are also stored without validation and are critical for correct operation.

### Proof of Concept
1. Deploy the `ENearProxy` implementation and a `ERC1967Proxy` pointing to it.
2. Call `initialize(eNearAddr, proverAddr, nearConnector, 0, address(0))`.
3. Confirm `hasRole(DEFAULT_ADMIN_ROLE, address(0))` returns `true`.
4. Attempt `grantRole(MINTER_ROLE, attacker)` from any EOA — reverts with `AccessControlUnauthorizedAccount`.
5. Attempt `mint(eNearAddr, recipient, 1e18)` — reverts with `AccessControlUnauthorizedAccount` (no `MINTER_ROLE` holder exists).
6. Attempt `upgradeToAndCall(newImpl, "")` — reverts (no `DEFAULT_ADMIN_ROLE` holder can authorize).
7. The contract is permanently bricked with no admin and no upgrade path.

### Citations

**File:** evm/src/eNear/contracts/ENearProxy.sol (L33-49)
```text
    function initialize(
        address _eNear,
        address _prover,
        bytes memory _nearConnector,
        uint256 _currentReceiptId,
        address _adminAddress
    ) public initializer {
        __UUPSUpgradeable_init();
        __AccessControl_init();
        __Pausable_init();
        eNear = IENear(_eNear);
        nearConnector = _nearConnector;
        currentReceiptId = _currentReceiptId;
        prover = INearProver(_prover);
        _grantRole(DEFAULT_ADMIN_ROLE, _adminAddress);
        _grantRole(PAUSABLE_ADMIN_ROLE, _msgSender());
    }
```

**File:** evm/src/eNear/contracts/ENearProxy.sol (L51-56)
```text
    function mint(
        address token,
        address to,
        uint128 amount
    ) public onlyRole(MINTER_ROLE) {
        require(token == address(eNear), "ERR_INCORRECT_ENEAR_ADDRESS");
```

**File:** evm/src/eNear/contracts/ENearProxy.sol (L92-102)
```text
    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        _pause(PAUSED_LEGACY_FIN_TRANSFER);
    }

    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L84-85)
```text
        _grantRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _grantRole(PAUSABLE_ADMIN_ROLE, _msgSender());
```
