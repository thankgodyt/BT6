### Title
`pauseAll()` Freezes In-Flight Bridged Funds by Blocking `finTransfer()` — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

`OmniBridge.pauseAll()`, callable by any `PAUSABLE_ADMIN_ROLE` holder, sets the `PAUSED_FIN_TRANSFER` flag alongside `PAUSED_INIT_TRANSFER` and `PAUSED_DEPLOY_TOKEN`. Because `finTransfer()` carries a `whenNotPaused(PAUSED_FIN_TRANSFER)` guard, any user who has already locked tokens on a source chain (NEAR or another EVM chain) and is waiting for delivery on the EVM destination chain is permanently blocked from receiving those tokens for the duration of the pause. There is no emergency bypass or alternative withdrawal path.

### Finding Description

`OmniBridge.sol` defines three selective pause flags:

```solidity
uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;   // stops new outbound transfers
uint256 constant PAUSED_FIN_TRANSFER  = 1 << 1;   // stops inbound deliveries
uint256 constant PAUSED_DEPLOY_TOKEN  = 1 << 2;   // stops token deployment
``` [1](#0-0) 

`pauseAll()`, restricted to `PAUSABLE_ADMIN_ROLE`, unconditionally sets all three flags at once:

```solidity
function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
    uint256 flags = PAUSED_FIN_TRANSFER |
        PAUSED_INIT_TRANSFER |
        PAUSED_DEPLOY_TOKEN;
    _pause(flags);
}
``` [2](#0-1) 

`finTransfer()` — the function that delivers tokens to users on the EVM side — is guarded by `whenNotPaused(PAUSED_FIN_TRANSFER)`:

```solidity
function finTransfer(
    bytes calldata signatureData,
    BridgeTypes.TransferMessagePayload calldata payload
) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
``` [3](#0-2) 

`_requireNotPaused` reverts unconditionally when the flag is set:

```solidity
function _requireNotPaused(uint256 flag) internal view virtual {
    require(!paused(flag), "Pausable: paused");
}
``` [4](#0-3) 

There is no `emergencyFinTransfer`, no `whenPaused` escape hatch, and no mechanism for a user to reclaim tokens already locked on the source chain while the EVM contract is paused.

### Impact Explanation

When `pauseAll()` is invoked, every pending inbound transfer — i.e., every transfer where a user has already locked or burned tokens on NEAR (or another source chain) and is awaiting delivery on EVM — is frozen. The relayer's call to `finTransfer()` reverts with `"Pausable: paused"`. The user's funds are locked on the source chain and undeliverable on the destination chain for the entire pause duration. If the pause is never lifted (e.g., due to a governance failure or contract upgrade), the funds are permanently frozen. This matches the **Critical** impact class: permanent freezing of bridged funds.

### Likelihood Explanation

`pauseAll()` is the designated emergency stop function and is expected to be called during security incidents. The `PAUSABLE_ADMIN_ROLE` is a lower-privilege role than `DEFAULT_ADMIN_ROLE` (which can do selective pausing via `pause(flags)`), making it more likely to be granted to operational accounts and invoked quickly in an emergency. Any pause event — however brief — blocks all in-flight inbound deliveries for its duration, affecting every user with a pending `finTransfer`.

### Recommendation

Separate the pause semantics for new usage from the pause semantics for delivery of already-committed funds. Concretely:

1. Remove `PAUSED_FIN_TRANSFER` from the set of flags applied by `pauseAll()`, so that emergency pausing only stops new outbound transfers and token deployments.
2. If `finTransfer` must also be pausable, restrict that flag to `DEFAULT_ADMIN_ROLE` (not `PAUSABLE_ADMIN_ROLE`) and document the fund-freezing consequence explicitly.
3. Alternatively, add an `emergencyFinTransfer` path that bypasses the pause flag but still enforces signature verification, allowing delivery of already-signed payloads even when the contract is paused.

### Proof of Concept

1. Alice locks 1000 USDC on NEAR via `ft_on_transfer`, initiating an outbound transfer to EVM. The NEAR MPC signs a `TransferMessagePayload` and a relayer is ready to call `finTransfer()` on EVM.
2. Before the relayer submits the transaction, a `PAUSABLE_ADMIN_ROLE` holder calls `pauseAll()`. This sets `PAUSED_FIN_TRANSFER | PAUSED_INIT_TRANSFER | PAUSED_DEPLOY_TOKEN`.
3. The relayer calls `finTransfer(signatureData, payload)`. The call reverts at `_requireNotPaused(PAUSED_FIN_TRANSFER)` with `"Pausable: paused"`.
4. Alice's 1000 USDC is locked on NEAR. She cannot receive tokens on EVM. There is no function she can call to recover her funds while the pause is active. [3](#0-2) [2](#0-1) [5](#0-4)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L52-55)
```text
    uint256 constant UNPAUSED_ALL = 0;
    uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
    uint256 constant PAUSED_FIN_TRANSFER = 1 << 1;
    uint256 constant PAUSED_DEPLOY_TOKEN = 1 << 2;
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L279-283)
```text
    function finTransfer(
        bytes calldata signatureData,
        BridgeTypes.TransferMessagePayload calldata payload
    ) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
        if (completedTransfers[payload.destinationNonce]) {
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L552-557)
```text
    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        uint256 flags = PAUSED_FIN_TRANSFER |
            PAUSED_INIT_TRANSFER |
            PAUSED_DEPLOY_TOKEN;
        _pause(flags);
    }
```

**File:** evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol (L63-66)
```text
    modifier whenNotPaused(uint256 flag) {
        _requireNotPaused(flag);
        _;
    }
```

**File:** evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol (L99-101)
```text
    function _requireNotPaused(uint256 flag) internal view virtual {
        require(!paused(flag), "Pausable: paused");
    }
```
