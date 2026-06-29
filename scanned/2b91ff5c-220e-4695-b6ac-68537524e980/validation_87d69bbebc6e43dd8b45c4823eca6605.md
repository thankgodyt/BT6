### Title
`finTransfer` Blocked by Pause Permanently Freezes In-Flight Bridged Funds - (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

### Summary

The `finTransfer()` function in `OmniBridge.sol` is gated by `whenNotPaused(PAUSED_FIN_TRANSFER)`. When this flag is active, relayers cannot deliver tokens to destination-chain recipients even though the user's funds have already been irreversibly locked or burned on the source chain. Because no on-chain refund or cancellation path exists, the pause permanently freezes in-flight bridged funds.

### Finding Description

`OmniBridge.sol` defines three selective pause flags:

```solidity
uint256 constant PAUSED_INIT_TRANSFER = 1 << 0;
uint256 constant PAUSED_FIN_TRANSFER  = 1 << 1;
uint256 constant PAUSED_DEPLOY_TOKEN  = 1 << 2;
``` [1](#0-0) 

The `finTransfer()` function — which is the only on-chain path for a relayer to deliver tokens to a recipient on the EVM chain — carries the `whenNotPaused(PAUSED_FIN_TRANSFER)` modifier:

```solidity
function finTransfer(
    bytes calldata signatureData,
    BridgeTypes.TransferMessagePayload calldata payload
) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {
``` [2](#0-1) 

The `pauseAll()` function, callable by any account holding `PAUSABLE_ADMIN_ROLE`, sets all three flags simultaneously — including `PAUSED_FIN_TRANSFER`:

```solidity
function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
    uint256 flags = PAUSED_FIN_TRANSFER | PAUSED_INIT_TRANSFER | PAUSED_DEPLOY_TOKEN;
    _pause(flags);
}
``` [3](#0-2) 

Critically, `initTransfer()` is gated by a **separate** flag (`PAUSED_INIT_TRANSFER`). An operator can pause only `PAUSED_FIN_TRANSFER` while leaving `PAUSED_INIT_TRANSFER` unset, or `pauseAll()` sets both simultaneously. In either case, once a user's source-chain transaction has committed (tokens burned or locked), the destination-side `finTransfer` call is blocked with no recourse.

The same pattern exists identically in the Starknet bridge:

```cairo
fn fin_transfer(...) {
    assert(!_is_paused(@self, PAUSE_FIN_TRANSFER), 'ERR_FIN_TRANSFER_PAUSED');
``` [4](#0-3) 

And in the NEAR hub contract, `fin_transfer` is also subject to the pause macro:

```rust
#[pause(except(roles(Role::DAO)))]
pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
``` [5](#0-4) 

### Impact Explanation

A user who calls `initTransfer` on the EVM bridge (or the equivalent on any spoke chain) has their tokens irreversibly burned or transferred into the bridge contract at that moment. If `PAUSED_FIN_TRANSFER` is subsequently set on the destination chain before the relayer submits `finTransfer`, the delivery is blocked. There is no on-chain cancel or refund function visible in the contract. The user's funds are frozen in the source-chain bridge with no path to recovery until the pause is lifted. If the pause is indefinite (e.g., the bridge is deprecated, admin keys are lost, or the pause is never revisited), the funds are permanently frozen. This matches the allowed impact: **permanent freezing of bridged funds**.

### Likelihood Explanation

The `pauseAll()` function is callable by any `PAUSABLE_ADMIN_ROLE` holder — a role that is separate from `DEFAULT_ADMIN_ROLE` and is granted at initialization. An emergency pause is a realistic operational event. The window between a user's `initTransfer` and the relayer's `finTransfer` is non-zero (cross-chain latency), so in-flight transfers exist at any given time. Any pause during that window affects real user funds.

### Recommendation

`finTransfer` should not be blocked by the pause, because it delivers funds that users have already irrevocably committed on the source chain. Blocking it provides no additional protocol safety (the ECDSA signature from `nearBridgeDerivedAddress` is still verified inside the function) while creating a fund-freezing risk for users. The fix mirrors the original report's recommendation exactly:

```solidity
// Before:
function finTransfer(
    bytes calldata signatureData,
    BridgeTypes.TransferMessagePayload calldata payload
) external payable whenNotPaused(PAUSED_FIN_TRANSFER) {

// After:
function finTransfer(
    bytes calldata signatureData,
    BridgeTypes.TransferMessagePayload calldata payload
) external payable {
```

Apply the same fix to the Starknet `fin_transfer` (remove the `PAUSE_FIN_TRANSFER` check) and to the NEAR `fin_transfer` (remove the `#[pause]` attribute or add an exception role that covers all users, not just DAO).

### Proof of Concept

1. User calls `initTransfer(tokenAddress, amount, ...)` on the EVM `OmniBridge`. For a bridge token, `BridgeToken(tokenAddress).burn(msg.sender, amount)` executes — tokens are destroyed. [6](#0-5) 
2. Before the relayer submits `finTransfer` on the destination chain, an account with `PAUSABLE_ADMIN_ROLE` calls `pauseAll()`, setting `PAUSED_FIN_TRANSFER`. [3](#0-2) 
3. The relayer attempts `finTransfer(signatureData, payload)`. The call reverts at `_requireNotPaused(PAUSED_FIN_TRANSFER)` → `require(!paused(flag), "Pausable: paused")`. [7](#0-6) 
4. The user's tokens are burned on the source chain. No tokens are minted on the destination chain. No refund function exists. Funds are permanently frozen.

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

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L404-406)
```text
            } else if (isBridgeToken[tokenAddress]) {
                BridgeToken(tokenAddress).burn(msg.sender, amount);
            } else {
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

**File:** starknet/src/omni_bridge.cairo (L242-245)
```text
        fn fin_transfer(
            ref self: ContractState, signature: Signature, payload: TransferMessagePayload,
        ) {
            assert(!_is_paused(@self, PAUSE_FIN_TRANSFER), 'ERR_FIN_TRANSFER_PAUSED');
```

**File:** near/omni-bridge/src/lib.rs (L672-673)
```rust
    #[pause(except(roles(Role::DAO)))]
    pub fn fin_transfer(&mut self, #[serializer(borsh)] args: FinTransferArgs) -> Promise {
```

**File:** evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol (L99-101)
```text
    function _requireNotPaused(uint256 flag) internal view virtual {
        require(!paused(flag), "Pausable: paused");
    }
```
