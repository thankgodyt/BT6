### Title
Admin `pause(flags)` Overwrites `_pausedFlags`, Inadvertently Unpausing Legacy Mint Path with FakeProver Active — (`evm/src/eNear/contracts/ENearProxy.sol`, `evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol`)

---

### Summary

`SelectivePausableUpgradable._pause(flags)` **replaces** `_pausedFlags` entirely with the supplied value instead of OR-ing new bits in. Because `ENearProxy.pause(uint256 flags)` delegates directly to `_pause`, a `DEFAULT_ADMIN_ROLE` holder who calls `pause(N)` where `N` does not include bit 0 (`PAUSED_LEGACY_FIN_TRANSFER`) will silently clear that bit, re-opening the legacy `finaliseNearToEthTransfer` path. In the production deployment described in the README, `eNear.prover` is replaced with `FakeProver`, which unconditionally returns `true` for any proof. The combination lets any attacker mint arbitrary eNear tokens through the now-unpaused legacy path.

---

### Finding Description

**Root cause — `_pause` overwrites instead of OR-ing:** [1](#0-0) 

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags = flags;          // ← full overwrite, not |= flags
    emit Paused(_msgSender(), $._pausedFlags);
}
```

**Admin-callable surface:** [2](#0-1) 

```solidity
function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
    _pause(flags);   // passes caller-supplied value straight through
}
```

**Guard on the legacy path:** [3](#0-2) 

```solidity
function finaliseNearToEthTransfer(
    bytes memory proofData,
    uint64 proofBlockHeight
) external whenNotPaused(PAUSED_LEGACY_FIN_TRANSFER) {
    require(prover.proveOutcome(proofData, proofBlockHeight), "Proof should be valid");
    eNear.finaliseNearToEthTransfer(proofData, proofBlockHeight);
}
```

**FakeProver is a production component, not a test mock.** The README explicitly documents the intended mainnet architecture: [4](#0-3) 

> "We will make `eNearProxy` the admin of `eNear` and replace the `Prover` with a `FakeProver` that will successfully verify any proof. We will pause the `finaliseNearToEthTransfer` and `transferToNear` functions, and only `eNearProxy`, as the admin, will have the ability to call these functions."

`FakeProver.proveOutcome` returns `true` for every input unconditionally: [5](#0-4) 

```solidity
contract FakeProver is INearProver {
    function proveOutcome(bytes calldata, uint64) external pure returns (bool) {
        return true;
    }
}
```

A dedicated Hardhat task (`deploy-fake-prover`) exists to deploy it to mainnet/testnet: [6](#0-5) 

---

### Impact Explanation

Once `PAUSED_LEGACY_FIN_TRANSFER` (bit 0) is cleared from `_pausedFlags`:

1. `whenNotPaused(PAUSED_LEGACY_FIN_TRANSFER)` passes (`(flags & 1) == 0`).
2. `prover.proveOutcome(craftedProof, 0)` returns `true` (FakeProver).
3. `eNear.finaliseNearToEthTransfer(craftedProof, 0)` executes on the legacy eNear contract, minting tokens to an attacker-controlled address.

The attacker can craft the proof to specify any recipient and any amount, resulting in **unauthorized minting of eNear tokens** — a direct theft/inflation of bridged funds.

---

### Likelihood Explanation

The precondition is an admin calling `pause(N)` where `N` omits bit 0. This is a realistic operational mistake: if a future flag (e.g., bit 1) needs to be set, an admin calling `pause(2)` would believe they are adding a pause, while actually clearing the critical legacy-path pause. The design of `_pause` gives no indication it is destructive to existing flags. The `pauseAll()` function itself demonstrates the same hazard — it calls `_pause(PAUSED_LEGACY_FIN_TRANSFER)`, which would clear any other flags that were previously set. [7](#0-6) 

---

### Recommendation

Change `_pause` to OR-in new flags rather than overwrite, and add a complementary `_unpause(flags)` that clears specific bits:

```solidity
function _pause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags |= flags;   // additive, never clears existing bits
    emit Paused(_msgSender(), $._pausedFlags);
}

function _unpause(uint256 flags) internal virtual {
    SelectivePausableStorage storage $ = _getSelectivePausableStorage();
    $._pausedFlags &= ~flags;
    emit Unpaused(_msgSender(), $._pausedFlags);
}
```

Additionally, consider adding an invariant check in `ENearProxy.pause` that prevents clearing `PAUSED_LEGACY_FIN_TRANSFER` once it has been set, since the README documents it as a permanent pause.

---

### Proof of Concept

```solidity
// 1. Deploy ENearProxy with FakeProver as prover
// 2. Admin sets PAUSED_LEGACY_FIN_TRANSFER
proxy.pause(1);  // _pausedFlags = 1
assert(proxy.paused(1) == true);

// 3. Admin later calls pause() to set a different flag, omitting bit 0
proxy.pause(2);  // _pausedFlags = 2  ← clears bit 0
assert(proxy.paused(1) == false);  // legacy path is now OPEN

// 4. Attacker calls the legacy path with a crafted proof
// FakeProver returns true for any input
proxy.finaliseNearToEthTransfer(craftedProof, 0);
// → eNear.finaliseNearToEthTransfer executes → attacker receives minted eNear
assert(eNear.balanceOf(attacker) > 0);
```

### Citations

**File:** evm/src/omni-bridge/contracts/SelectivePausableUpgradable.sol (L113-117)
```text
    function _pause(uint256 flags) internal virtual {
        SelectivePausableStorage storage $ = _getSelectivePausableStorage();
        $._pausedFlags = flags;
        emit Paused(_msgSender(), $._pausedFlags);
    }
```

**File:** evm/src/eNear/contracts/ENearProxy.sol (L80-90)
```text
    function finaliseNearToEthTransfer(
        bytes memory proofData,
        uint64 proofBlockHeight
    ) external whenNotPaused(PAUSED_LEGACY_FIN_TRANSFER) {
        require(
            prover.proveOutcome(proofData, proofBlockHeight),
            "Proof should be valid"
        );

        eNear.finaliseNearToEthTransfer(proofData, proofBlockHeight);
    }
```

**File:** evm/src/eNear/contracts/ENearProxy.sol (L92-94)
```text
    function pauseAll() external onlyRole(PAUSABLE_ADMIN_ROLE) {
        _pause(PAUSED_LEGACY_FIN_TRANSFER);
    }
```

**File:** evm/src/eNear/contracts/ENearProxy.sol (L96-98)
```text
    function pause(uint256 flags) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _pause(flags);
    }
```

**File:** evm/src/eNear/README.md (L17-23)
```markdown
We will make `eNearProxy` the admin of `eNear` and replace the `Prover` with a `FakeProver` 
that will successfully verify any proof. 
We will pause the `finaliseNearToEthTransfer` and `transferToNear` functions, 
and only `eNearProxy`, as the admin, will have the ability to call these functions.
For minting, the `eNearProxy` will call `finaliseNearToEthTransfer` on `eNear`, 
providing a fake proof with the necessary data on who and how much to mint. 
For burning, it will call the `transferToNear` function with a non-existent address on NEAR.
```

**File:** evm/src/eNear/contracts/FakeProver.sol (L6-9)
```text
contract FakeProver is INearProver {
    function proveOutcome(bytes calldata, uint64) external pure returns (bool) {
        return true;
    }
```

**File:** evm/src/eNear/scripts.ts (L44-56)
```typescript
task("deploy-fake-prover", "Deploy fake prover").setAction(
  async (_taskArgs, hre: HardhatRuntimeEnvironment) => {
    const { ethers } = hre
    const FakeProverContractFactory = await ethers.getContractFactory("FakeProver")
    const FakeProverContract = await FakeProverContractFactory.deploy()
    await FakeProverContract.waitForDeployment()

    console.log(
      JSON.stringify({
        fakeProverAddress: await FakeProverContract.getAddress(),
      }),
    )
  },
```
