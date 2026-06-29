### Title
Truncated keccak256 in `deriveDeterministicAddress` Enables Birthday-Attack Collision to Steal Bridged ERC1155 Tokens — (`evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.deriveDeterministicAddress` maps every ERC1155 `(tokenAddress, tokenId)` pair to a 20-byte "virtual" ERC20 address by taking only the first 20 bytes of a keccak256 hash. This truncation reduces collision resistance to 2^80 (birthday attack). Because `initTransfer1155` never validates that the caller's `(tokenAddress, tokenId)` matches the existing `multiTokens` mapping for the derived address, an attacker who finds a hash collision can lock worthless tokens under the same deterministic address as a legitimate token, then redeem the legitimate tokens on the way back.

---

### Finding Description

`deriveDeterministicAddress` is defined as:

```solidity
function deriveDeterministicAddress(
    address tokenAddress,
    uint256 tokenId
) public pure returns (address) {
    return address(bytes20(keccak256(abi.encodePacked(tokenAddress, tokenId))));
}
``` [1](#0-0) 

`bytes20(keccak256(...))` keeps only the first 160 bits of a 256-bit hash. The birthday-attack collision probability for a 160-bit space is approximately 86% after 2^81 hash evaluations (same math as the KyberSwap report). The attacker controls `tokenId` (a full `uint256`), giving an enormous search space to vary.

`logMetadata1155` does guard against collisions once a mapping is stored:

```solidity
if (multiToken.tokenAddress != tokenAddress || multiToken.tokenId != tokenId) {
    revert ERC1155MappingMismatch();
}
``` [2](#0-1) 

However, `initTransfer1155` performs **no such check**. It computes the deterministic address and immediately locks tokens and emits the event, without verifying that `(tokenAddress, tokenId)` matches the stored `multiTokens` entry for that derived address:

```solidity
address deterministicToken = deriveDeterministicAddress(tokenAddress, tokenId);

IERC1155(tokenAddress).safeTransferFrom(msg.sender, address(this), tokenId, amount, "");
// ...
emit BridgeTypes.InitTransfer(msg.sender, deterministicToken, ...);
``` [3](#0-2) 

`finTransfer` dispatches based on the `multiTokens` mapping keyed by the deterministic address:

```solidity
MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];
// ...
} else if (multiToken.tokenAddress != address(0)) {
    IERC1155(multiToken.tokenAddress).safeTransferFrom(
        address(this), payload.recipient, multiToken.tokenId, payload.amount, ""
    );
``` [4](#0-3) 

So whatever `(tokenAddress, tokenId)` was first registered via `logMetadata1155` is what gets released on `finTransfer`, regardless of which pair was used in `initTransfer1155`.

---

### Impact Explanation

An attacker who finds a collision `deriveDeterministicAddress(A, id_A) == deriveDeterministicAddress(B, id_B) = D`, where `B` is an attacker-controlled ERC1155 contract with freely mintable `id_B` tokens, can:

1. Wait for `logMetadata1155(A, id_A)` to register `multiTokens[D] = {A, id_A}` and for users to lock valuable `(A, id_A)` tokens via `initTransfer1155`.
2. Call `initTransfer1155(B, id_B, amount, ...)` — locks worthless attacker-minted tokens, emits `InitTransfer` with token `D`.
3. NEAR processes this as a valid transfer of token `D` (the EVM bridge is a registered factory) and mints NEAR-side token `D` for the attacker.
4. Attacker initiates a NEAR → EVM transfer of token `D`; NEAR MPC signs a `finTransfer` payload with `tokenAddress = D`.
5. Attacker calls `finTransfer` on EVM — since `multiTokens[D] = {A, id_A}`, the bridge releases real `(A, id_A)` tokens to the attacker.

**Result**: All ERC1155 tokens of type `(A, id_A)` locked in the bridge are stolen.

---

### Likelihood Explanation

The attacker controls `tokenId` (uint256), so they can generate 2^80 distinct `(B, id_B)` pairs with a fixed attacker-controlled contract `B`. Simultaneously they enumerate 2^80 `(A, id_A)` pairs for any target token `A`. A birthday collision between the two sets has ~86% probability at 2^81 total hashes. As established in the KyberSwap precedent, the Bitcoin network's current hashrate (~4.7×10^20 H/s) can reach this in hours; a well-funded attacker with 1% of that hashrate reaches it in weeks. The contract is upgradeable (UUPS), so the window is not permanent, but the attack is already within reach of a motivated, well-funded adversary, and ERC1155 tokens locked in the bridge accumulate over time.

---

### Recommendation

Replace the truncated-hash address derivation with a collision-resistant scheme:

1. **Use the full 32-byte hash as the key** — store `multiTokens` keyed by `bytes32` instead of `address`, eliminating the truncation entirely.
2. **Validate in `initTransfer1155`** — require that `multiTokens[deterministicToken]` is either unset or matches `(tokenAddress, tokenId)` before accepting the transfer. This mirrors the guard already present in `logMetadata1155` and closes the gap.

---

### Proof of Concept

The collision math is identical to the KyberSwap finding. The attacker:

- Generates set S1: 2^80 values of `keccak256(abi.encodePacked(A, id_A))` for fixed target token `A`, varying `id_A`.
- Generates set S2: 2^80 values of `keccak256(abi.encodePacked(B, id_B))` for attacker-controlled contract `B`, varying `id_B`.
- Truncates each to 20 bytes and finds a match between S1 and S2 (birthday probability ~86% at 2^81 total hashes).

Once `(A, id_A_victim)` and `(B, id_B_attacker)` are found such that `bytes20(keccak256(A || id_A_victim)) == bytes20(keccak256(B || id_B_attacker))`:

```
// Step 1: legitimate user registers and locks
logMetadata1155(A, id_A_victim)          // multiTokens[D] = {A, id_A_victim}
initTransfer1155(A, id_A_victim, 1000, ...) // bridge holds 1000 real tokens

// Step 2: attacker exploits (no mapping check in initTransfer1155)
initTransfer1155(B, id_B_attacker, 1000, ...) // emits InitTransfer with token D
// NEAR mints 1000 of token D for attacker

// Step 3: attacker bridges back
// NEAR signs finTransfer for EVM with tokenAddress=D
finTransfer(sig, {tokenAddress: D, recipient: attacker, amount: 1000, ...})
// finTransfer sees multiTokens[D]={A, id_A_victim}, releases 1000 real (A, id_A_victim) tokens
``` [5](#0-4) [1](#0-0)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L249-254)
```text
            if (
                multiToken.tokenAddress != tokenAddress ||
                multiToken.tokenId != tokenId
            ) {
                revert ERC1155MappingMismatch();
            }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L315-330)
```text
        MultiTokenInfo memory multiToken = multiTokens[payload.tokenAddress];

        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L439-490)
```text
    function initTransfer1155(
        address tokenAddress,
        uint256 tokenId,
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

        address deterministicToken = deriveDeterministicAddress(
            tokenAddress,
            tokenId
        );

        IERC1155(tokenAddress).safeTransferFrom(
            msg.sender,
            address(this),
            tokenId,
            amount,
            ""
        );

        uint256 extensionValue = msg.value - nativeFee;

        initTransferExtension(
            msg.sender,
            deterministicToken,
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
            deterministicToken,
            currentOriginNonce,
            amount,
            fee,
            nativeFee,
            recipient,
            message
        );
    }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L576-584)
```text
    function deriveDeterministicAddress(
        address tokenAddress,
        uint256 tokenId
    ) public pure returns (address) {
        return
            address(
                bytes20(keccak256(abi.encodePacked(tokenAddress, tokenId)))
            );
    }
```
