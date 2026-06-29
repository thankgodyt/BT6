### Title
ERC1155 `safeTransferFrom` in `fin_transfer` Permanently Locks Bridged Funds When Recipient Contract Lacks `IERC1155Receiver` — (File: `evm/src/omni-bridge/contracts/OmniBridge.sol`)

---

### Summary

`OmniBridge.sol`'s `fin_transfer` uses `IERC1155.safeTransferFrom` to deliver ERC1155-backed multi-tokens to the recipient. `safeTransferFrom` enforces that any contract recipient implements `IERC1155Receiver.onERC1155Received`. However, `initTransfer` accepts any recipient address string with no such check. When a user bridges ERC1155 tokens to a contract recipient that does not implement `IERC1155Receiver` (e.g., a multisig, DAO, or DeFi vault), the source-chain tokens are permanently locked: the initiation step succeeds and the funds are committed, but every finalization attempt reverts, and there is no refund path.

---

### Finding Description

`OmniBridge.sol` `fin_transfer` dispatches token delivery through a multi-branch conditional: [1](#0-0) 

```solidity
} else if (multiToken.tokenAddress != address(0)) {
    IERC1155(multiToken.tokenAddress).safeTransferFrom(
        address(this),
        payload.recipient,
        multiToken.tokenId,
        payload.amount,
        ""
    );
```

`safeTransferFrom` is mandated by EIP-1155 to call `onERC1155Received` on any contract recipient and revert if the call fails or returns the wrong selector. This is the **strict** delivery path.

By contrast, `initTransfer` accepts any `recipient` string with no validation of receiver compatibility: [2](#0-1) 

```solidity
function initTransfer(
    address tokenAddress,
    uint128 amount,
    uint128 fee,
    uint128 nativeFee,
    string calldata recipient,
    string calldata message
) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
```

This is the **permissive** initiation path — the structural analog of `_mint` vs `_safeMint` in the reference report.

The other delivery branches in `fin_transfer` — ERC20 bridge tokens via `IBridgeToken.mint` (which calls ERC20 `_mint`) and native ERC20 via `safeTransfer` — impose **no** receiver-interface requirement: [3](#0-2) 

```solidity
} else if (isBridgeToken[payload.tokenAddress]) {
    IBridgeToken(payload.tokenAddress).mint(
        payload.recipient,
        payload.amount
    );
} else {
    IERC20(payload.tokenAddress).safeTransfer(
        payload.recipient,
        payload.amount
    );
}
```

`BridgeToken.mint` calls ERC20 `_mint`, which has no receiver callback: [4](#0-3) 

```solidity
function mint(address beneficiary, uint256 amount) external onlyOwner {
    _mint(beneficiary, amount);
}
```

The inconsistency is therefore: `initTransfer` (and the ERC20 branches of `fin_transfer`) impose no receiver-interface requirement, while the ERC1155 branch of `fin_transfer` enforces `IERC1155Receiver`. A user who specifies a contract recipient that holds no `onERC1155Received` implementation will have their funds committed on the source chain but will find every finalization attempt reverting on the destination chain.

Because the MPC signature encodes the recipient address, the relayer cannot substitute a different recipient. Because there is no on-chain refund or cancellation path for a committed source-chain transfer, the funds are permanently unrecoverable.

---

### Impact Explanation

**Critical — permanent freezing of bridged funds.**

When a user bridges ERC1155-registered tokens to a contract recipient that does not implement `IERC1155Receiver`:

1. Source chain: tokens are locked in the bridge (or burned, for deployed tokens). The source-chain state is finalized.
2. NEAR: `fin_transfer` processes the proof and creates a signed transfer message with the fixed recipient.
3. Destination EVM: every call to `fin_transfer` reverts at `safeTransferFrom` because the recipient contract returns an invalid selector (or panics). The nonce is not consumed (the revert rolls back the nonce write), so the relayer can retry — but the recipient is immutably encoded in the MPC-signed payload, so no retry can ever succeed.
4. There is no mechanism to refund the source-chain locked/burned tokens.

The user's bridged assets are permanently frozen.

---

### Likelihood Explanation

**Realistic.** ERC1155 multi-token support is an active, production feature of the bridge (`multiTokens` mapping). Many widely-deployed contracts — Gnosis Safe multisigs, governance contracts, yield aggregators, lending protocols — do not implement `IERC1155Receiver`. A user who bridges ERC1155 tokens to such a contract (e.g., a DAO treasury) will trigger this condition without any warning from the protocol. No privileged access or special conditions are required; any unprivileged bridge user can trigger the loss by specifying a non-compliant contract as the recipient.

---

### Recommendation

Apply one or more of the following mitigations:

1. **Validate at initiation**: In `initTransfer`, when the `tokenAddress` maps to an ERC1155 multi-token and the recipient is a contract address, call `supportsInterface(type(IERC1155Receiver).interfaceId)` on the recipient and revert if it returns false.

2. **Use non-safe transfer in `fin_transfer`**: Replace `safeTransferFrom` with a direct `transferFrom` (without the receiver callback) for ERC1155 delivery, consistent with how ERC20 tokens are delivered. This removes the inconsistency at the cost of not enforcing the receiver interface — acceptable if the user is responsible for specifying a valid recipient.

3. **Allow a user-specified fallback recipient**: As suggested in the reference report's mitigation, allow the user to specify an alternative `receiver` address at claim/finalization time, so that if the original recipient cannot receive the token, a different address can be substituted.

---

### Proof of Concept

1. Admin registers an ERC1155 token via `multiTokens` mapping in `OmniBridge`.
2. User calls `initTransfer` on the source EVM chain, specifying `recipient = "eth:0xDeadBeef..."` where `0xDeadBeef` is a deployed contract (e.g., a Gnosis Safe) that does not implement `IERC1155Receiver`. Tokens are locked in the bridge.
3. NEAR `fin_transfer` processes the proof; MPC signs a `TransferMessagePayload` with `recipient = 0xDeadBeef`.
4. Relayer calls `fin_transfer` on the destination EVM chain. Execution reaches:
   ```solidity
   IERC1155(multiToken.tokenAddress).safeTransferFrom(
       address(this), 0xDeadBeef, tokenId, amount, ""
   );
   ```
   The ERC1155 contract calls `0xDeadBeef.onERC1155Received(...)`. The Gnosis Safe does not implement this selector; the call reverts. The entire `fin_transfer` transaction reverts.
5. The nonce is not consumed. The relayer retries — same result every time.
6. The user's tokens remain locked in the source-chain bridge with no recovery path. [1](#0-0) [5](#0-4) [4](#0-3)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L323-330)
```text
        } else if (multiToken.tokenAddress != address(0)) {
            IERC1155(multiToken.tokenAddress).safeTransferFrom(
                address(this),
                payload.recipient,
                multiToken.tokenId,
                payload.amount,
                ""
            );
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L337-355)
```text
        } else if (isBridgeToken[payload.tokenAddress]) {
            if (payload.message.length == 0) {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount
                );
            } else {
                IBridgeToken(payload.tokenAddress).mint(
                    payload.recipient,
                    payload.amount,
                    payload.message
                );
            }
        } else {
            IERC20(payload.tokenAddress).safeTransfer(
                payload.recipient,
                payload.amount
            );
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L373-381)
```text
    function initTransfer(
        address tokenAddress,
        uint128 amount,
        uint128 fee,
        uint128 nativeFee,
        string calldata recipient,
        string calldata message
    ) external payable whenNotPaused(PAUSED_INIT_TRANSFER) {
        currentOriginNonce += 1;
```

**File:** evm/src/omni-bridge/contracts/BridgeToken.sol (L50-52)
```text
    function mint(address beneficiary, uint256 amount) external onlyOwner {
        _mint(beneficiary, amount);
    }
```
