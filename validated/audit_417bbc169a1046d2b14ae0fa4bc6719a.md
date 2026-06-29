### Title
ETH Delivery Failure to Reverting Recipient Causes Permanent Fund Freeze — (File: evm/src/omni-bridge/contracts/OmniBridge.sol)

---

### Summary

When a user bridges ETH from NEAR to an EVM chain, the `finTransfer` function delivers ETH to `payload.recipient` via a low-level `call`. If the recipient is a smart contract whose `receive()` or `fallback()` function reverts, the delivery always fails and the entire transaction reverts. Because the recipient address is embedded in the MPC-signed payload and cannot be altered, and because no on-chain recovery path exists on NEAR to cancel the transfer and refund the user, the bridged ETH is permanently frozen.

---

### Finding Description

In `OmniBridge.sol`, `finTransfer` handles native ETH delivery at lines 317–322:

```solidity
if (payload.tokenAddress == address(0)) {
    // slither-disable-next-line arbitrary-send-eth
    (bool success, ) = payload.recipient.call{value: payload.amount}("");
    if (!success) revert FailedToSendEther();
}
```

When `success` is `false` the function reverts with `FailedToSendEther()`. Because the revert unwinds all state changes, `completedTransfers[payload.destinationNonce]` is also rolled back, so the nonce is never consumed and the relayer can retry. However, retrying is futile if the recipient contract always reverts on ETH receipt (e.g., a multisig or smart-contract wallet whose `receive()` contains access-control logic, a paused contract, or any contract with no payable fallback).

The recipient address is part of the Borsh-encoded, MPC-signed `TransferMessagePayload`. The bridge contract verifies the ECDSA signature against `nearBridgeDerivedAddress` before any transfer:

```solidity
if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
    revert InvalidSignature();
}
```

No party — not the user, not the relayer, not an admin — can substitute a different recipient without a new MPC signature. On the NEAR side, once `ft_on_transfer` / `init_transfer` burns or locks the tokens and stores the `TransferMessage` in `pending_transfers`, there is no `cancel_transfer` or refund function that would release those tokens back to the sender if EVM delivery is permanently impossible. The funds are therefore frozen on both sides.

---

### Impact Explanation

**Critical — permanent freezing of bridged ETH funds.**

A user who specifies a smart-contract wallet (e.g., a Safe multisig, an account-abstraction wallet, or any contract whose `receive()` reverts) as the EVM recipient will have their NEAR-side tokens burned/locked with no possibility of recovery. The ETH equivalent can never be delivered, and no protocol-level escape hatch exists to reclaim the funds.

---

### Likelihood Explanation

**Low.** The scenario requires the EVM recipient to be a smart contract that reverts on plain ETH receipt. This is uncommon but realistic: Safe multisigs, account-abstraction wallets, and contracts with access-controlled `receive()` functions are increasingly common recipients for bridge transfers. A user who bridges to their own smart-contract wallet without verifying its ETH-receive behaviour triggers this path with no malicious intent required.

---

### Recommendation

1. **Pull-payment pattern**: Instead of reverting on failed ETH delivery, credit the amount to a per-recipient claimable balance mapping and emit an event. The recipient can then call a `withdraw()` function at any time.
2. **Rescue path on NEAR**: Add a `cancel_transfer` / `refund_transfer` function on the NEAR side that can be invoked (after a timeout or with admin approval) to release locked/burned tokens back to the sender when EVM delivery has provably failed.
3. **Pre-flight check**: Document and enforce that ETH-destination recipients must be EOAs or contracts that accept plain ETH transfers, and reject transfers to known non-payable contracts at the NEAR initiation step.

---

### Proof of Concept

1. User calls `ft_transfer_call` on a NEAR token contract with `msg` encoding an `InitTransferMsg` whose `recipient` is `Eth(0xDeadBeef…)` — a deployed contract with:
   ```solidity
   receive() external payable { revert("no ETH"); }
   ```
2. NEAR bridge burns the tokens and stores the `TransferMessage` in `pending_transfers`.
3. Relayer calls `sign_transfer` → MPC signs a `TransferMessagePayload` with `tokenAddress = address(0)` and `recipient = 0xDeadBeef…`.
4. Relayer calls `finTransfer` on `OmniBridge.sol`. Execution reaches:
   ```solidity
   (bool success, ) = payload.recipient.call{value: payload.amount}("");
   if (!success) revert FailedToSendEther();   // always reverts
   ``` [1](#0-0) 
5. Every retry reverts. The nonce is never consumed. The NEAR tokens remain burned. No recovery function exists. Funds are permanently frozen.

The MPC signature lock-in is confirmed here: [2](#0-1) 

The absence of any cancel/refund path on NEAR is confirmed by the `pending_transfers` storage and the lack of any public cancellation entry point: [3](#0-2)

### Citations

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L311-313)
```text
        if (ECDSA.recover(hashed, signatureData) != nearBridgeDerivedAddress) {
            revert InvalidSignature();
        }
```

**File:** evm/src/omni-bridge/contracts/OmniBridge.sol (L317-322)
```text
        if (payload.tokenAddress == address(0)) {
            // slither-disable-next-line arbitrary-send-eth
            (bool success, ) = payload.recipient.call{value: payload.amount}(
                ""
            );
            if (!success) revert FailedToSendEther();
```

**File:** near/omni-bridge/src/lib.rs (L221-243)
```rust
    pub factories: LookupMap<ChainKind, OmniAddress>,
    pub pending_transfers: LookupMap<TransferId, TransferMessageStorage>,
    pub finalised_transfers: LookupSet<TransferId>,
    pub finalised_utxo_transfers: LookupSet<UnifiedTransferId>,
    pub fast_transfers: LookupMap<FastTransferId, FastTransferStatusStorage>,
    pub token_id_to_address: LookupMap<(ChainKind, AccountId), OmniAddress>,
    pub token_address_to_id: LookupMap<OmniAddress, AccountId>,
    pub token_decimals: LookupMap<OmniAddress, Decimals>,
    pub deployed_tokens: LookupSet<AccountId>,
    pub deployed_tokens_v2: LookupMap<AccountId, ChainKind>,
    pub token_deployer_accounts: LookupMap<ChainKind, AccountId>,
    pub mpc_signer: AccountId,
    pub current_origin_nonce: Nonce,
    // We maintain a separate nonce for each chain to optimize the storage usage on Solana by reducing the gaps.
    pub destination_nonces: LookupMap<ChainKind, Nonce>,
    pub accounts_balances: LookupMap<AccountId, StorageBalance>,
    pub wnear_account_id: AccountId,
    pub provers: UnorderedMap<ChainKind, AccountId>,
    pub init_transfer_promises: LookupMap<AccountId, CryptoHash>,
    pub utxo_chain_connectors: HashMap<ChainKind, UTXOChainConfig>,
    pub migrated_tokens: LookupMap<AccountId, AccountId>,
    pub locked_tokens: LookupMap<(ChainKind, AccountId), u128>,
}
```
