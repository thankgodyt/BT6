### Title
Confirmation-Delta Bypass for `extra_msg` Deposits: Non-Whitelisted Relayer Avoids `confirmations_delta` Penalty - (File: contracts/satoshi-bridge/src/config.rs)

---

### Summary

`get_extra_msg_confirmations` only checks `extra_msg_relayer_white_list` and applies `extra_msg_confirmations_delta`. It never checks `relayer_white_list` or applies `confirmations_delta`. When a deposit carries `extra_msg`, the standard relayer-whitelist penalty is silently dropped, so a relayer absent from `relayer_white_list` (but present on `extra_msg_relayer_white_list`, or absent from both) submits the deposit with fewer required confirmations than the protocol intends.

---

### Finding Description

The bridge maintains two independent trust controls for deposit relayers:

| Control | Whitelist | Penalty |
|---|---|---|
| General relayer trust | `relayer_white_list` | `+confirmations_delta` |
| Extra-msg relayer trust | `extra_msg_relayer_white_list` | `+extra_msg_confirmations_delta` |

`internal_verify_deposit` selects the confirmation count with a strict if/else:

```rust
// contracts/satoshi-bridge/src/btc_light_client/deposit.rs  lines 30-34
let confirmations = if deposit_msg.extra_msg.is_none() {
    self.get_confirmations(config, deposit_amount)        // checks relayer_white_list
} else {
    self.get_extra_msg_confirmations(config, deposit_amount) // checks ONLY extra_msg_relayer_white_list
};
```

`get_extra_msg_confirmations` is:

```rust
// contracts/satoshi-bridge/src/config.rs  lines 334-345
pub fn get_extra_msg_confirmations(&self, config: &Config, satoshi_amount: u128) -> u64 {
    if self.data().extra_msg_relayer_white_list.contains(&env::predecessor_account_id()) {
        config.get_confirmations(satoshi_amount)
    } else {
        config.get_confirmations(satoshi_amount) + u64::from(config.extra_msg_confirmations_delta)
    }
}
```

It never consults `relayer_white_list` or adds `confirmations_delta`. The two whitelists are independent sets — a relayer can be on `extra_msg_relayer_white_list` while absent from `relayer_white_list`, or absent from both. In either case, `confirmations_delta` is never applied to an `extra_msg` deposit, exactly mirroring M-07's pattern of applying a multiplier only once when it should be applied twice.

---

### Impact Explanation

The confirmation count is the bridge's primary on-chain defence against Bitcoin reorg-based double-spend attacks. Reducing it below the intended floor for untrusted relayers means a malicious relayer can submit a valid Merkle inclusion proof for a BTC transaction that has not yet reached the required depth. If that transaction is subsequently reorganised out of the canonical chain, the bridge has already minted nBTC against BTC that no longer exists in the protocol's UTXO set — **unauthorized minting of nBTC without corresponding locked BTC**. This matches the "Medium — bypass of bridge limits or policies, attacker-triggered temporary locking or premature processing of bridged funds" impact category.

---

### Likelihood Explanation

Medium. The two whitelists are managed independently by the DAO. Any relayer account that is granted `extra_msg_relayer_white_list` membership but not `relayer_white_list` membership (a plausible operational state) immediately exhibits the reduced confirmation requirement on every `extra_msg` deposit it submits. No special on-chain state beyond that membership asymmetry is required. The attacker-controlled entry point is the public `verify_deposit` / `verify_deposit_v2` call with a non-null `extra_msg` field.

---

### Recommendation

Combine both whitelist checks when `extra_msg` is present so that each independent trust control contributes its own delta:

```rust
pub fn get_extra_msg_confirmations(&self, config: &Config, satoshi_amount: u128) -> u64 {
    let base = config.get_confirmations(satoshi_amount);
    let relayer_delta = if self.data().relayer_white_list.contains(&env::predecessor_account_id()) {
        0
    } else {
        u64::from(config.confirmations_delta)
    };
    let extra_msg_delta = if self.data().extra_msg_relayer_white_list.contains(&env::predecessor_account_id()) {
        0
    } else {
        u64::from(config.extra_msg_confirmations_delta)
    };
    base + relayer_delta + extra_msg_delta
}
```

---

### Proof of Concept

1. DAO adds relayer `R` to `extra_msg_relayer_white_list` only (not to `relayer_white_list`). Both `confirmations_delta = 1` and `extra_msg_confirmations_delta = 1` are configured.
2. `R` calls `verify_deposit_v2` with a `DepositMsg` whose `extra_msg` is `Some("...")`.
3. `internal_verify_deposit` branches to `get_extra_msg_confirmations`.
4. `get_extra_msg_confirmations` finds `R` in `extra_msg_relayer_white_list` → returns `base_confirmations` (no delta added).
5. `relayer_white_list` is never consulted; `confirmations_delta` is never added.
6. The light-client call is issued with `base_confirmations` instead of the intended `base_confirmations + 1`.
7. `R` can submit a deposit proof for a BTC transaction with only `base_confirmations` depth, one block short of the intended security threshold, enabling a reorg-based double-spend that results in nBTC being minted without permanently locked BTC.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** contracts/satoshi-bridge/src/btc_light_client/deposit.rs (L30-34)
```rust
        let confirmations = if deposit_msg.extra_msg.is_none() {
            self.get_confirmations(config, deposit_amount)
        } else {
            self.get_extra_msg_confirmations(config, deposit_amount)
        };
```

**File:** contracts/satoshi-bridge/src/config.rs (L62-65)
```rust
    // The number of confirmations that need to be increased when a relayer not on the whitelist performs a verify.
    pub confirmations_delta: u8,
    // The number of confirmations that need to be increased when a relayer not on the extra msg whitelist performs a verify.
    pub extra_msg_confirmations_delta: u8,
```

**File:** contracts/satoshi-bridge/src/config.rs (L321-345)
```rust
    pub fn get_confirmations(&self, config: &Config, satoshi_amount: u128) -> u64 {
        if self
            .data()
            .relayer_white_list
            // Use predecessor_account_id to support both users and proxy protocols.
            .contains(&env::predecessor_account_id())
        {
            config.get_confirmations(satoshi_amount)
        } else {
            config.get_confirmations(satoshi_amount) + u64::from(config.confirmations_delta)
        }
    }

    pub fn get_extra_msg_confirmations(&self, config: &Config, satoshi_amount: u128) -> u64 {
        if self
            .data()
            .extra_msg_relayer_white_list
            .contains(&env::predecessor_account_id())
        {
            config.get_confirmations(satoshi_amount)
        } else {
            config.get_confirmations(satoshi_amount)
                + u64::from(config.extra_msg_confirmations_delta)
        }
    }
```
