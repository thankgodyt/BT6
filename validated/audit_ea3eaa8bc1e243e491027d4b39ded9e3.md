### Title
Race Condition Between `execute_refund` and `reject_refund` Allows Attacker to Redirect User BTC to Attacker-Controlled Address - (File: contracts/satoshi-bridge/src/api/bridge.rs)

### Summary

`request_refund` is callable by any unprivileged account for any unfinalized deposit UTXO, with a caller-supplied `refund_address`. After the `unsafe_refund_timelock_sec` elapses, `execute_refund` is also callable by anyone.