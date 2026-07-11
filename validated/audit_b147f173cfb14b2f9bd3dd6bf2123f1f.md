Looking at the external report's vulnerability class — **a sub-operation that should fail gracefully instead causes the entire outer transaction to panic/revert** — I need to find an analog in this bridge where user-controlled input bypasses early validation, is stored, and later causes an unrecoverable panic in a downstream call.

Let me read the remaining key files.