Looking at the external report's vulnerability class — **escrow mis-accounting where state is committed before the actual token transfer, and a transfer failure causes permanent, irrecoverable loss of funds** — I need to find an analog in the NEAR Omni Bridge.

Let me trace the `claim_fee` flow carefully.