Looking at the vulnerability class from the external report: a **post-operation validity check panics on zero**, but zero is a valid final state after a legitimate operation, permanently blocking that operation and locking funds.

Let me map this to the NEAR Omni Bridge codebase.