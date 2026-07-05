Looking at the ZkSync bug's vulnerability class — **a critical dispatch/validation function that always uses a stub/placeholder value, causing the required operation to never execute** — I need to find an analog in Ouroboros Consensus where a required validation or resource supply is permanently absent.

Let me examine the Peras certificate and vote validation paths.