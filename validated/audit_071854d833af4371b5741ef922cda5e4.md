Looking at the vulnerability class — a low-level call that silently succeeds even when the target resource doesn't exist — I need to find an analog where a consensus-critical operation returns success without verifying the existence or validity of the underlying resource.

Let me trace the Peras certificate validation path and the `assertWithMsg` production behavior.