# Ledger app deployment

The Docker image for middleware (see [the middleware readme](../../middleware/README.md)) provides an environment suitable to deploy Ledger Nano S applications on a Ledger Nano S device. This way new developers don't have to struggle setting up the deployment toolchain.

## Deploying built apps

Before deploying the Signer or UI, you first have to build them. Refer to [the build readme](../build/README.md) for details on doing this.

### UI

Once the UI is built, you must have your device plugged in and in recovery mode. Issue:

```bash
~/repo> ledger/deploy/deploy-ui
```

and follow the prompts on the device.

### Signer

Once the Signer is built, you must have your device plugged in and unlocked (or alternatively in recovery mode). Issue:

```bash
~/repo> ledger/deploy/deploy-signer
```

and follow the prompts on the device (only if in recovery mode or using the factory UI).


Happy deploying!
