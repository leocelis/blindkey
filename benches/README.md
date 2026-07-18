# Benchmarks

KDF / unlock timing (constraint **C22**) is implemented in `blindkey-core` (`crypto/tune.rs`) and
exposed as `blindkey tune`. The unit test `recommend_returns_valid_in_policy_params` exercises the
benchmark path in CI.

To measure on your machine:

```sh
blindkey tune
```

A dedicated `cargo bench` harness may land here later; until then, `blindkey tune` is the supported
interface.
