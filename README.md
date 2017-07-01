# Etcommon

Apache-2 licensed common Ethereum structs shared by crates. Work-in-progress right now.

## Rolling Release

As `etcommon` will be depended on many other projects like SptnikVM and EASM, rolling release is necessary to keep up with the development speed.

Note that rolling release will only happen for sub-crates like `etcommon-bigint`, `etcommon-rlp`, `etcommon-util`, etc. The top-level crate `etcommon` will follow the normal release process.