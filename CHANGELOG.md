# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [3.1.0](https://github.com/maidsafe/blsttc/compare/v3.0.0...v3.1.0) (2021-08-23)


### Features

* add derive_child for SecretKey and PublicKey ([524dd27](https://github.com/maidsafe/blsttc/commit/524dd278260859a96b361b3453a8ecbed9f55271))

## [3.0.0](https://github.com/maidsafe/blsttc/compare/v2.5.0...v3.0.0) (2021-08-05)


### ⚠ BREAKING CHANGES

* `PublicKey::from_bytes`, `PublicKeyShare::from_bytes`,
`Signature::from_bytes` and `SignatureShare::from_bytes` can no longer
take `&[u8; N]`, and must be called with `[u8; N]` instead. This may
require additional copying/cloning.

* Force a breaking change ([b4b22e5](https://github.com/maidsafe/blsttc/commit/b4b22e59cc96ea47ef910669d674f3b09f9a9d24)), closes [#11](https://github.com/maidsafe/blsttc/issues/11)

## [2.5.0](https://github.com/maidsafe/blsttc/compare/v2.4.0...v2.5.0) (2021-08-03)


### Features

* add to_bytes and from_bytes ([a1b9efa](https://github.com/maidsafe/blsttc/commit/a1b9efa049a68d6db1e2ef8b5bb27f6cce650502))

## [2.4.0](https://github.com/maidsafe/blsttc/compare/v2.3.0...v2.4.0) (2021-08-02)


### Features

* remove mock ([9919f98](https://github.com/maidsafe/blsttc/commit/9919f987b42720f5fd3636c8cd5c162f748eed98))

## [2.3.0](https://github.com/maidsafe/blsttc/compare/v2.2.0...v2.3.0) (2021-07-27)


### Features

* add SecretKeySet::poly() fn to make the Poly accessible ([598ffc0](https://github.com/maidsafe/blsttc/commit/598ffc0bab4c99458c7268185dbb98392b48f6c2))

## [2.2.0](https://github.com/maidsafe/blsttc/compare/v2.1.0...v2.2.0) (2021-07-27)


### Features

* make SecretKeySet::secret_key() public ([d20a879](https://github.com/maidsafe/blsttc/commit/d20a87949537f2f7b0a813e4a83f6d6ff7ba4629))

## [2.1.0](https://github.com/maidsafe/blsttc/compare/v2.0.2...v2.1.0) (2021-07-26)


### Features

* add pub fn to_bytes() to Ciphertext ([46a51ac](https://github.com/maidsafe/blsttc/commit/46a51acf95cb0788c852dfbe84ef9af847206202))
* changes byte order of and improves Ciphertext::to_bytes(), adds ::from_bytes(), and adds a test for both ([ab7d460](https://github.com/maidsafe/blsttc/commit/ab7d460693e03a60b4ad0ff58e5d0dfaf40157f2))

### [2.0.2](https://github.com/maidsafe/blsttc/compare/v2.0.1...v2.0.2) (2021-07-08)

### [2.0.1](https://github.com/maidsafe/blsttc/compare/v2.0.0...v2.0.1) (2021-06-30)


### Bug Fixes

* replace deprecated bench_function_over_inputs with BenchmarkGroup ([80eba34](https://github.com/maidsafe/blsttc/commit/80eba340c28347092b71fa187123a79919b93c5c))
* simple clippy warning ([a95b419](https://github.com/maidsafe/blsttc/commit/a95b4191447a50bc81cece4644434fb3dc59f4ab))
* tiny inconsistency ([265fe2e](https://github.com/maidsafe/blsttc/commit/265fe2e88f018ed12f19585b22cb45e90dc43009))

## [2.0.0](https://github.com/maidsafe/blsttc/compare/v1.0.1...v2.0.0) (2021-06-30)


### ⚠ BREAKING CHANGES

* **blst:** This enables blsttc to work on older cpu architectures

### Features

* **blst:** enable 'portable' feature of blst ([75d89f2](https://github.com/maidsafe/blsttc/commit/75d89f20ab2fe51aece33e0509c8b14f0a689491))

### 1.0.1 (2021-06-28)
