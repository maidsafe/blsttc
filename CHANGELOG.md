# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [6.0.0](https://github.com/maidsafe/blsttc/compare/v5.2.0...v6.0.0) (2022-06-10)


### ⚠ BREAKING CHANGES

* the `Eq`, `Serialize` and `Deserialize` derivations are removed from the error type
because the derived hex error doesn't implement these.

I'm finding myself repeating this code several times in places where I'm using the BLS library, so I
thought it would be useful to just have it directly on these types.

### Features

* provide hex conversion utilities ([2509f30](https://github.com/maidsafe/blsttc/commit/2509f30c942115b8dbcd1e0ab9f82a0b835f4437))

## [5.2.0](https://github.com/maidsafe/blsttc/compare/v5.1.3...v5.2.0) (2022-04-05)


### Features

* derive [De-]Serialize on Error ([525cc71](https://github.com/maidsafe/blsttc/commit/525cc7171ca9dc375b25ba5cb0caafdae3949046))

### [5.1.3](https://github.com/maidsafe/blsttc/compare/v5.1.2...v5.1.3) (2022-03-22)

### [5.1.2](https://github.com/maidsafe/blsttc/compare/v5.1.1...v5.1.2) (2022-03-21)

### [5.1.1](https://github.com/maidsafe/blsttc/compare/v5.1.0...v5.1.1) (2022-03-18)

## [5.1.0](https://github.com/maidsafe/blsttc/compare/v5.0.0...v5.1.0) (2022-03-15)


### Features

* add From<G1> for PublicKey ([a93c8e6](https://github.com/maidsafe/blsttc/commit/a93c8e6c2359ec0bdf3bb8719cb46546ba076595))
* add generic partial eq and from impls ([7a198d3](https://github.com/maidsafe/blsttc/commit/7a198d372dc9fba2ef72be7dbe11f95fc93c85f3))
* From<G1Affine> for PublicKey ([4c75c8a](https://github.com/maidsafe/blsttc/commit/4c75c8aa11b07597c237bd13c557001cb808aa7e))

## [5.0.0](https://github.com/maidsafe/blsttc/compare/v4.1.0...v5.0.0) (2022-03-10)


### ⚠ BREAKING CHANGES

* ensure version bump to 5.0.0

* update readme ([8251bb2](https://github.com/maidsafe/blsttc/commit/8251bb2b25239cb78f3d5f58a50c624142b2afe0))

## [4.1.0](https://github.com/maidsafe/blsttc/compare/v4.0.0...v4.1.0) (2022-03-09)


### Features

* replace bls12_381 with blstrs ([aca04ec](https://github.com/maidsafe/blsttc/commit/aca04ec8f2e2fa066fc890bb87c9a3f1c115f9bf))

## [4.0.0](https://github.com/maidsafe/blsttc/compare/v3.4.0...v4.0.0) (2022-02-21)


### ⚠ BREAKING CHANGES

* **api:** changes to public API

* **api:** removing calls to unwrap(), returning Result from all apis ([91db096](https://github.com/maidsafe/blsttc/commit/91db096613191175e757f1e740fedbf5afa56217))

## [3.4.0](https://github.com/maidsafe/blsttc/compare/v3.3.0...v3.4.0) (2021-09-13)


### Features

* accept Borrow<SignatureShare> for ::combine_signatures() to ease use of Vec<SignatureShare> ([fbd24a7](https://github.com/maidsafe/blsttc/commit/fbd24a72d2e1bedf7571101346ea26f4d21bcb75))

## [3.3.0](https://github.com/maidsafe/blsttc/compare/v3.2.0...v3.3.0) (2021-09-06)


### Features

* SecretKeySet and PublicKeySet derive_child ([fcd174f](https://github.com/maidsafe/blsttc/commit/fcd174f9bf92baec153f85c5765d51a358bfca31))

## [3.2.0](https://github.com/maidsafe/blsttc/compare/v3.1.0...v3.2.0) (2021-08-30)


### Features

* add g2_from_be_bytes and g2_to_be_bytes ([47f0102](https://github.com/maidsafe/blsttc/commit/47f01025271ef6acb6fd18884d8e279f3618505b))
* allow utils to be used publicly ([ce8e969](https://github.com/maidsafe/blsttc/commit/ce8e96953a38a6ee83ce9eafec004df89fd1b91c))

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
