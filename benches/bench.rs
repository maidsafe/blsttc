use blsttc::{
    group::ff::Field,
    poly::{BivarPoly, Poly},
    Fr,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

const TEST_DEGREES: [usize; 4] = [5, 10, 20, 40];
const TEST_THRESHOLDS: [usize; 4] = [5, 10, 20, 40];
const RNG_SEED: [u8; 16] = *b"0123456789abcdef";

mod poly_benches {
    use super::*;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    /// Benchmarks multiplication of two polynomials.
    fn multiplication(c: &mut Criterion) {
        let mut group = c.benchmark_group("Polynomial");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("multiplication", parameter_string),
                &deg,
                |b, deg| {
                    let rand_factors = || {
                        let lhs = Poly::random(*deg, &mut rng);
                        let rhs = Poly::random(*deg, &mut rng);
                        (lhs, rhs)
                    };
                    b.iter_with_setup(rand_factors, |(lhs, rhs)| &lhs * &rhs)
                },
            );
        }
        group.finish();
    }

    /// Benchmarks subtraction of two polynomials
    fn subtraction(c: &mut Criterion) {
        let mut group = c.benchmark_group("Polynomial");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("subtraction", parameter_string),
                &deg,
                |b, deg| {
                    let rand_factors = || {
                        let lhs = Poly::random(*deg, &mut rng);
                        let rhs = Poly::random(*deg, &mut rng);
                        (lhs, rhs)
                    };
                    b.iter_with_setup(rand_factors, |(lhs, rhs)| &lhs - &rhs)
                },
            );
        }
    }

    /// Benchmarks addition of two polynomials
    fn addition(c: &mut Criterion) {
        let mut group = c.benchmark_group("Polynomial");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("addition", parameter_string),
                &deg,
                |b, deg| {
                    let rand_factors = || {
                        let lhs = Poly::random(*deg, &mut rng);
                        let rhs = Poly::random(*deg, &mut rng);
                        (lhs, rhs)
                    };
                    b.iter_with_setup(rand_factors, |(lhs, rhs)| &lhs + &rhs)
                },
            );
        }
    }

    /// Benchmarks Lagrange interpolation for a polynomial.
    fn interpolate(c: &mut Criterion) {
        let mut group = c.benchmark_group("Polynomial");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("interpolation", parameter_string),
                &deg,
                |b, deg| {
                    b.iter_with_setup(
                        || {
                            (0..=*deg)
                                .map(|i| (i, Fr::random(&mut rng)))
                                .collect::<Vec<_>>()
                        },
                        Poly::interpolate,
                    )
                },
            );
        }
    }

    /// Benchmarks evaluation of Polynomial into Fr
    fn evaluate(c: &mut Criterion) {
        let mut group = c.benchmark_group("Polynomial");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("evaluate", parameter_string),
                &deg,
                |b, deg| {
                    let rand_factors = || {
                        let poly = Poly::random(*deg, &mut rng);
                        let x = Fr::random(&mut rng);
                        (poly, x)
                    };
                    b.iter_with_setup(rand_factors, |(poly, x)| poly.evaluate(x))
                },
            );
        }
    }

    criterion_group! {
        name = poly_benches;
        config = Criterion::default();
        targets = multiplication, interpolate, addition, subtraction, evaluate,
    }
}

mod bivarpoly_benches {
    use super::*;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    /// Benchmarks evaluation of BivarPolynomial into Fr
    fn evaluate(c: &mut Criterion) {
        let mut group = c.benchmark_group("BivarPolynomial");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("evaluate", parameter_string),
                &deg,
                |b, deg| {
                    let rand_factors = || {
                        let poly = BivarPoly::random(*deg, &mut rng);
                        let x = Fr::random(&mut rng);
                        let y = Fr::random(&mut rng);
                        (poly, x, y)
                    };
                    b.iter_with_setup(rand_factors, |(poly, x, y)| poly.evaluate(x, y))
                },
            );
        }
    }

    /// Benchmarks evaluation of BivarPolynomial row
    fn row(c: &mut Criterion) {
        let mut group = c.benchmark_group("BivarPolynomial");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(BenchmarkId::new("row", parameter_string), &deg, |b, deg| {
                let rand_factors = || {
                    let poly = BivarPoly::random(*deg, &mut rng);
                    let x = Fr::random(&mut rng);
                    (poly, x)
                };
                b.iter_with_setup(rand_factors, |(poly, x)| poly.row(x))
            });
        }
    }

    criterion_group! {
        name = bivarpoly_benches;
        config = Criterion::default();
        targets = evaluate, row,
    }
}

mod commitment_benches {
    use super::*;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    /// Benchmarks addition of two commitments
    fn addition(c: &mut Criterion) {
        let mut group = c.benchmark_group("Commitment");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("addition", parameter_string),
                &deg,
                |b, deg| {
                    let rand_factors = || {
                        let lhs = Poly::random(*deg, &mut rng).commitment();
                        let rhs = Poly::random(*deg, &mut rng).commitment();
                        (lhs, rhs)
                    };
                    b.iter_with_setup(rand_factors, |(lhs, rhs)| &lhs + &rhs)
                },
            );
        }
    }

    /// Benchmarks evaluation of Commitment into P1
    fn evaluate(c: &mut Criterion) {
        let mut group = c.benchmark_group("Commitment");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("evaluate", parameter_string),
                &deg,
                |b, deg| {
                    let rand_factors = || {
                        let commit = Poly::random(*deg, &mut rng).commitment();
                        let x = Fr::random(&mut rng);
                        (commit, x)
                    };
                    b.iter_with_setup(rand_factors, |(commit, x)| commit.evaluate(x))
                },
            );
        }
    }

    criterion_group! {
        name = commitment_benches;
        config = Criterion::default();
        targets = addition, evaluate,
    }
}

mod bivarcommitment_benches {
    use super::*;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    /// Benchmarks evaluation of BivarCommitment into P1
    fn evaluate(c: &mut Criterion) {
        let mut group = c.benchmark_group("BivarCommitment");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("evaluate", parameter_string),
                &deg,
                |b, deg| {
                    let rand_factors = || {
                        let commit = BivarPoly::random(*deg, &mut rng).commitment();
                        let x = Fr::random(&mut rng);
                        let y = Fr::random(&mut rng);
                        (commit, x, y)
                    };
                    b.iter_with_setup(rand_factors, |(commit, x, y)| commit.evaluate(x, y))
                },
            );
        }
    }

    /// Benchmarks evaluation of BivarCommitment row
    fn row(c: &mut Criterion) {
        let mut group = c.benchmark_group("BivarCommitment");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(BenchmarkId::new("row", parameter_string), &deg, |b, deg| {
                let rand_factors = || {
                    let commit = BivarPoly::random(*deg, &mut rng).commitment();
                    let x = Fr::random(&mut rng);
                    (commit, x)
                };
                b.iter_with_setup(rand_factors, |(commit, x)| commit.row(x))
            });
        }
    }

    criterion_group! {
        name = bivarcommitment_benches;
        config = Criterion::default();
        targets = evaluate, row,
    }
}

mod public_key_set_benches {
    use super::*;
    use blsttc::{PublicKeySet, SecretKeySet};
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::collections::BTreeMap;

    /// Benchmarks combining signatures
    fn combine_signatures(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("PublicKeySet");
        let msg = "Test message";
        for threshold in TEST_THRESHOLDS {
            let parameter_string = format!("{}", threshold);
            group.bench_with_input(
                BenchmarkId::new("combine signatures", parameter_string),
                &threshold,
                |b, threshold| {
                    let sk_set = SecretKeySet::random(*threshold, &mut rng);
                    let pk_set = sk_set.public_keys();
                    let mut sigs = BTreeMap::default();
                    for i in 0..=*threshold {
                        let sig = sk_set.secret_key_share(i).sign(msg);
                        sigs.insert(i, sig);
                    }

                    b.iter(|| {
                        pk_set
                            .combine_signatures(&sigs)
                            .expect("could not combine signatures");
                    })
                },
            );
        }
    }

    /// Benchmarks combining decryption shares
    fn combine_decryption_shares(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("PublicKeySet");
        let msg = "Test message";
        for threshold in TEST_THRESHOLDS {
            let parameter_string = format!("{}", threshold);
            group.bench_with_input(
                BenchmarkId::new("combine decryption_shares", parameter_string),
                &threshold,
                |b, threshold| {
                    let sk_set = SecretKeySet::random(*threshold, &mut rng);
                    let sk = sk_set.secret_key();
                    let pk = sk.public_key();
                    let ct = pk.encrypt(msg);
                    let pk_set = sk_set.public_keys();
                    let decryption_shares: BTreeMap<_, _> = (0..=*threshold)
                        .map(|i| {
                            let keyshare = sk_set.secret_key_share(i);
                            let share = keyshare.decrypt_share(&ct).expect("ct did not verify");
                            (i, share)
                        })
                        .collect();
                    b.iter(|| {
                        pk_set
                            .decrypt(&decryption_shares, &ct)
                            .expect("could not decrypt from decryption_shares");
                    })
                },
            );
        }
    }

    /// Benchmarks serialization of a PublicKeySet
    fn serialize(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("PublicKeySet");
        for threshold in TEST_THRESHOLDS {
            let parameter_string = format!("{}", threshold);
            group.bench_with_input(
                BenchmarkId::new("serialize", parameter_string),
                &threshold,
                |b, threshold| {
                    let sk_set = SecretKeySet::random(*threshold, &mut rng);
                    let pk_set = sk_set.public_keys();
                    b.iter(|| {
                        let _bytes = bincode::serialize(&pk_set).unwrap();
                    })
                },
            );
        }
    }

    /// Benchmarks deserialization of a PublicKeySet
    fn deserialize(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("PublicKeySet");
        for threshold in TEST_THRESHOLDS {
            let parameter_string = format!("{}", threshold);
            group.bench_with_input(
                BenchmarkId::new("deserialize", parameter_string),
                &threshold,
                |b, threshold| {
                    let sk_set = SecretKeySet::random(*threshold, &mut rng);
                    let pk_set = sk_set.public_keys();
                    let bytes = bincode::serialize(&pk_set).unwrap();
                    b.iter(|| {
                        let _pks: PublicKeySet = bincode::deserialize(&bytes).unwrap();
                    })
                },
            );
        }
    }

    criterion_group! {
        name = public_key_set_benches;
        config = Criterion::default();
        targets = combine_signatures, combine_decryption_shares, serialize, deserialize,
    }
}

mod public_key_benches {
    use super::*;
    use blsttc::{hash_g2, SecretKey};
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;

    /// Benchmarks verifying a 1000 byte message signature
    fn verify(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("PublicKey");
        group.bench_function("verify", |b| {
            let rand_factors = || {
                let sk = SecretKey::random();
                let pk = sk.public_key();
                let mut msg = [0u8; 1000];
                rng.fill_bytes(&mut msg);
                let sig = sk.sign(&msg);
                (pk, msg, sig)
            };
            b.iter_with_setup(rand_factors, |(pk, msg, sig)| pk.verify(&sig, &msg));
        });
    }

    /// Benchmarks verifying a signature for a point p2
    fn verify_g2(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("PublicKey");
        group.bench_function("verify_g2", |b| {
            let rand_factors = || {
                let sk = SecretKey::random();
                let pk = sk.public_key();
                let mut msg = [0u8; 1000];
                rng.fill_bytes(&mut msg);
                let hash = hash_g2(&msg);
                let sig = sk.sign_g2(&hash);
                (pk, hash, sig)
            };
            b.iter_with_setup(rand_factors, |(pk, hash, sig)| pk.verify_g2(&sig, &hash));
        });
    }

    /// Benchmarks deriving a child public key
    fn derive_child(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("PublicKey");
        group.bench_function("derive_child", |b| {
            let rand_factors = || {
                let sk = SecretKey::random();
                let pk = sk.public_key();
                let mut index = [0u8; 32];
                rng.fill_bytes(&mut index);
                (pk, index)
            };
            b.iter_with_setup(rand_factors, |(pk, index)| pk.derive_child(&index[..]));
        });
    }

    /// Benchmarks encrypting a 1000 byte message
    fn encrypt(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("PublicKey");
        group.bench_function("encrypt", |b| {
            let rand_factors = || {
                let sk = SecretKey::random();
                let pk = sk.public_key();
                let mut msg = [0u8; 1000];
                rng.fill_bytes(&mut msg);
                (pk, msg)
            };
            b.iter_with_setup(rand_factors, |(pk, msg)| pk.encrypt(&msg));
        });
    }

    criterion_group! {
        name = public_key_benches;
        config = Criterion::default();
        targets = verify, verify_g2, derive_child, encrypt,
    }
}

mod secret_key_benches {
    use super::*;
    use blsttc::{hash_g2, SecretKey};
    use rand::{RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;

    /// Benchmarks signing a 1000 byte message
    fn sign(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("SecretKey");
        group.bench_function("sign", |b| {
            let rand_factors = || {
                let sk = SecretKey::random();
                let mut msg = [0u8; 1000];
                rng.fill_bytes(&mut msg);
                (sk, msg)
            };
            b.iter_with_setup(rand_factors, |(sk, msg)| sk.sign(&msg));
        });
    }

    /// Benchmarks signing a point p2
    fn sign_g2(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("SecretKey");
        group.bench_function("sign_g2", |b| {
            let rand_factors = || {
                let sk = SecretKey::random();
                let mut msg = [0u8; 1000];
                rng.fill_bytes(&mut msg);
                let hash = hash_g2(&msg);
                (sk, hash)
            };
            b.iter_with_setup(rand_factors, |(sk, hash)| sk.sign_g2(&hash));
        });
    }

    /// Benchmarks deriving a child secret key
    fn derive_child(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("SecretKey");
        group.bench_function("sign_g2", |b| {
            let rand_factors = || {
                let sk = SecretKey::random();
                let mut msg = [0u8; 1000];
                rng.fill_bytes(&mut msg);
                let hash = hash_g2(&msg);
                (sk, hash)
            };
            b.iter_with_setup(rand_factors, |(sk, hash)| sk.sign_g2(&hash));
        });
    }

    /// Benchmarks decrypting a 1000 byte message
    fn decrypt(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("SecretKey");
        group.bench_function("decrypt", |b| {
            let rand_factors = || {
                let sk = SecretKey::random();
                let pk = sk.public_key();
                let mut msg = [0u8; 1000];
                rng.fill_bytes(&mut msg);
                let ct = pk.encrypt(&msg);
                (sk, ct)
            };
            b.iter_with_setup(rand_factors, |(sk, ct)| sk.decrypt(&ct));
        });
    }

    criterion_group! {
        name = secret_key_benches;
        config = Criterion::default();
        targets = sign, sign_g2, derive_child, decrypt,
    }
}

mod ciphertext_benches {
    use super::*;
    use blsttc::SecretKey;
    use rand::RngCore;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    /// Benchmarks verify of ciphertext
    fn verify(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("Ciphertext");
        group.bench_function("verify", |b| {
            let rand_factors = || {
                let sk = SecretKey::random();
                let pk = sk.public_key();
                let mut msg = [0u8; 1000];
                rng.fill_bytes(&mut msg);
                pk.encrypt(&msg)
            };
            b.iter_with_setup(rand_factors, |ct| ct.verify());
        });
    }

    criterion_group! {
        name = ciphertext_benches;
        config = Criterion::default();
        targets = verify,
    }
}

mod lib_benches {
    use super::*;
    use blsttc::{hash_g2, Fr};
    use rand::RngCore;
    use rand_core::SeedableRng;
    use rand_xorshift::XorShiftRng;

    /// Benchmarks hashing a message to a point in G2
    fn bench_hash_g2(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("lib");
        group.bench_function("hash_g2", |b| {
            let rand_factors = || {
                let mut msg = [0u8; 1000];
                rng.fill_bytes(&mut msg);
                msg
            };
            b.iter_with_setup(rand_factors, |msg| hash_g2(&msg));
        });
    }

    /// Benchmarks generating a random fr
    fn bench_fr_random(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("lib");
        group.bench_function("fr_random", |b| {
            b.iter(|| Fr::random(&mut rng));
        });
    }

    criterion_group! {
        name = lib_benches;
        config = Criterion::default();
        targets = bench_hash_g2, bench_fr_random,
    }
}

criterion_main!(
    poly_benches::poly_benches,
    commitment_benches::commitment_benches,
    bivarpoly_benches::bivarpoly_benches,
    bivarcommitment_benches::bivarcommitment_benches,
    secret_key_benches::secret_key_benches,
    public_key_benches::public_key_benches,
    ciphertext_benches::ciphertext_benches,
    public_key_set_benches::public_key_set_benches,
    lib_benches::lib_benches,
);
