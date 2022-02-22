use blsttc::poly::Poly;
use blsttc::Fr;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ff::Field;

const TEST_DEGREES: [usize; 4] = [5, 10, 20, 40];
const TEST_THRESHOLDS: [usize; 4] = [5, 10, 20, 40];
const RNG_SEED: [u8; 16] = *b"0123456789abcdef";

mod poly_benches {
    use super::*;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;

    /// Benchmarks multiplication of two polynomials.
    fn multiplication(c: &mut Criterion) {
        let mut group = c.benchmark_group("Polynomial multiplication");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("Polynomial multiplication", parameter_string),
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
        let mut group = c.benchmark_group("Polynomial subtraction");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("Polynomial subtraction", parameter_string),
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
        let mut group = c.benchmark_group("Polynomial addition");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("Polynomial addition", parameter_string),
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
        let mut group = c.benchmark_group("Polynomial interpolation");
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        for deg in TEST_DEGREES {
            let parameter_string = format!("{}", deg);
            group.bench_with_input(
                BenchmarkId::new("Polynomial interpolation", parameter_string),
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

    criterion_group! {
        name = poly_benches;
        config = Criterion::default();
        targets = multiplication, interpolate, addition, subtraction,
    }
}

mod public_key_set_benches {
    use super::*;
    use blsttc::SecretKeySet;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use std::collections::BTreeMap;

    /// Benchmarks combining signatures
    fn combine_signatures(c: &mut Criterion) {
        let mut rng = XorShiftRng::from_seed(RNG_SEED);
        let mut group = c.benchmark_group("Combine Signatures");
        let msg = "Test message";
        for threshold in TEST_THRESHOLDS {
            let parameter_string = format!("{}", threshold);
            group.bench_with_input(
                BenchmarkId::new("Combine Signatures", parameter_string),
                &threshold,
                |b, threshold| {
                    let sk_set = SecretKeySet::random(*threshold, &mut rng);
                    let pk_set = sk_set.public_keys();
                    let sigs: BTreeMap<_, _> = (0..=*threshold)
                        .map(|i| {
                            let sig = sk_set.secret_key_share(i).sign(msg);
                            (i, sig)
                        })
                        .collect();
                    b.iter(|| {
                        pk_set
                            .combine_signatures(&sigs)
                            .expect("could not combine signatures");
                    })
                },
            );
        }
    }

    criterion_group! {
        name = public_key_set_benches;
        config = Criterion::default();
        targets = combine_signatures,
    }
}

criterion_main!(
    poly_benches::poly_benches,
    public_key_set_benches::public_key_set_benches
);
