use blsttc::SecretKey;

/// Extremely simple example to effectively provide a little util program for quickly generating a
/// BLS keypair and printing out the hex representation.
///
/// Could be extended to demonstrate the use of shares.
fn main() {
    let sk = SecretKey::random();
    let pk = sk.public_key();
    println!("public key: {}", pk.to_hex());
    println!("secret key: {}", sk.to_hex());
}
