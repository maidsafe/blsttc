//! Serialization and deserialization implementations for lib structs

use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::{Bytes as SerdeBytes, ByteBuf as SerdeByteBuf};
use crate::{Ciphertext, Commitment, Poly, PublicKey, PublicKeySet, PublicKeyShare, PK_SIZE, SecretKey, SecretKeySet, SecretKeyShare, SK_SIZE, Signature, SIG_SIZE};

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(&self.to_bytes()).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        if bytes.len() != SK_SIZE {
            return Err(SerdeError::invalid_length(bytes.len(), &"32 bytes"));
        }
        let mut bits = [0u8; SK_SIZE];
        bits.copy_from_slice(&bytes[..SK_SIZE]);
        SecretKey::from_bytes(bits).map_err(SerdeError::custom)
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(&self.to_bytes()).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        if bytes.len() != PK_SIZE {
            return Err(SerdeError::invalid_length(bytes.len(), &"48 bytes"));
        }
        let mut bits = [0u8; PK_SIZE];
        bits.copy_from_slice(&bytes[..PK_SIZE]);
        PublicKey::from_bytes(bits).map_err(SerdeError::custom)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(&self.to_bytes()).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        if bytes.len() != SIG_SIZE {
            return Err(SerdeError::invalid_length(bytes.len(), &"96 bytes"));
        }
        let mut bits = [0u8; SIG_SIZE];
        bits.copy_from_slice(&bytes[..SIG_SIZE]);
        Signature::from_bytes(bits).map_err(SerdeError::custom)
    }
}

impl Serialize for Ciphertext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(&self.to_bytes()).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for Ciphertext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        Ciphertext::from_bytes(&bytes).map_err(SerdeError::custom)
    }
}

impl Serialize for SecretKeyShare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(&self.to_bytes()).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for SecretKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        if bytes.len() != SK_SIZE {
            return Err(SerdeError::invalid_length(bytes.len(), &"32 bytes"));
        }
        let mut bits = [0u8; SK_SIZE];
        bits.copy_from_slice(&bytes[..SK_SIZE]);
        SecretKeyShare::from_bytes(bits).map_err(SerdeError::custom)
    }
}

impl Serialize for SecretKeySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(&self.to_bytes()).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for SecretKeySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        if bytes.len() % SK_SIZE != 0 {
            return Err(SerdeError::invalid_length(bytes.len(), &"multiple of 32 bytes"));
        }
        SecretKeySet::from_bytes(bytes.to_vec()).map_err(SerdeError::custom)
    }
}

impl Serialize for PublicKeyShare {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(&self.to_bytes()).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for PublicKeyShare {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        if bytes.len() != PK_SIZE {
            return Err(SerdeError::invalid_length(bytes.len(), &"48 bytes"));
        }
        let mut bits = [0u8; PK_SIZE];
        bits.copy_from_slice(&bytes[..PK_SIZE]);
        PublicKeyShare::from_bytes(bits).map_err(SerdeError::custom)
    }
}

impl Serialize for PublicKeySet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(&self.to_bytes()).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for PublicKeySet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        if bytes.len() % PK_SIZE != 0 {
            return Err(SerdeError::invalid_length(bytes.len(), &"multiple of 48 bytes"));
        }
        PublicKeySet::from_bytes(bytes.to_vec()).map_err(SerdeError::custom)
    }
}

impl Serialize for Poly {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(&self.to_bytes()).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for Poly {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        if bytes.len() % SK_SIZE != 0 {
            return Err(SerdeError::invalid_length(bytes.len(), &"multiple of 32 bytes"));
        }
        Poly::from_bytes(bytes.to_vec()).map_err(SerdeError::custom)
    }
}

impl Serialize for Commitment {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerdeBytes::new(&self.to_bytes()).serialize(serializer)
    }
}

impl<'d> Deserialize<'d> for Commitment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let bytes = <SerdeByteBuf>::deserialize(deserializer)?;
        if bytes.len() % PK_SIZE != 0 {
            return Err(SerdeError::invalid_length(bytes.len(), &"multiple of 48 bytes"));
        }
        Commitment::from_bytes(bytes.to_vec()).map_err(SerdeError::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_sk() {
        let sk = SecretKey::random();
        let ser_sk = bincode::serialize(&sk).expect("serialize secret key");
        let deser_sk = bincode::deserialize(&ser_sk).expect("deserialize secret key");
        assert_eq!(sk, deser_sk);
    }

    #[test]
    fn test_serde_pk() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let ser_pk = bincode::serialize(&pk).expect("serialize public key");
        let deser_pk = bincode::deserialize(&ser_pk).expect("deserialize public key");
        assert_eq!(pk, deser_pk);
    }

    #[test]
    fn test_serde_sig() {
        let sk = SecretKey::random();
        let msg = "Meet at dawn";
        let sig = sk.sign(&msg);
        let ser_sig = bincode::serialize(&sig).expect("serialize signature");
        let deser_sig = bincode::deserialize(&ser_sig).expect("deserialize signature");
        assert_eq!(sig, deser_sig);
    }

    #[test]
    fn test_serde_ciphertext() {
        let sk = SecretKey::random();
        let pk = sk.public_key();
        let msg = "Meet at dawn";
        let ct = pk.encrypt(&msg);
        let ser_ct = bincode::serialize(&ct).expect("serialize ciphertext");
        let deser_ct = bincode::deserialize(&ser_ct).expect("deserialize ciphertext");
        assert_eq!(ct, deser_ct);
    }

    #[test]
    fn test_serde_secretkeyset() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let ser_sk_set = bincode::serialize(&sk_set).expect("serialize secretkeyset");
        let deser_sk_set: SecretKeySet = bincode::deserialize(&ser_sk_set).expect("deserialize secretkeyset");
        assert_eq!(sk_set, deser_sk_set);
    }

    #[test]
    fn test_serde_secretkeyset_share() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let share = sk_set.secret_key_share(5);
        let ser_share = bincode::serialize(&share).expect("serialize secretkeyset share");
        let deser_share = bincode::deserialize(&ser_share).expect("deserialize secretkeyset share");
        assert_eq!(share, deser_share);
    }

    #[test]
    fn test_serde_publickeyset() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let ser_pk_set = bincode::serialize(&pk_set).expect("serialize publickeyset");
        let deser_pk_set: PublicKeySet = bincode::deserialize(&ser_pk_set).expect("deserialize publickeyset");
        assert_eq!(pk_set, deser_pk_set);
    }

    #[test]
    fn test_serde_publickeyset_share() {
        let mut rng = rand::thread_rng();
        let sk_set = SecretKeySet::random(3, &mut rng);
        let pk_set = sk_set.public_keys();
        let share = pk_set.public_key_share(5);
        let ser_share = bincode::serialize(&share).expect("serialize publickeyset share");
        let deser_share = bincode::deserialize(&ser_share).expect("deserialize publickeyset share");
        assert_eq!(share, deser_share);
    }

    #[test]
    fn test_serde_poly() {
        let mut rng = rand::thread_rng();
        let poly = Poly::random(3, &mut rng);
        let ser_poly = bincode::serialize(&poly).expect("serialize poly");
        let deser_poly: Poly = bincode::deserialize(&ser_poly).expect("deserialize poly");
        assert_eq!(poly, deser_poly);
    }

    #[test]
    fn test_serde_commit() {
        let mut rng = rand::thread_rng();
        let poly = Poly::random(3, &mut rng);
        let commit = poly.commitment();
        let ser_commit = bincode::serialize(&commit).expect("serialize commitment");
        let deser_commit: Commitment = bincode::deserialize(&ser_commit).expect("deserialize commitment");
        assert_eq!(commit, deser_commit);
    }
}
