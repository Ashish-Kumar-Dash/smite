//! BOLT 2 `revoke_and_ack` message.

use super::BoltError;
use super::types::{ChannelId, PER_COMMITMENT_SECRET_SIZE};
use super::wire::WireFormat;
use bitcoin::secp256k1::PublicKey;

/// BOLT 2 `revoke_and_ack` message (type 133).
///
/// Acknowledges a `commitment_signed` by revoking the previous commitment
/// transaction and providing the next per-commitment point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeAndAck {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// Secret corresponding to the previous commitment transaction's
    /// per-commitment point.
    pub per_commitment_secret: [u8; PER_COMMITMENT_SECRET_SIZE],
    /// The per-commitment point for the next commitment transaction.
    pub next_per_commitment_point: PublicKey,
}

impl RevokeAndAck {
    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.per_commitment_secret.write(&mut out);
        self.next_per_commitment_point.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field, or
    /// `InvalidPublicKey` if the public key field is invalid.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let per_commitment_secret = WireFormat::read(&mut cursor)?;
        let next_per_commitment_point = WireFormat::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            per_commitment_secret,
            next_per_commitment_point,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, PUBLIC_KEY_SIZE};
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    /// Valid `RevokeAndAck` message for testing.
    fn sample_revoke_and_ack() -> RevokeAndAck {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).expect("valid secret");
        let pk = PublicKey::from_secret_key(&secp, &sk);

        RevokeAndAck {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            per_commitment_secret: [0xcd; PER_COMMITMENT_SECRET_SIZE],
            next_per_commitment_point: pk,
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let encoded = sample_revoke_and_ack().encode();
        // channel_id(32) + per_commitment_secret(32)
        // + next_per_commitment_point(33) = 97
        assert_eq!(encoded.len(), 97);
    }

    #[test]
    fn roundtrip() {
        let original = sample_revoke_and_ack();
        let encoded = original.encode();
        let decoded = RevokeAndAck::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            RevokeAndAck::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_per_commitment_secret() {
        // channel_id(32) + 16 bytes into per_commitment_secret
        let data = vec![0x00; 48];
        assert_eq!(
            RevokeAndAck::decode(&data),
            Err(BoltError::Truncated {
                expected: PER_COMMITMENT_SECRET_SIZE,
                actual: 16
            })
        );
    }

    #[test]
    fn decode_truncated_next_per_commitment_point() {
        // channel_id(32) + per_commitment_secret(32)
        // + 10 bytes into next_per_commitment_point
        let data = vec![0x00; 74];
        assert_eq!(
            RevokeAndAck::decode(&data),
            Err(BoltError::Truncated {
                expected: PUBLIC_KEY_SIZE,
                actual: 10
            })
        );
    }

    #[test]
    fn decode_invalid_next_per_commitment_point() {
        // Full-length payload (97 bytes) with an all-zero (invalid) public key.
        let data = vec![0x00; 97];
        assert_eq!(
            RevokeAndAck::decode(&data),
            Err(BoltError::InvalidPublicKey([0x00; PUBLIC_KEY_SIZE]))
        );
    }
}
