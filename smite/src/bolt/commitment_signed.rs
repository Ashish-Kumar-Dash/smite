//! BOLT 2 `commitment_signed` message.

use super::BoltError;
use super::tlv::TlvStream;
use super::types::ChannelId;
use super::wire::WireFormat;
use bitcoin::Txid;
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::hashes::Hash;

/// TLV type for the funding txid.
const TLV_FUNDING_TXID: u64 = 1;

/// BOLT 2 `commitment_signed` message (type 132).
///
/// Updates the counterparty's commitment transaction with the sender's
/// commitment signature and one HTLC signature per HTLC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitmentSigned {
    /// The channel ID.
    pub channel_id: ChannelId,
    /// Signature for the counterparty commitment transaction.
    pub signature: Signature,
    /// One signature per HTLC transaction, ordered to match the HTLC outputs
    /// on the counterparty's commitment transaction.
    pub htlc_signatures: Vec<Signature>,
    /// Optional TLV extensions.
    pub tlvs: CommitmentSignedTlvs,
}

/// TLV extensions for the `commitment_signed` message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CommitmentSignedTlvs {
    /// Funding transaction spent by this commitment transaction.
    pub funding_txid: Option<Txid>,
}

impl CommitmentSigned {
    /// Encodes to wire format (without message type prefix).
    ///
    /// # Panics
    ///
    /// Panics if the number of HTLC signatures exceeds `u16::MAX`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.signature.write(&mut out);
        u16::try_from(self.htlc_signatures.len())
            .expect("number of HTLC signatures must not exceed u16::MAX")
            .write(&mut out);
        for htlc_signature in &self.htlc_signatures {
            htlc_signature.write(&mut out);
        }

        // Encode TLVs
        let mut tlv_stream = TlvStream::new();
        if let Some(funding_txid) = &self.tlvs.funding_txid {
            tlv_stream.add(TLV_FUNDING_TXID, funding_txid.to_byte_array().to_vec());
        }
        out.extend(tlv_stream.encode());

        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short for any fixed field,
    /// `InvalidSignature` if any signature is not a valid compact ECDSA
    /// signature, or a TLV error if the TLV stream is malformed.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;

        let channel_id = WireFormat::read(&mut cursor)?;
        let signature = WireFormat::read(&mut cursor)?;
        let num_htlcs = u16::read(&mut cursor)?;
        let mut htlc_signatures = Vec::new();
        for _ in 0..num_htlcs {
            htlc_signatures.push(WireFormat::read(&mut cursor)?);
        }

        // Decode TLVs (remaining bytes)
        let tlv_stream = TlvStream::decode(cursor)?;
        let tlvs = CommitmentSignedTlvs::from_stream(&tlv_stream)?;

        Ok(Self {
            channel_id,
            signature,
            htlc_signatures,
            tlvs,
        })
    }
}

impl CommitmentSignedTlvs {
    /// Extracts TLVs from a parsed TLV stream.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if `funding_txid` has invalid length.
    fn from_stream(stream: &TlvStream) -> Result<Self, BoltError> {
        let funding_txid = stream.get_as::<Txid>(TLV_FUNDING_TXID)?;
        Ok(Self { funding_txid })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{CHANNEL_ID_SIZE, COMPACT_SIGNATURE_SIZE, TXID_SIZE};
    use super::*;
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    /// Valid `CommitmentSigned` message for testing.
    fn sample_commitment_signed(tlvs: Option<CommitmentSignedTlvs>) -> CommitmentSigned {
        let sig = |seed: u8| {
            let secp = Secp256k1::new();
            let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
            let msg = Message::from_digest([seed; 32]);
            secp.sign_ecdsa(&msg, &sk)
        };

        CommitmentSigned {
            channel_id: ChannelId::new([0xaa; CHANNEL_ID_SIZE]),
            signature: sig(0x11),
            htlc_signatures: vec![sig(0x22), sig(0x33)],
            tlvs: tlvs.unwrap_or_default(),
        }
    }

    #[test]
    fn encode_fixed_field_size() {
        let encoded = sample_commitment_signed(None).encode();
        // channel_id(32) + signature(64) + num_htlcs(2) + 2*signature(64) = 226
        assert_eq!(encoded.len(), 226);
    }

    #[test]
    #[should_panic(expected = "number of HTLC signatures must not exceed u16::MAX")]
    fn encode_panics_on_oversized_htlc_signatures() {
        let mut msg = sample_commitment_signed(None);
        msg.htlc_signatures = vec![msg.signature; u16::MAX as usize + 1];
        let _ = msg.encode();
    }

    #[test]
    fn roundtrip() {
        let original = sample_commitment_signed(None);
        let encoded = original.encode();
        let decoded = CommitmentSigned::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn roundtrip_no_htlcs() {
        let original = CommitmentSigned {
            htlc_signatures: vec![],
            ..sample_commitment_signed(None)
        };
        let encoded = original.encode();
        // channel_id(32) + signature(64) + num_htlcs(2) = 98
        assert_eq!(encoded.len(), 98);
        let decoded = CommitmentSigned::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn decode_truncated_channel_id() {
        assert_eq!(
            CommitmentSigned::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn decode_truncated_signature() {
        // channel_id(32) + 10 bytes into signature
        let data = vec![0x00; 42];
        assert_eq!(
            CommitmentSigned::decode(&data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 10
            })
        );
    }

    #[test]
    #[allow(clippy::range_plus_one)]
    fn decode_truncated_num_htlcs() {
        // channel_id(32) + signature(64) + 1 byte into num_htlcs
        let encoded = sample_commitment_signed(None).encode();
        let data = &encoded[..CHANNEL_ID_SIZE + COMPACT_SIGNATURE_SIZE + 1];
        assert_eq!(
            CommitmentSigned::decode(data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn decode_truncated_htlc_signature() {
        // num_htlcs claims 2, but only one full HTLC signature is present.
        let encoded = sample_commitment_signed(None).encode();
        let data =
            &encoded[..CHANNEL_ID_SIZE + COMPACT_SIGNATURE_SIZE + 2 + COMPACT_SIGNATURE_SIZE];
        assert_eq!(
            CommitmentSigned::decode(data),
            Err(BoltError::Truncated {
                expected: COMPACT_SIGNATURE_SIZE,
                actual: 0
            })
        );
    }

    #[test]
    fn decode_invalid_signature() {
        let mut encoded = sample_commitment_signed(None).encode();
        // r and s are both above the curve order.
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        encoded[CHANNEL_ID_SIZE..CHANNEL_ID_SIZE + COMPACT_SIGNATURE_SIZE]
            .copy_from_slice(&bad_sig);
        assert_eq!(
            CommitmentSigned::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }

    #[test]
    fn decode_invalid_htlc_signature() {
        let mut encoded = sample_commitment_signed(None).encode();
        let bad_sig = [0xff; COMPACT_SIGNATURE_SIZE];
        let offset = CHANNEL_ID_SIZE + COMPACT_SIGNATURE_SIZE + 2;
        encoded[offset..offset + COMPACT_SIGNATURE_SIZE].copy_from_slice(&bad_sig);
        assert_eq!(
            CommitmentSigned::decode(&encoded),
            Err(BoltError::InvalidSignature(bad_sig))
        );
    }

    #[test]
    fn roundtrip_with_tlvs() {
        let original = sample_commitment_signed(Some(CommitmentSignedTlvs {
            funding_txid: Some(Txid::from_byte_array([0xbb; TXID_SIZE])),
        }));

        let encoded = original.encode();
        let decoded = CommitmentSigned::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn encode_with_funding_txid() {
        let msg = sample_commitment_signed(Some(CommitmentSignedTlvs {
            funding_txid: Some(Txid::from_byte_array([0xbb; TXID_SIZE])),
        }));

        let encoded = msg.encode();
        // 226 fixed + TLV: type(1) + len(1) + value(32) = 34
        assert_eq!(encoded.len(), 226 + 34);

        let decoded = CommitmentSigned::decode(&encoded).unwrap();
        assert_eq!(
            decoded.tlvs.funding_txid,
            Some(Txid::from_byte_array([0xbb; TXID_SIZE]))
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_truncated_funding_txid() {
        let msg = sample_commitment_signed(None);
        let mut encoded = msg.encode();

        // Append funding_txid TLV with only 31 bytes (need 32)
        encoded.push(TLV_FUNDING_TXID as u8); // type = 1
        encoded.push(0x1f); // length = 31
        encoded.extend_from_slice(&[0x00; 31]);
        assert_eq!(
            CommitmentSigned::decode(&encoded),
            Err(BoltError::Truncated {
                expected: TXID_SIZE,
                actual: 31
            })
        );
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)] // Test constants are known to fit in u8
    fn decode_funding_txid_reject_trailing_bytes() {
        let msg = sample_commitment_signed(None);
        let mut encoded = msg.encode();

        // funding_txid TLV should be a 32 byte txid, but we push 33 bytes
        encoded.push(TLV_FUNDING_TXID as u8); // type = 1
        encoded.push(0x21); // length = 33
        encoded.extend_from_slice(&[0xbb; TXID_SIZE]);
        encoded.push(0x00);

        assert_eq!(
            CommitmentSigned::decode(&encoded),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: TLV_FUNDING_TXID,
                expected: TXID_SIZE,
                actual: 33,
            })
        );
    }

    #[test]
    fn decode_unknown_odd_tlv_ignored() {
        let msg = sample_commitment_signed(None);
        let mut encoded = msg.encode();

        // Append unknown odd TLV: type 3, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x03, 0x02, 0xaa, 0xbb]);

        let decoded = CommitmentSigned::decode(&encoded).unwrap();
        assert!(decoded.tlvs.funding_txid.is_none());
    }

    #[test]
    fn decode_unknown_even_tlv_rejected() {
        let msg = sample_commitment_signed(None);
        let mut encoded = msg.encode();

        // Append an unknown even TLV: type 2, length 2, value [0xaa, 0xbb]
        encoded.extend_from_slice(&[0x02, 0x02, 0xaa, 0xbb]);

        assert_eq!(
            CommitmentSigned::decode(&encoded),
            Err(BoltError::TlvUnknownEvenType(2))
        );
    }

    #[test]
    fn decode_default_empty_tlv_values() {
        let tlvs = CommitmentSignedTlvs::default();
        assert!(tlvs.funding_txid.is_none());

        let msg = sample_commitment_signed(Some(tlvs));
        let decoded = CommitmentSigned::decode(&msg.encode()).unwrap();
        assert!(decoded.tlvs.funding_txid.is_none());
    }
}
