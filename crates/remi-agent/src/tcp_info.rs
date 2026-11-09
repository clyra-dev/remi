//! Linux UAPI INET_DIAG_INFO attributes, with explicit lengths and native endianness.
use remi_core::connections::TcpTraffic;

pub fn traffic(mut attributes: &[u8]) -> Option<TcpTraffic> {
    while attributes.len() >= 4 {
        let len = u16::from_ne_bytes(attributes[..2].try_into().ok()?) as usize;
        let kind = u16::from_ne_bytes(attributes[2..4].try_into().ok()?) & 0x3fff;
        if len < 4 || len > attributes.len() {
            return None;
        }
        if kind == 2 {
            let info = &attributes[4..len];
            // Data-segment counters distinguish a new, unused socket from recent payload.
            // Linux tcp_info: last_data_sent=44, last_data_recv=52,
            // data_segs_in=152, data_segs_out=156 (available since Linux 4.2).
            if info.len() < 160 {
                return None;
            }
            let word = |offset| u32::from_ne_bytes(info[offset..offset + 4].try_into().unwrap());
            let sent = (word(156) > 0).then(|| word(44));
            let received = (word(152) > 0).then(|| word(52));
            return Some(TcpTraffic {
                last_data_ago_ms: sent.into_iter().chain(received).min(),
            });
        }
        attributes = attributes.get((len + 3) & !3..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(sent: u32, recv: u32, sent_segments: u32, recv_segments: u32) -> Vec<u8> {
        let mut bytes = vec![0; 164];
        bytes[..2].copy_from_slice(&164u16.to_ne_bytes());
        bytes[2..4].copy_from_slice(&2u16.to_ne_bytes());
        for (offset, value) in [
            (48, sent),
            (56, recv),
            (160, sent_segments),
            (156, recv_segments),
        ] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
        }
        bytes
    }
    #[test]
    fn decodes_payload_recency_and_excludes_directions_without_payload() {
        for (sent, recv, sc, rc, expected) in [
            (12000, 230, 3, 2, Some(230)),
            (240, 13000, 1, 4, Some(240)),
            (0, 15000, 0, 2, Some(15000)),
            (17000, 0, 2, 0, Some(17000)),
            (0, 0, 0, 0, None),
        ] {
            assert_eq!(
                traffic(&fixture(sent, recv, sc, rc))
                    .unwrap()
                    .last_data_ago_ms,
                expected
            );
        }
        let mut bytes = vec![5, 0, 99, 0, 8, 0, 0, 0];
        bytes.extend(fixture(13, 300, 1, 1));
        assert_eq!(traffic(&bytes).unwrap().last_data_ago_ms, Some(13));
    }
    #[test]
    fn missing_old_or_malformed_attributes_remain_unknown() {
        let valid = fixture(42, 43, 1, 1);
        assert_eq!(traffic(&valid).unwrap().last_data_ago_ms, Some(42));
        for len in 0..164 {
            assert!(traffic(&valid[..len]).is_none());
        }
        for len in [0u16, 1, 3, 165, u16::MAX] {
            let mut bad = valid.clone();
            bad[..2].copy_from_slice(&len.to_ne_bytes());
            assert!(traffic(&bad).is_none());
        }
        let mut old = valid[..108].to_vec();
        old[..2].copy_from_slice(&108u16.to_ne_bytes());
        assert!(traffic(&old).is_none());
    }
}
