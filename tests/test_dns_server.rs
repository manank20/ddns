use ddns::{process_datagram, DnsName, DnsRecord};
use fixed_buffer::FixedBuf;
use multimap::MultiMap;

#[test]
fn test_process_datagram() {
    // From https://courses.cs.duke.edu//fall16/compsci356/DNS/DNS-primer.pdf
    // with some changes:
    // - Set result authoritative bit.
    let mut buf: FixedBuf<512> = FixedBuf::new();
    buf.write_bytes(&[
        0x9A, 0x9A, 1, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 97, 97, 97,
        0x07, 101, 120, 97, 109, 112, 108, 101, 0x03, 99, 111, 109, 0x00, 0x00, 0x01, 0x00, 0x01,
    ])
    .unwrap();
    let expected_response = [
        0x9A, 0x9A, 0x85, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x03, 97, 97, 97,
        0x07, 101, 120, 97, 109, 112, 108, 101, 0x03, 99, 111, 109, 0x00, 0x00, 0x01, 0x00, 0x01,
        0x03, 97, 97, 97, 0x07, 101, 120, 97, 109, 112, 108, 101, 0x03, 99, 111, 109, 0x00, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04, 10, 0, 0, 1_u8,
    ];
    let records = [DnsRecord::new_a("aaa.example.com", "10.0.0.1").unwrap()];
    let name_to_records: MultiMap<&DnsName, &DnsRecord> =
        records.iter().map(|x| (x.name(), x)).collect();
    let response = process_datagram(&name_to_records, &mut buf).unwrap();
    assert_eq!(expected_response, response.readable());
}
