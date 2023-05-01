use ddns::DnsRecord;
use permit::Permit;
use prob_rate_limiter::ProbRateLimiter;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::time::Duration;

// TODO: Test rate limiting.

#[test]
fn example() {
    let permit = Permit::new();
    let serve_udp_permit = permit.new_sub();
    let sock = UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).unwrap();
    let addr = sock.local_addr().unwrap();
    let response_bytes_rate_limiter = ProbRateLimiter::new(100_000);
    let records = vec![
        DnsRecord::new_a("aaa.example.com", "10.0.0.1").unwrap(),
        DnsRecord::new_aaaa("aaa.example.com", "2606:2800:220:1:248:1893:25c8:1946").unwrap(),
        DnsRecord::new_cname("bbb.example.com", "ccc.example.com").unwrap(),
    ];
    let join_handle = std::thread::spawn(move || {
        ddns::serve_udp(
            &serve_udp_permit,
            &sock,
            response_bytes_rate_limiter,
            &records,
        )
        .unwrap();
    });
    assert!(Command::new("dig")
        .arg("@localhost")
        .arg("-p")
        .arg(addr.port().to_string())
        .arg("+time=1")
        .arg("a")
        .arg("aaa.example.com")
        .status()
        .unwrap()
        .success());
    assert!(Command::new("dig")
        .arg("@localhost")
        .arg("-p")
        .arg(addr.port().to_string())
        .arg("+time=1")
        .arg("aaaa")
        .arg("aaa.example.com")
        .status()
        .unwrap()
        .success());
    assert!(Command::new("dig")
        .arg("@localhost")
        .arg("-p")
        .arg(addr.port().to_string())
        .arg("+time=1")
        .arg("aaa.example.com")
        .status()
        .unwrap()
        .success());
    assert!(Command::new("dig")
        .arg("@localhost")
        .arg("-p")
        .arg(addr.port().to_string())
        .arg("+time=1")
        .arg("cname")
        .arg("bbb.example.com")
        .status()
        .unwrap()
        .success());
    permit.revoke();
    join_handle.join().unwrap();
}

#[test]
#[allow(clippy::unusual_byte_groupings)]
#[allow(clippy::too_many_lines)]
fn hard_coded() {
    let permit = Permit::new();
    let serve_udp_permit = permit.new_sub();
    let server_sock =
        UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).unwrap();
    let addr = server_sock.local_addr().unwrap();
    let response_bytes_rate_limiter = ProbRateLimiter::new(100_000);
    let records = vec![
        DnsRecord::new_a("aaa.example.com", "10.0.0.1").unwrap(),
        DnsRecord::new_aaaa("aaa.example.com", "2606:2800:220:1:248:1893:25c8:1946").unwrap(),
    ];
    let join_handle = std::thread::spawn(move || {
        ddns::serve_udp(
            &serve_udp_permit,
            &server_sock,
            response_bytes_rate_limiter,
            &records,
        )
        .unwrap();
    });
    let client_sock =
        UdpSocket::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).unwrap();
    client_sock
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client_sock
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    client_sock.connect(addr).unwrap();
    let mut buf = [0_u8; 512];
    // request type=A
    client_sock
        .send(&[
            // ID
            0x9A,
            0x9A,
            // is_response=0b0, opcode=0b0000 QUERY, authoritative=0b0, truncated=0b0, recursion_desired=0b0
            0b0_0000_0_0_1,
            // recursion_available=0b0, reserved=0b000, response_code=0b0000 NOERROR
            0b0_000_0000,
            // question_count=1
            0x00,
            0x01,
            // answer_count=0
            0x00,
            0x00,
            // name_server_count=0
            0x00,
            0x00,
            // additional_count=0
            0x00,
            0x00,
            // question 0
            // name=aaa.example.com
            0x03,
            97,
            97,
            97,
            0x07,
            101,
            120,
            97,
            109,
            112,
            108,
            101,
            0x03,
            99,
            111,
            109,
            0x00,
            // type=1 A
            0x00,
            0x01,
            // class=1 IN
            0x00,
            0x01,
        ])
        .unwrap();
    let response_len = client_sock.recv(&mut buf).unwrap();
    let response = &buf[0..response_len];
    assert_eq!(
        vec![
            // ID
            0x9A,
            0x9A,
            // is_response=0b1, opcode=0b0000 QUERY, authoritative=0b1, truncated=0b0, recursion_desired=0b1
            0b1_0000_1_0_1,
            // recursion_available=0b0, reserved=0b000, response_code=0b0000 NOERROR
            0b0_000_0000,
            // question_count=1
            0x00,
            0x01,
            // answer_count=1
            0x00,
            0x01,
            // name_server_count=0
            0x00,
            0x00,
            // additional_count=0
            0x00,
            0x00,
            // question 0
            // name=aaa.example.com
            0x03,
            97,
            97,
            97,
            0x07,
            101,
            120,
            97,
            109,
            112,
            108,
            101,
            0x03,
            99,
            111,
            109,
            0x00,
            // type=1 A
            0x00,
            0x01,
            // class=1 IN
            0x00,
            0x01,
            // answer 0
            // name=aaa.example.com
            0x03,
            97,
            97,
            97,
            0x07,
            101,
            120,
            97,
            109,
            112,
            108,
            101,
            0x03,
            99,
            111,
            109,
            0x00,
            // type=1 A
            0x00,
            0x01,
            // class=1 IN
            0x00,
            0x01,
            // ttl_seconds=300
            0x00,
            0x00,
            0x01,
            0x2C,
            // rdlength=4
            0x00,
            0x04,
            // ipv4_addr=10.0.0.1
            10,
            0,
            0,
            1,
        ],
        response
    );
    // request type=AAAA
    client_sock
        .send(&[
            // ID
            0x9A,
            0x9A,
            // is_response=0b0, opcode=0b0000 QUERY, authoritative=0b0, truncated=0b0, recursion_desired=0b0
            0b0_0000_0_0_1,
            // recursion_available=0b0, reserved=0b000, response_code=0b0000 NOERROR
            0b0_000_0000,
            // question_count=1
            0x00,
            0x01,
            // answer_count=0
            0x00,
            0x00,
            // name_server_count=0
            0x00,
            0x00,
            // additional_count=0
            0x00,
            0x00,
            // question 0
            // name=aaa.example.com
            0x03,
            97,
            97,
            97,
            0x07,
            101,
            120,
            97,
            109,
            112,
            108,
            101,
            0x03,
            99,
            111,
            109,
            0x00,
            // type=28 AAAA
            0x00,
            0x1C,
            // class=1 IN
            0x00,
            0x01,
        ])
        .unwrap();
    let response_len = client_sock.recv(&mut buf).unwrap();
    let response = &buf[0..response_len];
    assert_eq!(
        vec![
            // ID
            0x9A,
            0x9A,
            // is_response=0b1, opcode=0b0000 QUERY, authoritative=0b1, truncated=0b0, recursion_desired=0b1
            0b1_0000_1_0_1,
            // recursion_available=0b0, reserved=0b000, response_code=0b0000 NOERROR
            0b0_000_0000,
            // question_count=1
            0x00,
            0x01,
            // answer_count=1
            0x00,
            0x01,
            // name_server_count=0
            0x00,
            0x00,
            // additional_count=0
            0x00,
            0x00,
            // question 0
            // name=aaa.example.com
            0x03,
            97,
            97,
            97,
            0x07,
            101,
            120,
            97,
            109,
            112,
            108,
            101,
            0x03,
            99,
            111,
            109,
            0x00,
            // type=28 AAAA
            0x00,
            0x1C,
            // class=1 IN
            0x00,
            0x01,
            // answer 0
            // name=aaa.example.com
            0x03,
            97,
            97,
            97,
            0x07,
            101,
            120,
            97,
            109,
            112,
            108,
            101,
            0x03,
            99,
            111,
            109,
            0x00,
            // type=28 AAAA
            0x00,
            0x1C,
            // class=1 IN
            0x00,
            0x01,
            // ttl_seconds=300
            0x00,
            0x00,
            0x01,
            0x2C,
            // rdlength=16
            0x00,
            0x10,
            // ipv6_addr=2606:2800:220:1:248:1893:25c8:1946
            0x26,
            0x06,
            0x28,
            0x00,
            0x02,
            0x20,
            0x00,
            0x01,
            0x02,
            0x48,
            0x18,
            0x93,
            0x25,
            0xc8,
            0x19,
            0x46
        ],
        response
    );
    // request type=ANY
    client_sock
        .send(&[
            // ID
            0x9A,
            0x9A,
            // is_response=0b0, opcode=0b0000 QUERY, authoritative=0b0, truncated=0b0, recursion_desired=0b0
            0b0_0000_0_0_1,
            // recursion_available=0b0, reserved=0b000, response_code=0b0000 NOERROR
            0b0_000_0000,
            // question_count=1
            0x00,
            0x01,
            // answer_count=0
            0x00,
            0x00,
            // name_server_count=0
            0x00,
            0x00,
            // additional_count=0
            0x00,
            0x00,
            // question 0
            // name=aaa.example.com
            0x03,
            97,
            97,
            97,
            0x07,
            101,
            120,
            97,
            109,
            112,
            108,
            101,
            0x03,
            99,
            111,
            109,
            0x00,
            // type=255 ANY
            0x00,
            0xFF,
            // class=1 IN
            0x00,
            0x01,
        ])
        .unwrap();
    let response_len = client_sock.recv(&mut buf).unwrap();
    let response = &buf[0..response_len];
    assert_eq!(
        vec![
            // ID
            0x9A,
            0x9A,
            // is_response=0b1, opcode=0b0000 QUERY, authoritative=0b1, truncated=0b0, recursion_desired=0b1
            0b1_0000_1_0_1,
            // recursion_available=0b0, reserved=0b000, response_code=0b0000 NOERROR
            0b0_000_0000,
            // question_count=1
            0x00,
            0x01,
            // answer_count=2
            0x00,
            0x02,
            // name_server_count=0
            0x00,
            0x00,
            // additional_count=0
            0x00,
            0x00,
            // question 0
            // name=aaa.example.com
            0x03,
            97,
            97,
            97,
            0x07,
            101,
            120,
            97,
            109,
            112,
            108,
            101,
            0x03,
            99,
            111,
            109,
            0x00,
            // type=255 ANY
            0x00,
            0xFF,
            // class=1 IN
            0x00,
            0x01,
            // answer 0
            // name=aaa.example.com
            0x03,
            97,
            97,
            97,
            0x07,
            101,
            120,
            97,
            109,
            112,
            108,
            101,
            0x03,
            99,
            111,
            109,
            0x00,
            // type=1 A
            0x00,
            0x01,
            // class=1 IN
            0x00,
            0x01,
            // ttl_seconds=300
            0x00,
            0x00,
            0x01,
            0x2C,
            // rdlength=4
            0x00,
            0x04,
            // ipv4_addr=10.0.0.1
            10,
            0,
            0,
            1,
            // answer 1
            // name=aaa.example.com
            0x03,
            97,
            97,
            97,
            0x07,
            101,
            120,
            97,
            109,
            112,
            108,
            101,
            0x03,
            99,
            111,
            109,
            0x00,
            // type=28 AAAA
            0x00,
            0x1C,
            // class=1 IN
            0x00,
            0x01,
            // ttl_seconds=300
            0x00,
            0x00,
            0x01,
            0x2C,
            // rdlength=16
            0x00,
            0x10,
            // ipv6_addr=2606:2800:220:1:248:1893:25c8:1946
            0x26,
            0x06,
            0x28,
            0x00,
            0x02,
            0x20,
            0x00,
            0x01,
            0x02,
            0x48,
            0x18,
            0x93,
            0x25,
            0xc8,
            0x19,
            0x46
        ],
        response
    );
    permit.revoke();
    join_handle.join().unwrap();
}

// https://github.com/m-ou-se/single-use-dns
// https://crates.io/crates/dns-parser/0.8.0
// https://docs.rs/rusty_dns/0.0.3/rusty_dns/index.html
