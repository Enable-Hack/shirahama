use chrono::Utc;
use std::fmt;
use std::net::UdpSocket;

const LISTEN_ADDR: &str = "0.0.0.0:1053";
const TARGET_NAME: &str = "example.local.";
const ANSWER_IP: [u8; 4] = [192, 168, 56, 10];
const TTL: u32 = 60;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind(LISTEN_ADDR)?;
    eprintln!("DNS server listening on {}", LISTEN_ADDR);

    let mut buf = [0u8; 512];

    loop {
        let (size, peer) = socket.recv_from(&mut buf)?;
        let request = &buf[..size];

        let question = match parse_question(request) {
            Some(q) => q,
            None => {
                eprintln!("invalid DNS packet from {}", peer);
                continue;
            }
        };

        let response = match build_response(request, &question) {
            Some(r) => r,
            None => {
                eprintln!("failed to build response for {}", peer);
                continue;
            }
        };

        socket.send_to(&response.bytes, peer)?;

        let entry = serde_json::json!({
            "timestamp": now_iso8601(),
            "src_ip": peer.ip().to_string(),
            "src_port": peer.port(),
            "qname": question.qname,
            "qtype": question.qtype.to_string(),
            "rcode": response.rcode.to_string(),
            "response_bytes": response.bytes.len()
        });

        println!("{}", entry);
    }
}

fn now_iso8601() -> String {
    Utc::now().to_rfc3339()
}

struct Question {
    qname: String,
    qtype: QType,
    qclass: u16,
    question_end: usize,
}

struct DnsResponse {
    bytes: Vec<u8>,
    rcode: RCode,
}

#[derive(Clone, Copy)]
enum QType {
    A,
    Other(u16),
}

impl fmt::Display for QType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QType::A => write!(f, "A"),
            QType::Other(value) => write!(f, "TYPE{}", value),
        }
    }
}

#[derive(Clone, Copy)]
enum RCode {
    NoError,
    NXDomain,
}

impl fmt::Display for RCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RCode::NoError => write!(f, "NOERROR"),
            RCode::NXDomain => write!(f, "NXDOMAIN"),
        }
    }
}

fn parse_question(request: &[u8]) -> Option<Question> {
    if request.len() < 12 {
        return None;
    }

    let qdcount = u16::from_be_bytes([request[4], request[5]]);

    if qdcount != 1 {
        return None;
    }

    let mut pos = 12;
    let qname = read_qname(request, &mut pos)?;

    if pos + 4 > request.len() {
        return None;
    }

    let raw_qtype = u16::from_be_bytes([request[pos], request[pos + 1]]);
    let qclass = u16::from_be_bytes([request[pos + 2], request[pos + 3]]);
    pos += 4;

    let qtype = match raw_qtype {
        1 => QType::A,
        other => QType::Other(other),
    };

    Some(Question {
        qname,
        qtype,
        qclass,
        question_end: pos,
    })
}

fn build_response(request: &[u8], question: &Question) -> Option<DnsResponse> {
    if request.len() < 12 {
        return None;
    }

    let transaction_id = u16::from_be_bytes([request[0], request[1]]);
    let request_flags = u16::from_be_bytes([request[2], request[3]]);

    let is_target_name = question.qname == TARGET_NAME;
    let is_a_record = matches!(question.qtype, QType::A);
    let is_in_class = question.qclass == 1;

    let has_answer = is_target_name && is_a_record && is_in_class;

    let rcode = if has_answer {
        RCode::NoError
    } else {
        RCode::NXDomain
    };

    let rd_bit = request_flags & 0x0100;

    let rcode_bits = match rcode {
        RCode::NoError => 0,
        RCode::NXDomain => 3,
    };

    // QR=1, AA=1, RDは維持, RA=0, RCODEは結果に応じて設定
    let response_flags = 0x8000 | 0x0400 | rd_bit | rcode_bits;

    let mut bytes = Vec::new();

    // Header
    bytes.extend_from_slice(&transaction_id.to_be_bytes());
    bytes.extend_from_slice(&response_flags.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    bytes.extend_from_slice(&(if has_answer { 1u16 } else { 0u16 }).to_be_bytes()); // ANCOUNT
    bytes.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    bytes.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question section
    bytes.extend_from_slice(&request[12..question.question_end]);

    if has_answer {
        // Answer section

        // NAME: pointer to QNAME at offset 12
        bytes.extend_from_slice(&[0xc0, 0x0c]);

        bytes.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
        bytes.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
        bytes.extend_from_slice(&TTL.to_be_bytes());
        bytes.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        bytes.extend_from_slice(&ANSWER_IP);
    }

    Some(DnsResponse { bytes, rcode })
}

fn read_qname(packet: &[u8], pos: &mut usize) -> Option<String> {
    let mut labels = Vec::new();

    loop {
        if *pos >= packet.len() {
            return None;
        }

        let len = packet[*pos] as usize;
        *pos += 1;

        if len == 0 {
            break;
        }

        // 最小実装なので圧縮QNAMEは対象外
        if len & 0xc0 != 0 {
            return None;
        }

        if *pos + len > packet.len() {
            return None;
        }

        let label = std::str::from_utf8(&packet[*pos..*pos + len]).ok()?;
        labels.push(label.to_string());

        *pos += len;
    }

    Some(format!("{}.", labels.join(".")))
}
