use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use ciborium::value::Value;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, IsCa, KeyPair, KeyUsagePurpose,
    PublicKeyData, SignatureAlgorithm,
};

use crate::cbor::{as_array, as_bytes, as_map, bytes, decode, encode, map_get};

pub(super) enum Reply {
    Valid,
    WrongKey,
    Rejected,
    Unknown,
}

type RecordedRequests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

pub(super) struct Server {
    pub url: String,
    pub requests: RecordedRequests,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl Server {
    pub fn start(reply: Reply) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (stored, stopping) = (requests.clone(), stop.clone());
        let worker = thread::spawn(move || {
            while !stopping.load(Ordering::SeqCst) {
                let Ok((mut socket, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                socket.set_nonblocking(false).unwrap();
                let (path, body) = read_request(&mut socket);
                stored.lock().unwrap().push((path.clone(), body.clone()));
                if path.contains(":fetchEekChain") {
                    let body = encode(&Value::Array(vec![
                        Value::Array(vec![]),
                        bytes(vec![9; 32]),
                    ]))
                    .unwrap();
                    respond(&mut socket, 200, &body);
                } else {
                    match reply {
                        Reply::Unknown => {}
                        Reply::Rejected => {
                            respond(&mut socket, 403, b"do not reflect this response")
                        }
                        Reply::Valid | Reply::WrongKey => {
                            let data = certificates(&body, matches!(reply, Reply::WrongKey));
                            respond(&mut socket, 200, &data);
                        }
                    }
                }
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let result = self.worker.take().unwrap().join();
        if !thread::panicking() {
            result.unwrap();
        }
    }
}

fn read_request(socket: &mut TcpStream) -> (String, Vec<u8>) {
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut data = Vec::new();
    let (end, header) = loop {
        let mut buffer = [0; 8192];
        let size = socket.read(&mut buffer).unwrap();
        assert!(size > 0);
        data.extend_from_slice(&buffer[..size]);
        if let Some(end) = data.windows(4).position(|v| v == b"\r\n\r\n") {
            break (end + 4, String::from_utf8(data[..end].to_vec()).unwrap());
        }
    };
    let length = header
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().unwrap())
        })
        .unwrap_or(0);
    while data.len() < end + length {
        let mut buffer = [0; 8192];
        let size = socket.read(&mut buffer).unwrap();
        assert!(size > 0);
        data.extend_from_slice(&buffer[..size]);
    }
    (
        header.lines().next().unwrap().to_string(),
        data[end..end + length].to_vec(),
    )
}

fn respond(socket: &mut TcpStream, status: u16, body: &[u8]) {
    write!(
        socket,
        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .unwrap();
    socket.write_all(body).unwrap();
}

struct Requested(Vec<u8>);
impl PublicKeyData for Requested {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

fn certificates(csr: &[u8], wrong_key: bool) -> Vec<u8> {
    let value = decode(csr).unwrap();
    let request = as_array(&value, "CSR").unwrap();
    let signed = as_array(&request[3], "signed").unwrap();
    let payload = decode(as_bytes(&signed[2], "payload").unwrap()).unwrap();
    let signed_items = as_array(&payload, "payload").unwrap();
    assert_eq!(as_bytes(&signed_items[0], "challenge").unwrap(), &[9; 32]);
    let csr_payload = decode(as_bytes(&signed_items[1], "CSR payload").unwrap()).unwrap();
    let keys = as_array(&as_array(&csr_payload, "CSR payload").unwrap()[3], "keys").unwrap();
    let key = as_map(&keys[0], "key").unwrap();
    let mut public = vec![4];
    public.extend_from_slice(as_bytes(map_get(key, -2).unwrap(), "x").unwrap());
    public.extend_from_slice(as_bytes(map_get(key, -3).unwrap(), "y").unwrap());
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let root = CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap();
    let mut leaf_params = CertificateParams::default();
    leaf_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    leaf_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    leaf_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "synthetic attestation");
    let other = KeyPair::generate().unwrap();
    let wrong = leaf_params.signed_by(&other, &root).unwrap();
    let mut unique = vec![bytes(wrong.der().to_vec())];
    if !wrong_key {
        unique.push(bytes(
            leaf_params
                .signed_by(&Requested(public), &root)
                .unwrap()
                .der()
                .to_vec(),
        ));
    }
    encode(&Value::Array(vec![
        bytes(root.der().to_vec()),
        Value::Array(unique),
    ]))
    .unwrap()
}
