//! Connects to l2cap_server and sends and receives test data.

use bluer::{
    adv::Advertisement,
    l2cap::{SocketAddr, PSM_LE_DYN_START, StreamListener},
};
use rand::prelude::*;
use std::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use openssl::pkey::PKey;
use openssl::symm::{encrypt, Cipher};
use openssl::sign::Signer;
use openssl::hash::MessageDigest;
use openssl::derive::Deriver;
use openssl::x509::X509;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509StoreContext;
use openssl::sign::Verifier;
use openssl::ec::EcGroup;
use openssl::nid::Nid;
use openssl::ec::EcKey;

use bluer::l2cap::Stream;
use bluer::Address;

use tokio::io::AsyncBufReadExt;

use std::io::BufReader;
use std::io::BufRead;

use std::time::Duration;
use tokio::time::sleep;

const BLUETOOTH_PARAMETERS_PATH_LINUX: &str = "/var/lib/bluetooth/";

const CA_CERT_FILE: &str = "cert_CA.crt";

const RSA_KEY_FILE: &str = "rsa_key.pem";
//const RSA_PASSWORD = None;
const RSA_CERT_FILE: &str = "cert_RSA.crt";

const ECDH_KEY_FILE: &str = "ecdh_key.pem";
//const ECDH_PASSWORD = None;
const ECDH_CERT_FILE: &str = "cert_DH.crt";

const PSM: u16 = PSM_LE_DYN_START + 1;

async fn get_ltk(addr: &str, remote_addr: &str) -> std::io::Result<Vec<u8>> {
    for _n in 1..=2{
        let path = BLUETOOTH_PARAMETERS_PATH_LINUX.to_owned() + addr + "/" + remote_addr + "/info";

        let info_file = fs::File::open(path)?;
        let reader = BufReader::new(info_file);

        let mut start = false;
        for line in reader.lines() {
            let line = line?;
            if start && line.contains("Key"){
                let ltk = line.split("=").collect::<Vec<&str>>()[1].trim();
                return Ok(hex::decode(ltk).expect("Key decoding failed"));
            }
            if line.contains("LongTermKey") {
                start = true;
            }
        }
        sleep(Duration::from_secs(6)).await;
    }
    Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No LTK found"))
}

async fn digital_signature(certificate: &X509) -> bool {
    let text = certificate.to_text().unwrap();
    let mut extension = false;
    let mut digital_signature = false;
    let mut lines = tokio::io::BufReader::new(std::io::Cursor::new(text)).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        
        if line.contains("X509v3 Key Usage") {
            extension = true;
            continue;
        }
        if line.contains("Digital Signature") && extension {
            digital_signature = true;
            break;
        }
        if line.contains("X509v3") {
            extension = false;
            continue;
        }
    }
    return digital_signature;
}

async fn validate_certificate(
    certificate: &X509,
    addr: &bluer::Address,
) -> bluer::Result<()> {
    let file = fs::read(CA_CERT_FILE).unwrap();
    let cert_ca = openssl::x509::X509::from_pem(&file).unwrap();

    let mut store_builder = X509StoreBuilder::new().unwrap();
    store_builder.add_cert(cert_ca).unwrap();
    let store = store_builder.build();

    let mut store_ctx = X509StoreContext::new().unwrap();
    let chain = openssl::stack::Stack::new().unwrap();
    store_ctx
        .init(
            &store,
            &certificate,
            &chain,
            |c| c.verify_cert()
        )
        .unwrap();

    if certificate.subject_name().entries_by_nid(openssl::nid::Nid::COMMONNAME).next().unwrap().data().as_utf8().unwrap().contains(addr.to_string().as_str()) == false{
        println!("❌ Certificate does match the address: {:?}", addr);
        return Err(bluer::Error::from(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Certificate does not match the address: {:?}",
                addr
            ),
        )));
    }

    // Check if certificate has KeyUsage with the DigitalSignature bit set
    if !digital_signature(certificate).await {
        println!("❌ Certificate missing DigitalSignature in KeyUsage");
        return Err(bluer::Error::from(std::io::Error::new(
            std::io::ErrorKind::Other,
            "Certificate missing DigitalSignature in KeyUsage",
        )));
    }

    if store_ctx.error() == openssl::x509::X509VerifyResult::OK {
        println!("✅ Certificate is valid!");
        Ok(())
    } else {
        let e = store_ctx.error();
        println!("❌ Certificate is invalid: {:?}", e);
        Err(bluer::Error::from(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("Certificate invalid: {:?}", e),
        )))
    }
}

async fn authentication_signature(
    stream: &mut Stream,
    adapter_addr: Address,
    target_addr: Address
) -> bluer::Result<()> {
    println!("Mode: Signatures");

    let start = std::time::Instant::now();

    let mut chall_a = [0u8; 16];
    stream.read_exact(&mut chall_a).await.expect("Receiving chall_a failed");

    let mut rng = rand::rng();
    let chall_b = rng.random::<[u8; 16]>();

    let pem = fs::read(RSA_KEY_FILE).unwrap();
    let private_key = PKey::private_key_from_pem(&pem).unwrap();

    let ltk = get_ltk(&adapter_addr.to_string(), &target_addr.to_string()).await?;

    let time_encryption = std::time::Instant::now();

    let cipher = Cipher::aes_128_ctr();
    let data = chall_b;
    let nonce = rng.random::<[u8; 16]>();
    let encrypted = encrypt(cipher, &ltk, Some(&nonce), &data).unwrap();

    println!("Encryption time: {:?}", time_encryption.elapsed());

    let pair_req: &[u8] = b"000000";

    let time_signing = std::time::Instant::now();

    let message = [&encrypted, &chall_a[..], &chall_b[..], pair_req].concat();
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
    signer.update(&message).unwrap();
    let signature = signer.sign_to_vec().unwrap();

    println!("Signature time: {:?}", time_signing.elapsed());

    let file = fs::read(RSA_CERT_FILE).unwrap();

    let time_sending = std::time::Instant::now();

    let time_sc = std::time::Instant::now();
    stream.write_all(&signature).await.expect("Sending signature failed");
    stream.write_all(&chall_b).await.expect("Sending chall_b failed");
    println!("Sending chall_b & signature: {:?}", time_sc.elapsed());

    let test = std::time::Instant::now();
    stream.write_all(&chall_a).await.expect("Sending chall_a failed");
    println!("Sending chall_a: {:?}", test.elapsed());


    let time_pair_req = std::time::Instant::now();
    stream.write_all(&pair_req).await.expect("Sending pair_req failed");
    println!("Sending pair_req: {:?}", time_pair_req.elapsed());

    println!("Sending first part: {:?}", time_sending.elapsed());

    let cert_len = file.len().min(u16::MAX as usize) as u16;
    let cert_len_buf = cert_len.to_be_bytes();
    stream.write_all(&cert_len_buf).await.expect("Sending cert_len_buf failed");
    stream.write_all(&file).await.expect("Sending certificate failed");
    stream.write_all(&nonce).await.expect("Sending nonce failed");

    println!("Sending time: {:?}", time_sending.elapsed());

    stream.read_exact(&mut [0u8; 1]).await.expect("Receiving response failed");

    let elapsed = start.elapsed();
    println!("Elapsed time: {:?}", elapsed);

    verifying_signature(stream, target_addr, adapter_addr).await.expect("Verifying signature failed");

    return Ok(())
}

async fn authentication_dh(
    stream: &mut Stream,
    adapter_addr: Address,
    target_addr: Address
) -> bluer::Result<()> {
    println!("Mode: DH");

    let start = std::time::Instant::now();

    let pem = fs::read(ECDH_KEY_FILE).unwrap();
    let private_key = PKey::private_key_from_pem(&pem).unwrap();

    let mut public_key_central_pem = [0u8; 178];
    stream.read_exact(&mut public_key_central_pem).await.expect("Receiving ecdh public key failed");
    let public_key_central = PKey::public_key_from_pem(&public_key_central_pem).unwrap();

    let mut deriver = Deriver::new(&private_key).unwrap();
    deriver.set_peer(&public_key_central).unwrap();
    let shared_key = deriver.derive_to_vec().unwrap();

    let mut chall_a = [0u8; 16];
    stream.read_exact(&mut chall_a).await.expect("Receiving chall_a failed");

    let mut rng = rand::rng();
    let chall_b = rng.random::<[u8; 16]>();

    let ltk = get_ltk(&adapter_addr.to_string(), &target_addr.to_string()).await?;

    let cipher = Cipher::aes_128_ctr();
    let data = chall_b;
    let nonce = rng.random::<[u8; 16]>();
    let encrypted = encrypt(cipher, &ltk, Some(&nonce), &data).unwrap();

    let pair_req = b"000000";

    let message = [&encrypted, &chall_a[..], &chall_b[..], pair_req].concat();

    // CMAC signature
    let cipher = openssl::symm::Cipher::aes_256_cbc();
    let pkey = PKey::cmac(&cipher, &shared_key).expect("Failed to create CMAC key");
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("Failed to create CMAC signer");
    signer.update(&message).expect("Failed to update CMAC key");
    let signature = signer.sign_to_vec().unwrap();

    let file = fs::read(ECDH_CERT_FILE).unwrap();

    stream.write_all(&signature).await.expect("Sending signature failed");
    stream.write_all(&chall_b).await.expect("Sending chall_b failed");
    stream.write_all(&pair_req[..]).await.expect("Sending pair_req failed");
    let cert_len = file.len().min(u16::MAX as usize) as u16;
    let cert_len_buf = cert_len.to_be_bytes();
    stream.write_all(&cert_len_buf).await.expect("Sending cert_len_buf failed");
    stream.write_all(&file).await.expect("Sending certificate failed");
    stream.write_all(&nonce).await.expect("Sending nonce failed");

    stream.read_exact(&mut [0u8; 1]).await.expect("Receiving response failed");

    let elapsed = start.elapsed();
    println!("Elapsed time: {:?}", elapsed);

    verifying_dh(stream, target_addr, adapter_addr).await.expect("Verifying DH failed");

    return Ok(())
}

async fn verifying_signature(
    stream: &mut Stream,
    target_addr: Address,
    adapter_addr: Address
) -> bluer::Result<()> {
    let mut rng = rand::rng();
    let chall_a = rng.random::<[u8; 16]>();

    stream.write_all(&chall_a).await.expect("write failed");

    let mut chall_b = [0u8; 16];
    let mut signature = [0u8; 256];
    let mut pair_req = [0u8; 6];
    let mut nonce = [0u8; 16];
    let mut cert_len_buf = [0u8; 2];

    stream.read_exact(&mut signature).await.expect("read signature failed");
    stream.read_exact(&mut chall_b).await.expect("read chall_b failed");
    stream.read_exact(&mut pair_req).await.expect("read pair_req failed");
    stream.read_exact(&mut cert_len_buf).await.expect("read cert_len_buf failed");

    let cert_len = u16::from_be_bytes(cert_len_buf) as usize;
    let mut cert_buffer = vec![0u8; cert_len];
    stream.read_exact(&mut cert_buffer).await.expect("read cert_buffer failed");
    let cert = X509::from_pem(&cert_buffer).expect("Failed to parse certificate as DER");

    stream.read_exact(&mut nonce).await.expect("read failed");

    let ltk = get_ltk(&adapter_addr.to_string(), &target_addr.to_string()).await?;

    let cipher = Cipher::aes_128_ctr();
    let encrypted = encrypt(cipher, &ltk, Some(&nonce), &chall_b).unwrap();

    let message = [&encrypted, &chall_a[..], &chall_b[..], &pair_req].concat();
    let public_key = cert.public_key().unwrap();

    validate_certificate(&cert, &target_addr).await?;

    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).unwrap();
    verifier.update(&message).unwrap();
    let verify = verifier.verify(&signature).unwrap();
    assert!(verify);

    println!("Signature verified");

    return Ok(());
}

async fn verifying_dh(
    stream: &mut Stream,
    target_addr: Address, 
    adapter_addr: Address
) -> bluer::Result<()> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)
        .map_err(|e| bluer::Error::from(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
    let private_key = EcKey::generate(&group)
        .map_err(|e| bluer::Error::from(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    stream.write_all(
        &PKey::from_ec_key(private_key.clone())
            .unwrap()
            .public_key_to_pem()
            .unwrap()
    ).await.expect("sending public key failed");

    let mut rng = rand::rng();
    let chall_a = rng.random::<[u8; 16]>();

    stream.write_all(&chall_a).await.expect("sending chall_a failed");
    
    let mut chall_b = [0u8; 16];
    let mut signature = [0u8; 16];
    let mut pair_req = [0u8; 6];
    let mut nonce = [0u8; 16];
    let mut cert_len_buf = [0u8; 2];

    stream.read_exact(&mut signature).await.expect("receiving signature failed");
    stream.read_exact(&mut chall_b).await.expect("receiving chall_b failed");
    stream.read_exact(&mut pair_req).await.expect("receiving pair_req failed");
    stream.read_exact(&mut cert_len_buf).await.expect("receiving cert_len_buf failed");

    let cert_len = u16::from_be_bytes(cert_len_buf) as usize;
    let mut cert_buffer = vec![0u8; cert_len];
    stream.read_exact(&mut cert_buffer).await.expect("receiving cert_buffer failed");
    let cert = X509::from_pem(&cert_buffer).expect("Failed to parse certificate as DER");

    stream.read_exact(&mut nonce).await.expect("receiving nonce failed");

    let ltk = get_ltk(&adapter_addr.to_string(), &target_addr.to_string()).await?;

    let cipher = Cipher::aes_128_ctr();
    let encrypted = encrypt(cipher, &ltk, Some(&nonce), &chall_b).unwrap();

    let message = [&encrypted, &chall_a[..], &chall_b[..], &pair_req].concat();

    let public_key = cert.public_key().unwrap();
    let private_pkey = PKey::from_ec_key(private_key).unwrap();
    let mut deriver = Deriver::new(&private_pkey).unwrap();
    deriver.set_peer(&public_key).unwrap();
    let shared_key = deriver.derive_to_vec().unwrap();

    validate_certificate(&cert, &target_addr).await?;
    
    let cipher = openssl::symm::Cipher::aes_256_cbc();
    let pkey = PKey::cmac(&cipher, &shared_key).expect("Failed to create CMAC key");
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey).expect("Failed to create CMAC signer");
    signer.update(&message).expect("Failed to update CMAC key");
    let signature_test = signer.sign_to_vec().unwrap();
    if signature_test != signature {
        println!("❌ Signature does not match: {:?}", &signature_test);
        assert_eq!(signature_test, signature, "Signature does not match");
    }

    println!("Signature verified");

    return Ok(());

}

#[tokio::main]
async fn main() -> bluer::Result<()> {
    println!("Authentication Peripheral");
    env_logger::init();
    let session = bluer::Session::new().await?;
    let adapter = session.default_adapter().await?;
    adapter.set_powered(true).await?;
    println!("Adapter: {}", adapter.name());
    let adapter_addr = adapter.address().await?;
    let adapter_addr_type = adapter.address_type().await?;

    // Advertising is necessary for device to be connectable.
    println!(
        "Advertising on Bluetooth adapter {} with {} address {}",
        adapter.name(),
        &adapter_addr_type,
        &adapter_addr
    );
    let le_advertisement = Advertisement {
        discoverable: Some(true),
        advertisement_type: bluer::adv::Type::Peripheral,
        local_name: Some("Peripheral".to_string()),
        ..Default::default()
    };
    let adv_handle = adapter.advertise(le_advertisement).await?;

    let local_sa = SocketAddr::new(adapter_addr, adapter_addr_type, PSM);
    let listener = StreamListener::bind(local_sa).await?;

    let mut security = listener.as_ref().security()?;
    security.level = bluer::l2cap::SecurityLevel::Fips;
    security.key_size = 16;
    listener.as_ref().set_security(security)?;

    println!("Listening on PSM {}", listener.as_ref().local_addr()?.psm);

    let (mut stream, sa) = listener.accept().await.expect("accept failed");

    let recv_mtu = stream.as_ref().recv_mtu()?;
    println!("Accepted connection from {:?} with receive MTU {} bytes", &sa, &recv_mtu);

    let mut mode_s = [0u8; 1];
    stream.read_exact(&mut mode_s).await.expect("read failed");
    let mode = mode_s[0];

    let device = adapter.device(sa.addr)?;
    let target_addr = sa.addr;

    if mode == 0 {
        match authentication_signature(&mut stream, adapter_addr, target_addr).await {
            Ok(_) => println!("Signature verification successful"),
            Err(e) => {
                println!("Signature verification failed: {:?}", e);
                device.disconnect().await?;
                adapter.remove_device(target_addr).await?;
            }
        }
    }
    if mode == 1 {
        match authentication_dh(&mut stream, adapter_addr, target_addr).await {
            Ok(_) => println!("DH verification successful"),
            Err(e) => {
                println!("DH verification failed: {:?}", e);
                device.disconnect().await?;
                adapter.remove_device(target_addr).await?;
            }
        }
    }

    println!("Removing advertisement");
    drop(adv_handle);
    // sleep(Duration::from_secs(1)).await;
    

    println!("Done");
    Ok(())
}