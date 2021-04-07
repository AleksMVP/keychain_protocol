extern crate openssl;
extern crate sha2;

use openssl::pkey::{Private, Public};
use openssl::rsa::{Padding, Rsa};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::convert::TryFrom;
use std::time::{Duration, SystemTime};

const TIME_LENGTH: usize = 8;

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

fn now() -> [u8; TIME_LENGTH] {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap();
    let nanos: u64 = now.as_nanos() as u64;
    nanos.to_be_bytes()
}

fn elapsed(since: [u8; TIME_LENGTH], to: [u8; TIME_LENGTH]) -> Option<Duration> {
    if let Some(diff) = u64::from_be_bytes(to).checked_sub(u64::from_be_bytes(since)) {
        Some(Duration::from_nanos(diff))
    } else {
        None
    }
}

struct Car {
    rsa: Rsa<Public>,
}

struct Keychain {
    rsa: Rsa<Private>,
}

enum MessageKind {
    CommandOpen = 1, // keychain sends this to open the car
    Success = 1 << 2, // car sends this to notify keychain about success of the operation
}

trait MessageProcessor {
    fn process(self: &Self, message: &Vec<u8>) -> Option<Vec<u8>>;
}

impl TryFrom<u8> for MessageKind {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == MessageKind::CommandOpen as u8 => Ok(MessageKind::CommandOpen),
            x if x == MessageKind::Success as u8 => Ok(MessageKind::Success),
            _ => Err(()),
        }
    }
}

impl Car {
    fn new(pem: Vec<u8>) -> Car {
        let rsa = Rsa::public_key_from_pem(&pem).unwrap();
        Car { rsa }
    }
}

impl Keychain {
    fn new(pem: Vec<u8>) -> Keychain {
        let rsa = Rsa::private_key_from_pem(&pem).unwrap();
        Keychain { rsa }
    }

    fn get_initiation_message(self: &Self) -> Vec<u8> {
        let mut message = vec![MessageKind::CommandOpen as u8];
        let mut sha = Sha256::new();
        let mut time = now().to_vec();
        sha.input(&time);
        let hash = sha.result();
        let mut sign: Vec<u8> = vec![0; 256];
        self.rsa
            .private_encrypt(&hash, sign.as_mut_slice(), Padding::PKCS1)
            .unwrap();
        time.extend_from_slice(&sign);
        message.extend_from_slice(&time);
        message
    }
}

impl MessageProcessor for Car {
    fn process(self: &Self, message: &Vec<u8>) -> Option<Vec<u8>> {
        if message.len() > TIME_LENGTH + 1 {
            if let Ok(MessageKind::CommandOpen) = MessageKind::try_from(message[0]) {
                println!("car recieved CommandOpen:\n{}", hex(&message[..]));
                let message = message[1..].to_vec();
                let mut sha = Sha256::new();
                let mut time = [0u8; TIME_LENGTH];
                for i in 0..TIME_LENGTH {
                    time[i] = message[i];
                }

                if let Some(duration) = elapsed(time, now()) {
                    if duration.as_secs() < 1 {
                        let mut decrypted_hash: Vec<u8> = vec![0; 256];
                        if let Ok(_) = self.rsa.public_decrypt(
                            &message[TIME_LENGTH..],
                            decrypted_hash.as_mut_slice(),
                            Padding::PKCS1,
                        ) {
                            sha.input(&time);
                            let hash2 = sha.result().to_vec();
                            for (k, &v) in hash2.iter().enumerate() {
                                if decrypted_hash[k] != v {
                                    return None;
                                }
                            }
                            return Some(vec![MessageKind::Success as u8]);
                        }
                    }
                }
            }
        }
        return None;
    }
}

impl MessageProcessor for Keychain {
    fn process(self: &Self, message: &Vec<u8>) -> Option<Vec<u8>> {
        if message.len() < 1 {
            return None;
        }
        if let Ok(MessageKind::Success) = MessageKind::try_from(message[0]) {
            println!("keys recieved Success");
        }
        return None;
    }
}

fn make_key_car_pair() -> (Car, Keychain) {
    let rsa = Rsa::generate(2048).unwrap();
    let (public_pem, private_pem) = (
        rsa.public_key_to_pem().unwrap(),
        rsa.private_key_to_pem().unwrap(),
    );
    println!(
        "registration:\n\tcar:\n{}\n\tkeychain:\n{}",
        hex(&public_pem[..]),
        hex(&private_pem[..])
    );
    (Car::new(public_pem), Keychain::new(private_pem))
}

fn main() {
    let (car, keychain) = make_key_car_pair();
    let devices: Vec<&dyn MessageProcessor> = vec![&car, &keychain];
    let mut ether: VecDeque<Vec<u8>> = VecDeque::new();
    let message = keychain.get_initiation_message();
    ether.push_front(message);

    while ether.len() > 0 {
        if let Some(x) = ether.pop_back() {
            for d in &devices {
                if let Some(response) = d.process(&x) {
                    ether.push_front(response);
                }
            }
        }
    }
}