#![allow(clippy::needless_return)]
#![feature(portable_simd)]

use core_simd::Simd;
use core::convert::TryInto;
use srng::SRng;
use simd_aes::SimdAes;

const DEFAULT_SEED: Simd<u8, 16> = Simd::from_array([
    178, 201, 95, 240, 40, 41, 143, 216,
    2, 209, 178, 114, 232, 4, 176, 188,
]);

#[allow(non_snake_case)]
fn ComputeGlyphHash(data: &[u8]) -> Simd<u8, 16> {
    let zero = Simd::splat(0);
    let mut hash = Simd::<u64, 2>::from_array([data.len() as u64, 0]).to_ne_bytes();
    hash ^= DEFAULT_SEED;

    let mut chunks = data.chunks_exact(16);
    for chunk in chunks.by_ref() {
        let chunk: &[u8; 16] = chunk.try_into().unwrap();
        let value = Simd::from_array(*chunk);
        hash ^= value;
        hash = hash.aes_dec(zero);
        hash = hash.aes_dec(zero);
        hash = hash.aes_dec(zero);
        hash = hash.aes_dec(zero);
    }

    let remainder = chunks.remainder();
    let mut temp = [0_u8; 16];
    temp[..remainder.len()].copy_from_slice(remainder);
    let value = Simd::from_array(temp);

    hash ^= value;
    hash = hash.aes_dec(zero);
    hash = hash.aes_dec(zero);
    hash = hash.aes_dec(zero);
    hash = hash.aes_dec(zero);
    return hash;
}

#[allow(dead_code)]
fn inv_aes_dec(mut data: Simd<u8, 16>, key: Simd<u8, 16>) -> Simd<u8, 16> {
    data ^= key;
    let zero = Simd::splat(0);
    data = data.aes_dec_last(zero).aes_enc(zero);
    return data.aes_enc_last(zero);
}

fn inv_aes_decx4(mut hash: Simd<u8, 16>) -> Simd<u8, 16> {
    let zero = Simd::splat(0);
    hash = hash.aes_dec_last(zero);
    hash = hash.aes_enc(zero);
    hash = hash.aes_enc(zero);
    hash = hash.aes_enc(zero);
    hash = hash.aes_enc(zero);
    hash = hash.aes_enc_last(zero);
    return hash;
}

fn single_prefix(count: usize, target_hash: Simd<u8, 16>) -> Simd<u8, 16> {
    // The first stage looks like this:
    //     Hash ^ Seed = dec^4(Count ^ Seed ^ Chunk)
    // To get the chunk, we need to reverse these:
    //     dec^-4(Hash ^ Seed) = Count ^ Seed ^ Chunk
    //     Chunk = dec^4(Hash ^ Seed) ^ Count ^ Seed
    // To create a one-prefix initialization, we want:
    //     Hash = Count
    //     Count = Count + 16
    let mut hash = target_hash;
    hash = inv_aes_decx4(hash);

    let prefix_init = Simd::<u64, 2>::from_array([count as u64 + 16, 0]).to_ne_bytes();
    hash ^= prefix_init;
    hash ^= DEFAULT_SEED;

    return hash;
}

fn preimage_prefix_hash(mut hash: Simd<u8, 16>, data: &[u8]) -> Simd<u8, 16> {
    let chunks = data.len() / 16;
    let tail = &data[chunks*16..];
    let mut tail_buf = [0_u8; 16];
    tail_buf[..tail.len()].copy_from_slice(tail);
    let value = Simd::from_array(tail_buf);

    hash = inv_aes_decx4(hash);
    hash ^= value;

    for chunk in data.chunks_exact(16).rev() {
        let chunk: &[u8; 16] = chunk.try_into().unwrap();
        let value = Simd::from_array(*chunk);
        hash = inv_aes_decx4(hash);
        hash ^= value;
    }

    return hash;
}

fn invert_block(mut hash: Simd<u8, 16>, chunk: &[u8]) -> Simd<u8, 16> {
    let chunk: &[u8; 16] = chunk.try_into().unwrap();
    let value = Simd::from_array(*chunk);
    hash = inv_aes_decx4(hash);
    return hash ^ value;
}

fn invert_last(suffix: &[u8], mut hash: Simd<u8, 16>) -> Simd<u8, 16> {
    let mut tail_buf = [0_u8; 16];
    tail_buf[..suffix.len()].copy_from_slice(suffix);
    let value = Simd::from_array(tail_buf);

    hash = inv_aes_decx4(hash);
    hash ^= value;
    hash = inv_aes_decx4(hash);
    return hash;
}

fn concat(prefix: Simd<u8, 16>, target: &[u8]) -> Vec<u8> {
    let mut image = prefix.to_array().to_vec();
    image.extend_from_slice(target);
    image
}

fn prefix_collision_attack(message: &[u8]) {
    let mut target_hash = Simd::<u64, 2>::from_array([message.len() as u64, 0]).to_ne_bytes();
    target_hash ^= DEFAULT_SEED;

    let prefix = single_prefix(message.len(), target_hash);
    println!("Demonstrating prefix attack");
    println!("message: {:x?}", message);
    println!("hash:    {:x?}", ComputeGlyphHash(b"hello"));
    println!("prefix:  {:x?}", prefix);
    let forgery = concat(prefix, message);
    println!("forgery: {:x?}", forgery);
    println!("hash:    {:x?}", ComputeGlyphHash(&forgery));
    println!();
}

fn chosen_prefix(prefix: &[u8]) {
    let zero = Simd::splat(0);
    let mut message = prefix.to_vec();
    let remainder = 16 - (message.len() % 16);
    message.extend((0..remainder).map(|_| b'A'));
    message.extend((0..16).map(|_| 0));
    let hash = ComputeGlyphHash(&message);
    let pre_current = invert_last(&[], hash);
    let pre_target = invert_last(&[], zero);
    let last = message.len() - 16;
    let suffix = pre_current ^ pre_target;
    message[last..].copy_from_slice(&suffix.to_array());
    println!("Demonstrating chosen prefix attack");
    println!("prefix:  {:x?}", prefix);
    println!("forgery: {:x?}", message);
    println!("hash:    {:x?}", ComputeGlyphHash(&message));
    println!();
}

fn preimage_attack(suffix: &[u8]) {
    println!("Demonstrating preimage attack");
    println!("suffix:    {:x?}", suffix);
    let target_hash = Simd::splat(0);
    println!("goal hash: {:x?}", target_hash);
    let prefix_hash = preimage_prefix_hash(target_hash, suffix);
    let preimage_prefix = single_prefix(suffix.len(), prefix_hash);
    println!("prefix:    {:x?}", preimage_prefix);
    let message = concat(preimage_prefix, suffix);

    println!("message:   {:x?}", message);
    println!("hash:      {:x?}", ComputeGlyphHash(&message));
}

fn padding_attack() {
    println!("Demonstrating padding attack");
    println!(r#"message: "",      hash: {:x?}"#, ComputeGlyphHash(b""));
    println!(r#"message: "\x01",  hash: {:x?}"#, ComputeGlyphHash(b"\x01"));
    println!(r#"message: "A",     hash: {:x?}"#, ComputeGlyphHash(b"A"));
    println!(r#"message: "B\x00", hash: {:x?}"#, ComputeGlyphHash(b"B\x00"));
    println!(r#"message: "BAAAAAAAAAAAAAAA",         hash: {:x?}"#, ComputeGlyphHash(b"BAAAAAAAAAAAAAAA"));
    println!(r#"message: "CAAAAAAAAAAAAAAA\x00",     hash: {:x?}"#, ComputeGlyphHash(b"CAAAAAAAAAAAAAAA\x00"));
    println!();
}

fn invert_attack(message: &[u8]) {
    println!("Demonstrating invert attack, invert a hash up to 15 bytes");
    println!("Note: due to padding attack, there are actually more messages");
    println!("plaintext: {:x?}", message);
    let mut hash = ComputeGlyphHash(message);
    println!("hash:      {:x?}", hash);
    hash = inv_aes_decx4(hash);
    hash ^= DEFAULT_SEED;
    let mut buffer = hash.to_array();
    let len = buffer.iter().rposition(|&chr| chr != 0).map_or(0, |x| x + 1);
    if len == 16 {
        println!("the plaintext mus be shorter than 16 bytes, cannot invert");
        return;
    }
    buffer[0] ^= len as u8;
    let recovered = &buffer[..len];
    println!("recovered: {:x?}", recovered);
    println!("hash:      {:x?}", ComputeGlyphHash(recovered));
    println!();
}

pub fn check_alphanum(bytes: Simd<u8, 16>) -> bool {
    // check if the characters are outside of '0'..'z' range
    if (bytes - Simd::splat(b'0')).lanes_gt(Simd::splat(b'z' - b'0')).any() {
        return false;
    }
    // check if the characters are in of '9'+1..'A'-1 range
    if (bytes - Simd::splat(b'9' + 1)).lanes_lt(Simd::splat(b'A' - (b'9' + 1))).any() {
        return false;
    }
    // check if the characters are in of 'Z'+1..'a'-1 range
    if (bytes - Simd::splat(b'Z' + 1)).lanes_lt(Simd::splat(b'a' - (b'Z' + 1))).any() {
        return false;
    }
    return true;
}

use core::sync::atomic::{AtomicBool, Ordering};
static FOUND: AtomicBool = AtomicBool::new(false);
fn find_ascii_zeros(suffix: &[u8], worker: u64) {
    const ATTACK_BYTES: usize = 6;
    let mut target_hash = Simd::<u8, 16>::splat(0);
    let mut bsuffix = suffix;
    let suffix_len = 16 - ATTACK_BYTES;
    let mut whole_block = false;
    if suffix.len() >= suffix_len {
        target_hash = preimage_prefix_hash(target_hash, &suffix[suffix_len..]);
        bsuffix = &suffix[..suffix_len];
        whole_block = true;
    }
    let mut controlled = [0u8; 16];
    let total_len = ATTACK_BYTES + suffix.len();
    let controlled_bytes = total_len.min(16);
    let controlled = &mut controlled[..controlled_bytes];
    controlled[ATTACK_BYTES..].copy_from_slice(bsuffix);

    let seed = Simd::from_array([
        17820195240, 4041143216,
        22093178114, 2324176188,
    ]);
    let mut rng = SRng::new(seed * Simd::splat(worker + 1));
    let start = std::time::Instant::now();

    for ii in 0_u64.. {
        if FOUND.load(Ordering::Relaxed) {
            return;
        }

        let prefix = rng.random_alphanum();
        controlled[..6].copy_from_slice(&prefix[..6]);

        let prefix = {
            let prefix_hash = if whole_block {
                invert_block(target_hash, controlled)
            } else {
                preimage_prefix_hash(target_hash, controlled)
            };
            single_prefix(total_len, prefix_hash)
        };

        if check_alphanum(prefix) {
            FOUND.store(true, Ordering::Relaxed);
            let mut buffer = prefix.to_array().to_vec();
            buffer.extend_from_slice(&controlled[..6]);
            buffer.extend_from_slice(suffix);
            let elapsed = start.elapsed();
            let mhs = (ii as f64) / 1e6 / elapsed.as_secs_f64();
            eprintln!("found prefix in {}it {:?} {:3.3}MH/s/core", ii, elapsed, mhs);
            eprintln!("hash: {:x?}", ComputeGlyphHash(&buffer));
            println!("{}", core::str::from_utf8(&buffer).unwrap());
            break;
        }
    }
}

const MESSAGE: &[&[u8]] = &[
    b" Hello Casey!  I hope this message finds you well.",
    b" Please ignore those 22 random chars to the left for now.",
    b" The work you've done on refterm is admirable.  There are",
    b" not enough performance conscious programmers around, and",
    b" we need a demonstration of what is achievable.  However,",
    b" I would like to address the claim that the hash function",
    b" used in refterm is 'cryptographically secure'.  There is",
    b" a very specific meaning attached to those words, namely:",
    b" 1) it is hard to create a message for a given hash value",
    b" 2) it is hard to produce two messages with the same hash",
    b" If you check, the following strings have the same hash:",
    b" xvD7FsaUdGy9UyjalZlFEU, 0XXPpB0wpVszsvSxgsn0su,",
    b" IGNwdjol0dxLflcnfW7vsI, jcTHx0zBJbW2tdiX157RSz.",
    b" In fact, every line in the message yields the exact same",
    b" hash value.  That is 0x00000000000000000000000000000000.",
    b" I believe this was a clear enough demonstration that the",
    b" hash function `ComputeGlyphHash` isn't cryptographically",
    b" secure, and that an attacker can corrupt the glyph cache",
    b" by printing glyphs with the same hash.  The main problem",
    b" with this hash function is that all operations consuming",
    b" bytes are invertible.  Which means an attacker could run",
    b" the hash function in reverse, consuming the message from",
    b" behind, and calculate the message to get the given hash.",
    b" The hash is also weak to a padding attack.  For example,",
  br#" two strings "A" and "B\x00" yield the same hash, because"#,
    b" the padding is constant, so zero byte in the end doens't",
    b" matter, and the first byte is `xor`ed with input length.",
    b" If you'd like to, you can read this blog post explaining",
    b" these attacks in detail and how to avoid them using well",
    b" known methods: https://m1el.github.io/refterm-hash",
    b" Best regards, -- Igor",
];

fn main() {
    padding_attack();
    invert_attack(b"Qwerty123");
    prefix_collision_attack(b"hello");
    chosen_prefix(b"hello");
    preimage_attack(b"hello");

    const THREADS: u64 = 16;
    for msg in MESSAGE {
        FOUND.store(false, Ordering::Relaxed);
        let threads = (0..THREADS)
            .map(|worker| std::thread::spawn(move || find_ascii_zeros(msg, worker)))
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
    };
}
