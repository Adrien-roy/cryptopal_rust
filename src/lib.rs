use base64::{engine::general_purpose, Engine};
use hex;
use std::panic::{catch_unwind};
use std::fs;
use aes::Aes128;
use block_modes::{BlockMode, Ecb};
use block_modes::block_padding::NoPadding;
use crate::fs::File;
use rand::thread_rng;
type Aes128Ecb = Ecb<Aes128, NoPadding>;
use std::io::BufRead;
use std::io::BufReader;
use rand::Rng;
use std::collections::HashMap;
use std::time::{UNIX_EPOCH,SystemTime,Duration};
use urlencoding::encode;
use std::thread::sleep;
use std::thread;

pub mod challenge13;
pub mod rng;
use crate::rng::Mt19937;
use crate::rng::ReverseMt19937;
use crate::rng::untemper;
pub mod sha1;
use crate::sha1::Sha1;

use num_traits::{Zero, One,ToBytes,ToPrimitive};
use hmac::{Hmac, Mac};
use sha2::{Sha256,Digest};
use num_bigint::{BigInt,BigUint, RandBigInt, ToBigUint,ToBigInt};
use std::ops::{Shr, Rem};

use num_primes::Generator;


type HmacSha256 = Hmac<Sha256>;

pub fn convert_hexstring_to_base64string(hex_str: &str) -> String {
    let bytes = hex::decode(hex_str).expect("Invalid hex string");
    general_purpose::STANDARD.encode(bytes)
}

pub fn convert_base64_to_hexstring(b64_str: &str) -> String {
    let bytes = general_purpose::STANDARD
        .decode(b64_str)
        .expect("Invalid Base64 string");
    hex::encode(bytes)
}

pub fn convert_hexa_to_vec(input: &str) -> Vec<u8> {
    input.as_bytes().chunks(2).map(|pair| {
            let hex_str = std::str::from_utf8(pair).expect("Invalid UTF-8");
            u8::from_str_radix(hex_str, 16).expect("Invalid hex digit")
        })
        .collect()
}
pub fn convert_base64_to_vec(b64_str: &str) -> Vec<u8> {
    general_purpose::STANDARD
        .decode(b64_str)
        .expect("Invalid Base64 string")
}

pub fn convert_vec_to_hexa(input: &Vec<u8>) -> String{
        input.iter()
        .map(|num| format!("{:02x}", num)) // Lowercase hex (use {:02X} for uppercase)
        .collect::<String>()

}






pub fn xor_two(vec1: &[u8], vec2: &[u8])-> Vec<u8> {

    let xor_bytes: Vec<u8> = vec1.iter()
        .zip(vec2.iter())
        .map(|(a, b)| a ^ b)
        .collect();

    xor_bytes
}

pub fn hex_to_ascii(hex_str: &str) -> String {
    let bytes = hex::decode(hex_str).expect("Invalid hex string");
    let ascii = String::from_utf8_lossy(&bytes);
    ascii.to_string()
}

pub fn vec_to_ascii(input: &[u8]) -> String {
    let string = String::from_utf8_lossy(input).to_string();
    string.chars().collect()
}

pub fn ascii_to_vec(input: &str) -> Vec<u8> {
    input.as_bytes().to_vec()
}



pub fn score_text(text: &Vec<u8>) -> i32 {
    let common_letters = "etaoinshrdluETAOIN SHRDLU";
    let string = vec_to_ascii(&text);
    string.chars()
        .map(|c| {
            let uc = c.to_ascii_uppercase();
            if common_letters.contains(uc) {
                1
            } else {
                0
            }
        })
        .sum()
}

pub fn xor_one_string(hex_vec: &[u8]) -> Vec<u8> {
    let mut best_score = 0;
    let mut best_xored = Vec::new();

    for key in 0u8..=255 {
        let xored: Vec<u8> = hex_vec.iter().map(|b| b ^ key).collect();

        let score = score_text(&xored);
        if score > best_score {
            best_score = score;
            best_xored = xored;
        }
        
    }

    best_xored
}


pub fn get_best_key(hex_vec: &[u8]) -> u8 {
    let mut best_score = 0;
    let mut best_key = 0;

    for key in 0u8..=255 {
        let xored: Vec<u8> = hex_vec.iter().map(|b| b ^ key).collect();

        let score = score_text(&xored);
        if score > best_score {
            best_score = score;
            best_key = key;
        }
        
    }

    best_key
}




pub fn encrypt_repeating_key(entry_vec: &[u8], key:&[u8]) -> Vec<u8> {
    let xor_bytes: Vec<u8> = entry_vec 
        .iter()
        .zip(key.iter().cycle())
        .map(|(a, b)| a ^ b)
        .collect();
    xor_bytes
}

pub fn hamming_distance(vec1 : &[u8] , vec2 :&[u8]) -> u32 {

    vec1.iter()
        .zip(vec2.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum()
}

pub fn read_file_to_string(path: &str) -> String {
    fs::read_to_string(path).expect("Failed to read file")
}

pub fn read_file_lines(path: &str) -> Vec<String> {
    let file = File::open(path).expect("Failed to open file");
    let reader = BufReader::new(file);

    reader
        .lines()
        .map(|line| line.expect("Failed to read line"))
        .collect()
}

pub fn find_keysize(input_vec: &[u8]) -> usize{
    let mut min_distance = u32::MAX;
    let mut best_keysize = 0;
    
    for keysize in 2..=40{
        let chunks:Vec<&[u8]> = input_vec.chunks(keysize).take(2).collect();
        if chunks.len() < 2 {
            continue;
        }
        let chunk1 = chunks[0];
        let chunk2 = chunks[1];
        let distance = hamming_distance(&chunk1,&chunk2)/keysize as u32;

        if distance < min_distance{
            min_distance = distance;
            best_keysize = keysize ;
        } 

    }

    best_keysize
}



pub fn vigenere(input_vec: &[u8],key_length:usize)-> Vec<u8> {

    let mut groups: Vec<Vec<u8>> = vec![Vec::new(); key_length];
    let mut results: Vec<Vec<u8>> = vec![Vec::new(); key_length];
    
    for (i, &byte) in input_vec.iter().enumerate() {
    groups[i % key_length].push(byte);
    }
    for (i,group) in groups.iter().enumerate(){
        results[i] = xor_one_string(&group);
    }

    let combined = zip_by_column(&results);
    combined
}


pub fn zip_by_column(chunks: &[Vec<u8>]) -> Vec<u8> {
    let max_len = chunks.iter().map(|v| v.len()).max().unwrap_or(0);
    let mut combined = Vec::new();

    for i in 0..max_len {
        for chunk in chunks {
            if let Some(&val) = chunk.get(i) {
                combined.push(val);
            }
        }
    }

    combined
}





pub fn aes_ecb_encrypt(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128Ecb::new_from_slices(key, &[]).expect("Invalid key");
    cipher.encrypt_vec(plaintext)
}


pub fn aes_ecb_decrypt(key: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes128Ecb::new_from_slices(key, &[]).expect("Invalid key");
    cipher.decrypt_vec(ciphertext).expect("Decryption error")
}






pub fn cbc_encrypt_block(block_to_encrypt:&[u8],previous_block:&[u8],key:&[u8]) -> Vec<u8>{

    let cyphertext = xor_two(block_to_encrypt,previous_block);
    let result = aes_ecb_encrypt(key,&cyphertext);
    result
}


pub fn cbc_encrypt(key: &[u8],vec_to_encrypt:&[u8],iv:&[u8]) -> Vec<u8>{


    let length = vec_to_encrypt.len();
    let nb_block;
    let padded_text;
    let output_vec:Vec<u8>;

    if length%16 != 0{
        padded_text = padding(&vec_to_encrypt,(length / 16 + 1) * 16);
        nb_block = length/16 +1;
    }else{
        nb_block = length/16;
        padded_text = vec_to_encrypt.to_vec();
    }

    let mut input_block: Vec<Vec<u8>> = vec![Vec::new(); nb_block +1]; //nb of line in file
    let mut output_block: Vec<Vec<u8>> = vec![Vec::new(); nb_block +1];


    input_block = padded_text
        .chunks(16)
        .map(|chunk| chunk.to_vec())  // convert &[u8] slice to Vec<u8>
        .collect();
    input_block.insert(0, iv.to_vec());
    output_block.insert(0,iv.to_vec());

    for i in 0..= nb_block-1{
        output_block[i+1]=cbc_encrypt_block(&input_block[i+1],&output_block[i],&key);
    }

    output_vec = output_block.iter().skip(1).flatten().copied().collect();
    output_vec

}
pub fn cbc_decrypt(key: &[u8],vec_to_encrypt:&[u8],iv:&[u8]) -> Vec<u8>{


    let length = vec_to_encrypt.len();
    let nb_block;
    let padded_text;
    let output_vec:Vec<u8>;

    if length%16 != 0{
        padded_text = padding(&vec_to_encrypt,(length / 16 + 1) * 16);
        nb_block = length/16 +1;
    }else{
        nb_block = length/16;
        padded_text = vec_to_encrypt.to_vec();
    }

    let mut input_block: Vec<Vec<u8>> = vec![Vec::new(); nb_block +1]; //nb of line in file
    let mut output_block: Vec<Vec<u8>> = vec![Vec::new(); nb_block +1];


    input_block = padded_text
        .chunks(16)
        .map(|chunk| chunk.to_vec()) 
        .collect();
    input_block.insert(0, iv.to_vec());
    output_block.insert(0,iv.to_vec());

    for i in 0..= nb_block-1{
        output_block[i+1]=cbc_decrypt_block(&input_block[i+1],&input_block[i],&key);
    }

    output_vec = output_block.iter().skip(1).flatten().copied().collect();
    output_vec

}



pub fn cbc_decrypt_block( block_to_decrypt: &[u8], previous_block: &[u8],key:&[u8]) -> Vec<u8> {

    let decrypted = aes_ecb_decrypt(&key, &block_to_decrypt);
    let result = xor_two(&decrypted, &previous_block);
    result
}








pub fn padding(entry: &[u8], padding_to: usize) -> Vec<u8> {
    let mut result = entry.to_vec();

    if entry.len() < padding_to {
        let pad_len = padding_to - entry.len();
        result.extend(std::iter::repeat(pad_len as u8).take(pad_len));
    }

    result
}

pub fn remove_padding(entry: &[u8]) -> Vec<u8> {
    if entry.is_empty() {
        return Vec::new();
    }

    let pad_len = *entry.last().unwrap() as usize;

    if pad_len == 0 || pad_len > entry.len() {
        panic!("Invalid padding");
    }

    // Check that all padding bytes are equal to pad_len
    if !entry[entry.len() - pad_len..].iter().all(|&b| b as usize == pad_len) {
        panic!("Invalid padding bytes");
    }

    entry[..entry.len() - pad_len].to_vec()
}

pub fn encrypt_random(entry:&[u8])-> Vec<u8>{
    let key = generate_random_key();
    let iv = generate_random_key();
    let mut rng = rand::thread_rng();
    let nb_append_before =rng.gen_range(5..=10);
    let nb_append_after = rng.gen_range(5..=10);

    let padded = pad_to_block_size(&padding_preandpost(entry,nb_append_before,nb_append_after,0x04),16);

    let encrypted;
    if rng.r#gen::<bool>(){
        encrypted = aes_ecb_encrypt(&key,&padded);
    }else{
        encrypted = cbc_encrypt(&key,&padded,&iv);
    }
    encrypted
}

pub fn generate_random_key() -> [u8; 16] {
    let mut key = [0u8; 16];
    rand::thread_rng().fill(&mut key);
    key
}



pub fn padding_preandpost(entry: &[u8], pad_before: usize, pad_after: usize, pad_byte: u8) -> Vec<u8> {
    let mut result = Vec::with_capacity(pad_before + entry.len() + pad_after);
    
    result.extend(std::iter::repeat(pad_byte).take(pad_before));
    result.extend_from_slice(entry);
    result.extend(std::iter::repeat(pad_byte).take(pad_after));
    
    result
}

pub fn pad_to_block_size(entry: &[u8], block_size: usize) -> Vec<u8> {
    let mut result = entry.to_vec();
    let pad_len = block_size - (entry.len() % block_size);
    let pad_byte = pad_len as u8;

    // If already aligned, add a full block of padding for compliance with pck7
    let pad_len = if pad_len == 0 { block_size } else { pad_len };

    result.extend(std::iter::repeat(pad_byte).take(pad_len));
    result
}

pub fn detect_repeating(entry: &[u8])-> i32{ // take a ciphered text tells if there is repetiotion in it 

    let mut groups: Vec<Vec<u8>> = vec![Vec::new(); entry.len()/16];

    let mut hamming;


    for (i, &byte) in entry.iter().enumerate() {
        groups[i/16].push(byte);
    }

    let mut nb_of_repeated_block =0;
    for i in 1..= (entry.len()/16)-1{
        for j in 0..= (i-1){
        hamming = hamming_distance(&groups[i],&groups[j]);
        if hamming == 0{
            nb_of_repeated_block += 1;
        }
        }
    }
    nb_of_repeated_block
}

pub fn iterate_byte_possibilities_inline(
    buffer_vec: &mut [u8],
    byte_index: usize,
    mut f: impl FnMut(&[u8], u8),
) {
    let original = buffer_vec[byte_index];
    for value in 0u8..=255 {
        buffer_vec[byte_index] = value;
        f(buffer_vec, value);
    }
    buffer_vec[byte_index] = original;
}


pub fn shift_left_and_append(arr: &mut [u8; 16], new_byte: u8) {
    for i in 0..(arr.len() - 1) {
        arr[i] = arr[i + 1];
    }

    arr[arr.len() - 2] = new_byte;
}

pub fn combine_3_vec(    buffer_guess_vec: &[u8],      
    buffer_padding_vec: &[u8],    
    third_buffer: &[u8],          
) -> Vec<u8> {
    let total_len = buffer_guess_vec.len() + buffer_padding_vec.len() + third_buffer.len();
    let mut combined = Vec::with_capacity(total_len);
    
    combined.extend_from_slice(buffer_guess_vec);
    combined.extend_from_slice(buffer_padding_vec);
    combined.extend_from_slice(third_buffer);

    combined
}

pub fn fill_vec_to_length(vec: &mut Vec<u8>, target_length: usize, fill_val: u8) {
    if vec.len() > target_length {
        // Truncate to target_length
        vec.truncate(target_length);
    } else if vec.len() < target_length {
        // Extend to target_length with fill_val
        vec.extend(std::iter::repeat(fill_val).take(target_length - vec.len()));
    }

    // Now fill the first `target_length` bytes with fill_val
    for i in 0..target_length {
        vec[i] = fill_val;
    }
}
pub fn remove_trailing_ones(data: &[u8]) -> &[u8] {
    let mut end = data.len();
    while end > 0 && data[end - 1] == 1 {
        end -= 1;
    }
    &data[..end]
}

pub fn parse_kv_string(s: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in s.split('&') {
        if let Some(pos) = pair.find('=') {
            let key = &pair[..pos];
            let val = &pair[pos + 1..];
            map.insert(key.to_string(), val.to_string());
        }
    }
    map
}

// Percent-encode the email so metacharacters are escaped safely

pub fn profile_for(email: &str) -> String {
    let uid = 10;
    let role = "user";
    let safe_email = encode(email);

    format!("email={}&uid={}&role={}", safe_email, uid, role)
}

pub fn is_admin_tuple(s: &str) -> bool {
    s.split(';')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            if let (Some(key), Some(value)) = (parts.next(), parts.next()) {
                Some((key, value))
            } else {
                None
            }
        })
        .any(|(key, value)| key == "admin" && value == "true")
}

pub fn split_into_blocks<const N: usize>(data: &[u8]) -> Vec<[u8; N]> {
    assert!(
        data.len() % N == 0,
        "Input length is not a multiple of block size"
    );

    let mut blocks = Vec::with_capacity(data.len() / N);

    for chunk in data.chunks(N) {
        let block: [u8; N] = chunk.try_into().expect("Chunk size mismatch");
        blocks.push(block);
    }

    blocks
}


pub fn decrypt_cbc_with_padding_attack(iv: [u8; 16], full_ciphertext: &[u8]) -> Vec<u8> {
    let blocks = split_into_blocks::<16>(full_ciphertext);
    let mut decrypted_message = Vec::with_capacity(full_ciphertext.len());
    let mut previous_block = iv;

    for current_block in blocks.iter() {
        let result = cbc_block_padding_attack(&previous_block, &*current_block);
        decrypted_message.extend_from_slice(&result);
        previous_block = *current_block;
    }

    decrypted_message
}


pub fn cbc_block_padding_attack(previous_block:&[u8;16],attacked_block:&[u8;16]) -> [u8;16]{

    let mut attacking_iv = [0u8; 16]; 
    let mut original_message = [0u8; 16]; 




    for  i in (0..=15).rev() {
        for  j in 0u8..=255 {
            attacking_iv[i] = j;
            if !oracle(attacked_block,&attacking_iv){
                original_message[i] = attacking_iv[i] ^ (16-i) as u8 ;
               
                for k in 0..16{
                    attacking_iv[k] = original_message[k] ^ (17-i) as u8
                }
                break;
            } 
        }
    }

    for i in 0..16 {
        original_message[i] = previous_block[i] ^ original_message[i];
    }

original_message
}


pub fn client()-> (Vec<u8>, [u8;16]){
    let options = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    ];

    // Pick one at random

    let plaintext = convert_hexa_to_vec(&convert_base64_to_hexstring(options[2]));// set as fixed for test

    let iv = b"YELLOW_SUBMARINE";

    let key = b"YELLOW_SUBMARINE";//original i know the attacker doen't know it 


    let cipher = cbc_encrypt(key,&pad_to_block_size(&plaintext,16),iv);

    (cipher, *iv)

}

pub fn oracle(ciphertext : &[u8],iv:&[u8])-> bool{

    let key = b"YELLOW_SUBMARINE";//original i know the attacker doen't know it 
    let plaintext = cbc_decrypt(key,&ciphertext,iv);
    let result = catch_unwind(|| {
        let _text2_vec=remove_padding(&plaintext);
    });

    result.is_err()

}



pub fn ctr_construct(key:[u8;16],message:&[u8]) -> Vec<u8>{
    let nonce =[0;8] ;
    let keystream = generate_keystream(key, nonce,message.len());
    let output = xor_two(&keystream, &message);
    output
}


pub fn generate_keystream(key: [u8; 16], nonce: [u8; 8], length: usize) -> Vec<u8> {
    let mut keystream = vec![0u8; length];
    let mut counter = [0u8; 8];
    let mut offset = 0;

    while offset < length {
        // Combine nonce + counter in little endian
        let mut block = [0u8; 16];
        block[..8].copy_from_slice(&nonce);
        block[8..].copy_from_slice(&counter);

        let cipher_block = aes_ecb_encrypt(&key, &block);
        let chunk_size = (length - offset).min(16);
        keystream[offset..offset + chunk_size].copy_from_slice(&cipher_block[..chunk_size]);

        increment_le_bytes(&mut counter);
        offset += chunk_size;
    }

    keystream
}

pub fn increment_le_bytes(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        let (new_byte, carry) = byte.overflowing_add(1);
        *byte = new_byte;
        if !carry {
            break; // no overflow, done incrementing
        }
    }
}

pub fn transpose_pad(vecs: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    if vecs.is_empty() {
        return Vec::new();
    }

    // Find max length of inner vectors
    let max_len = vecs.iter().map(|v| v.len()).max().unwrap_or(0);
    let row_len = max_len;
    let col_len = vecs.len();

    // Pad vectors with 0 if shorter than max_len
    let padded: Vec<Vec<u8>> = vecs.iter()
        .map(|v| {
            let mut padded_v = v.clone();
            padded_v.resize(max_len, 0); // pad with zeros
            padded_v
        })
        .collect();

    // Create transposed vector with swapped dimensions
    let mut transposed = vec![vec![0u8; col_len]; row_len];

    for i in 0..col_len {
        for j in 0..row_len {
            transposed[j][i] = padded[i][j];
        }
    }

    transposed
}


pub fn generate_random()-> u32{
    let seed = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards")
    .as_secs();
    let mut rng = Mt19937::new(seed.try_into().unwrap());
    let delay_secs = 0 + (rng.next_u32() % (40 - 0 + 1)); // Random u32 in [40, 1000]
    println!("Sleeping for {} seconds...", delay_secs);
    sleep(Duration::from_secs(delay_secs as u64));
    rng.next_u32()
}

pub fn clone_mt19937(original: &mut Mt19937) -> ReverseMt19937 {
    const N: usize = 256;
    let mut state = [0u32; N];
    for i in 0..N {
        let output = original.next_u32();
        state[i] = untemper(output);
    }

    ReverseMt19937::from_state(state)
}

pub fn last_full_u32(data: &[u8]) -> &[u8] {

    let trimmed_len = data.len() - (data.len() % 4);
    let slice = &data[trimmed_len - 4..trimmed_len];
    slice
}

pub fn mt19937_construct(key:u32,message:&[u8]) -> Vec<u8>{
    let mut rng = Mt19937::new(key);
    let keystream = generate_keystream_mt(&mut rng,message.len());// one result = 4 byte 
    let output = xor_two(&keystream, &message);
    output
}




pub fn generate_keystream_mt(rng: &mut Mt19937, length: usize) -> Vec<u8> {
    let mut keystream = Vec::with_capacity(length);
    
    while keystream.len() < length {
        let value = rng.next_u32();
        let bytes = value.to_le_bytes(); // or to_be_bytes() depending on spec

        let remaining = length - keystream.len();
        if remaining >= 4 {
            keystream.extend_from_slice(&bytes);
        } else {
            keystream.extend_from_slice(&bytes[..remaining]);
        }
    }
    
    keystream
}

pub fn sleep_random_5_to_10_seconds() {
    let secs = rand::thread_rng().gen_range(5..=10); // inclusive range
    println!("Sleeping for {} seconds...", secs);
    thread::sleep(Duration::from_secs(secs));
}



pub fn digest_to_state(digest: &[u8; 20]) -> [u32; 5] {
    let mut state = [0u32; 5];
    for i in 0..5 {
        let offset = i * 4;
        state[i] = ((digest[offset] as u32) << 24)
                 | ((digest[offset + 1] as u32) << 16)
                 | ((digest[offset + 2] as u32) << 8)
                 |  (digest[offset + 3] as u32);
    }
    state
}


pub fn sha1_padding(original_message_len: usize) -> Vec<u8> {
    let mut padding = Vec::new();

    // Step 1: append 0x80
    padding.push(0x80);

    // Step 2: calculate padding length
    let total_len = original_message_len + 1; // +1 for the 0x80 byte
    let rem = total_len % 64;
    let pad_len = if rem <= 56 {
        56 - rem
    } else {
        64 + 56 - rem
    };

    padding.extend(vec![0u8; pad_len]);

    // Step 3: append message length in bits (big endian)
    let bit_len = (original_message_len as u64) * 8;
    padding.extend(&bit_len.to_be_bytes());

    padding
}

pub fn modular_exponentiation(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    if *modulus == Zero::zero() {
        panic!("Modulus cannot be zero");
    }

    let mut result = One::one();
    let mut base = base % modulus;
    let mut exp = exp.clone();

    while exp > Zero::zero() {
        if (&exp & &One::one()) == One::one() {
            result = (result * &base) % modulus;
        }
        exp >>= 1;
        base = (&base * &base) % modulus;
    }

    result
}



pub struct Participant {
    private_key: BigUint,
    public_key: BigUint,
    shared_key: Option<BigUint>,
    p: BigUint,
    g: BigUint,
}

impl Participant {
    pub fn new(p: &BigUint, g: &BigUint) -> Self {
        let mut rng = thread_rng();
        let private = rng.gen_biguint_below(p);
        let public = modular_exponentiation(g, &private, p);

        Self {
            private_key: private,
            public_key: public,
            shared_key: None,
            p: p.clone(),
            g: g.clone(),
        }
    }

pub fn compute_shared_key(&mut self, other_public: &BigUint) {
    self.shared_key = Some(modular_exponentiation(other_public, &self.private_key, &self.p));
}
pub fn export_public(&self) -> (BigUint, BigUint, BigUint) {
    (self.p.clone(), self.g.clone(), self.public_key.clone())
}

/// Receive (p, g, peer's public_key) and set up internal values
pub fn receive_public(&mut self, p: BigUint, g: BigUint, other_public: BigUint) {
    self.p = p.clone();
    self.g = g.clone();
    self.compute_shared_key(&other_public);
}

/// Export just the public key (used after receiving p & g)
pub fn export_public_key(&self) -> BigUint {
    self.public_key.clone()
}

/// Receive the other party’s public key and compute shared secret
pub fn receive_public_key(&mut self, other_public: BigUint) {
    self.compute_shared_key(&other_public);
}

pub fn encrypt_message(&self, message: &[u8]) -> Vec<u8> {
    let s = self.shared_key.as_ref().unwrap();

    let iv = generate_random_key();
    let mut sha = Sha1::new();
    sha.update(&s.to_bytes_be());
    let key = sha.digest().bytes();
    let ciphertext = cbc_encrypt(&key[0..16], &pad_to_block_size(message, 16), &iv);

    let mut encrypted = Vec::with_capacity(ciphertext.len() + iv.len());
    encrypted.extend_from_slice(&ciphertext);
    encrypted.extend_from_slice(&iv);
    encrypted
}
pub fn set_shared_key(&mut self, forced_key: BigUint) {
    self.shared_key = Some(forced_key);
}


pub fn decrypt_message(&self, encrypted: &[u8]) -> Vec<u8> {
    let s = self.shared_key.as_ref().unwrap();

    let (ciphertext, iv) = encrypted.split_at(encrypted.len() - 16);
    let mut sha = Sha1::new();
    sha.update(&s.to_bytes_be());
    let key = sha.digest().bytes();
    let decrypted = cbc_decrypt(&key[0..16], ciphertext, iv);
    remove_padding(&decrypted)
}

}
pub fn message_decrypting(s:&BigUint,message:&[u8]) ->Vec<u8>{

    let message_len = message.len();
    let (ciphertext, iv) = message.split_at(message_len - 16);



    let mut sha = Sha1::new();
    sha.update(&s.to_bytes_be());
    
    let key =sha.digest().bytes();
    let decrypted = cbc_decrypt(&key[0..16],&ciphertext,&iv );
    

    
    remove_padding(&decrypted)
}




pub struct SecureRemotePassword { // implementation of SRP 
    email:Vec<u8>,
    password:Vec<u8>,
    nist_prime: BigUint,
    public_key:BigUint,
    private_key: BigUint,
    common_key:BigUint,
    hash:BigUint,
    g: BigUint,
    k: BigUint,
    n: u32,//salt
}

impl SecureRemotePassword {
    pub fn new(n:BigUint ,g: BigUint, k: BigUint,email :&[u8],password:&[u8]) -> Self {
        Self {
            nist_prime:n ,
            g: g,
            k: k,
            email: email.to_vec(),
            password: password.to_vec(),
            private_key: BigUint::zero(),
            public_key:BigUint::zero(),
            hash:BigUint::zero(),
            common_key:BigUint::zero(),
            n: 0,
        }
    }
    pub fn generate_hash(&mut self){

        let mut rng = rand::thread_rng();
        // Generate a random integer between 1 and 100 (inclusive)
        let n: u32 = rng.r#gen();
        let n_bytes = n.to_be_bytes();
        let mut combined = Vec::with_capacity(4 + self.password.len());
        combined.extend_from_slice(&n_bytes);
        combined.extend_from_slice(&self.password);

        let x_h = sha256::digest(combined);
        let x = BigUint::parse_bytes(x_h.as_bytes(), 16).unwrap();
        self.hash = modular_exponentiation(&self.g,&x,&self.nist_prime);
        self.n = n 
    }
    pub fn generate_public_key(&mut self){
        let mut rng = rand::thread_rng();
        self.private_key = rng.gen_biguint_below(&self.nist_prime);

        self.public_key =(self.k.clone() * self.hash.clone()) + modular_exponentiation(&self.g, &self.private_key, &self.nist_prime);
    }
    pub fn generate_client_key(&mut self){
        let mut rng = rand::thread_rng();
        self.private_key = rng.gen_biguint_below(&self.nist_prime);

        self.public_key =modular_exponentiation(&self.g, &self.private_key, &self.nist_prime);
    }
    pub fn generate_public_shared_key(&mut self,key_1:BigUint,key_2 :BigUint){

        let key_2_bytes = key_2.to_be_bytes();
        let public_key_bytes = key_1.to_be_bytes();

        let mut combined = Vec::with_capacity(key_2_bytes.len() +public_key_bytes.len() );
        combined.extend_from_slice(&key_2_bytes);
        combined.extend_from_slice(&public_key_bytes);
        
        let u_h = sha256::digest(combined);
        let u = BigUint::parse_bytes(u_h.as_bytes(), 16).unwrap();
        self.common_key = u
    }



    pub fn send_auth_server(&self) -> (u32,BigUint) {
        (self.n.clone(),self.public_key.clone())
    }
    pub fn send_auth_client(&self) -> (Vec<u8>,BigUint) {
        (self.email.clone(),self.public_key.clone())
    }
    pub fn generate_shared_private_key_client(&self,salt:u32,key_server:BigUint)-> Vec<u8>{
        let n_bytes = salt.to_be_bytes();
        let mut combined = Vec::with_capacity(4 + self.password.len());
        combined.extend_from_slice(&n_bytes);
        combined.extend_from_slice(&self.password);

        let x_h = sha256::digest(combined);
        let x = BigUint::parse_bytes(x_h.as_bytes(), 16).unwrap();
        
        let shared_private_key = modular_exponentiation( &(key_server - self.k.clone() * self.g.modpow(&x,&self.nist_prime)), &(self.private_key.clone() + self.common_key.clone()*x), &self.nist_prime);
        
        let proof = sha256::digest(shared_private_key.to_bytes_be());

        let validator = hmac_sha256(proof.as_bytes(),&salt.to_be_bytes());
        validator
        //Generate S = (B - k * g**x)**(a + u * x) % N
    }
    
    pub fn generate_shared_private_key_server(&self,key_client:BigUint) -> Vec<u8>{
        //S = (A * v**u) ** b % N
    
        let hash_pow_u = self.hash.modpow(&self.common_key, &self.nist_prime);

    
        let product = key_client.clone() * hash_pow_u.clone();

    
        let exp = self.private_key.clone();

    
        let shared_private_key = modular_exponentiation(&product, &exp, &self.nist_prime);


        let proof = sha256::digest(shared_private_key.to_bytes_be());

        let validator = hmac_sha256(proof.as_bytes(),&self.n.to_be_bytes());
        validator
    }
    pub fn set_public_key(&mut self, new_key: BigUint) {
        self.public_key = new_key;
    }


}

pub fn hmac_sha256(key: &[u8], text: &[u8]) -> Vec<u8> {
    // Create HMAC instance
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");

    // Process input text
    mac.update(text);

    // Finalize and return raw bytes
    mac.finalize().into_bytes().to_vec()
}

pub fn sha256_bytes(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}


pub fn generate_keypair(bit_size: usize) -> ((BigInt, BigInt), (BigInt, BigInt)) {
    let e = BigInt::from(3);
    loop {
        let p = BigInt::from_bytes_be(num_bigint::Sign::Plus, &Generator::new_prime(bit_size).to_bytes_be());// two different implementation of bigint 
        let q = BigInt::from_bytes_be(num_bigint::Sign::Plus, &Generator::new_prime(bit_size).to_bytes_be());

        let n = &p * &q;
        let et = (&p - BigInt::one()) * (&q - BigInt::one());


        if bigint_gcd(e.clone(), et.clone()) == BigInt::one() {
            let d = mul_inv(e.clone(), et);

            let public_key = (e.clone(), n.clone());
            let private_key = (d, n);

        
            return (public_key, private_key)
        }
    }
}


/// Encrypt a message using RSA in 16-byte blocks, padding the final block if necessary
pub fn rsa_encrypt_blocks(message: &[u8], e: &BigInt, n: &BigInt) -> Vec<BigInt> {
    let mut ciphertext_blocks = Vec::new();

    for chunk in message.chunks(16) {
        let mut block = chunk.to_vec();
        if block.len() < 16 {
            block.resize(16, 0); // Pad with zeros
        }
        let cipher = rsa_encrypt(&block, e, n);
        ciphertext_blocks.push(cipher.to_bigint().unwrap());
    }

    ciphertext_blocks
}

/// Decrypt ciphertext blocks using RSA and remove padding from the final block
pub fn rsa_decrypt_blocks(cipher_blocks: &[BigInt], d: &BigInt, n: &BigInt) -> Vec<u8> {
    let mut message = Vec::new();

    for (i, cipher) in cipher_blocks.iter().enumerate() {
        let mut block = rsa_decrypt(cipher, d, n).to_bytes_be();
        if i == cipher_blocks.len() - 1 {
            while block.last() == Some(&0) && block.len() > 1 {
                block.pop(); // Remove padding from the last block
            }
        }
        message.extend_from_slice(&block);
    }

    message
}


/// Encrypt a message using RSA
pub fn rsa_encrypt(message: &[u8], e: &BigInt, n: &BigInt) -> BigInt {
    let m = BigUint::from_bytes_be(message);
    assert!(m < n.to_biguint().unwrap(), "Message must be smaller than modulus");
    modular_exponentiation(&m.to_biguint().unwrap(), &e.to_biguint().unwrap(), &n.to_biguint().unwrap()).to_bigint().unwrap()
}

/// Decrypt ciphertext using RSA
pub fn rsa_decrypt(ciphertext: &BigInt, d: &BigInt, n: &BigInt) -> BigUint {
    let decrypted = modular_exponentiation(&ciphertext.to_biguint().unwrap(), &d.to_biguint().unwrap(), &n.to_biguint().unwrap());
    decrypted
}





pub fn mul_inv(mut a:BigInt,mut b:BigInt)-> BigInt{//((a *x)%m =1)

    let  b0 = b.clone();
    let mut x0 = BigInt::zero() ;let mut x1=BigInt::one();
    while a>BigInt::one(){
        let  q = a.clone() / b.clone();
        let mut  t =b.clone();
        b = a % b;
        a = t;
        t = x0.clone().into();
        x0 =x1 -(q *x0); 
        x1 = t ;
    }
    if x1 < BigInt::zero(){ x1 += b0;}
    x1
}

fn bigint_gcd(mut a: BigInt, mut b: BigInt) -> BigInt {
    while !b.is_zero() {
        let temp = b.clone();
        b = a % &b;
        a = temp;
    }
    a 
}

pub fn integer_cube_root(n: &BigInt) -> BigInt {
    let mut low = BigInt::zero();
    let mut high = n.clone();
    
    while low < high {
        let mid = (&low + &high).shr(1); // mid = (low + high) / 2
        let mid_cubed = &mid * &mid * &mid;
        
        if mid_cubed == *n {
            return mid;
        } else if mid_cubed < *n {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    
    low - 1
}


pub fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let zero = BigInt::zero();
    let one = BigInt::one();

    let (mut t, mut new_t) = (zero.clone(), one.clone());
    let (mut r, mut new_r) = (m.to_bigint().unwrap(), a.to_bigint().unwrap().rem(m.to_bigint().unwrap()));

    while new_r != zero {
        let quotient = &r / &new_r;

        let temp_t = &t - &quotient * &new_t;
        let temp_r = &r - &quotient * &new_r;

        t = new_t;
        r = new_r;
        new_t = temp_t;
        new_r = temp_r;
    }

    if r != one {
        return None; // No inverse exists
    }

    if t < zero {
        t += m.to_bigint().unwrap();
    }

    t.to_biguint()
}


pub fn group_div(a: &BigUint, b: &BigUint, m: &BigUint) -> Option<BigUint> {
    if let Some(b_inv) = modinv(b, m) {
        Some((a * b_inv).rem(m))
    } else {
        None
    }
}


pub fn cube_residue_prefilter(n: &BigUint) -> bool {
    // cubes mod 9 are {0,1,8}
    let r9 = (n % &BigUint::from(9u32)).to_u32().unwrap();
    if r9 != 0 && r9 != 1 && r9 != 8 { return false; }

    // cubes mod 7 are {0,1,6}
    let r7 = (n% &BigUint::from(7u32)).to_u32().unwrap() ;
    if r7 != 0 && r7 != 1 && r7 != 6 { return false; }

    // cubes mod 13 are {0,1,5,8,12}
    let r13 = (n% &BigUint::from(13u32)).to_u32().unwrap();
    if !matches!(r13, 0 | 1 | 5 | 8 | 12) { return false; }
    true
}


pub fn cube_root_floor(n: &BigUint) -> BigUint {
    if n.is_zero() { return BigUint::zero(); }

    // initial approximation: 2^ceil(bits/3)
    let bits = n.bits(); // number of bits (num-bigint 0.4 has .bits())
    let approx_shift = (bits + 2) / 3;
    let mut x = BigUint::one() << approx_shift; // initial x = 2^(approx_shift)

    // Newton iteration: x_{k+1} = (2*x + n / x^2) / 3
    loop {
        // x2 = x^2
        let x2 = &x * &x;
        if x2.is_zero() { break; } // safety
        let n_div_x2 = n / &x2;
        let numerator = &x * 2u32 + n_div_x2;
        let x_next = &numerator / 3u32;

        // converged? x_next >= x -> done (floor)
        if x_next >= x {
            // ensure we return floor: maybe adjust downwards if (x)^3 > n
            let mut res = x;
            while &(&res * &res * &res) > n {
                res -= BigUint::one();
            }
            while &(&(&res + BigUint::one()) * &(&res + BigUint::one()) * &(&res + BigUint::one())) <= n {
                res += BigUint::one();
            }
            return res;
        }
        x = x_next;
    }

    x
}


pub fn is_perfect_cube(n: &BigUint) -> bool {
    if !cube_residue_prefilter(n) {
        println!("n having passed preliminary {}",n );
        return false;
    }

    let r = cube_root_floor(n);
    let r3 = &r * &r * &r;
    if &r3 == n {return true ;} else {return false;}

}