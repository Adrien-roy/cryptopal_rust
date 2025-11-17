use cryptopal_chalenge::*; 
use rand::Rng;
use std::panic::{catch_unwind, set_hook};
use std::collections::HashMap;
use urlencoding::encode;
use std::time::{UNIX_EPOCH,SystemTime,Duration};
use crate::rng::Mt19937;

use sha1::Sha1;

use num_bigint::{BigUint, RandBigInt, ToBigUint,ToBigInt};
use num_traits::{Zero, One,Signed,ToBytes};
use rand::thread_rng;
// format 1 string hexadecimal  vec<u8> use as.byte() to get hexadecimal 
// format 2 string base 64v string_to_base64()
// string = utf8 = 32 bit max 



//set 1

//chal_1


#[test]
fn set_1_challenge_01(){
    let a = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(convert_hexstring_to_base64string(a), b);
}


#[test]

fn bilateral_conversion(){

    let a ="49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b = convert_hexa_to_vec(&a);
    let c = convert_vec_to_hexa(&b);
    assert_eq!(a,c);
}


#[test]

fn set_1_challenge_02(){


let a = "1c0111001f010100061a024b53535009181c";
let b = "686974207468652062756c6c277320657965";
let c = "746865206b696420646f6e277420706c6179";

let a_hex =convert_hexa_to_vec(a);
let b_hex =convert_hexa_to_vec(b);
let c_hex =convert_hexa_to_vec(c);
println!("{:?}",a_hex);
println!("{:?}",b_hex);


assert_eq!(xor_two(&a_hex,&b_hex),c_hex)

}

#[test]

fn set_1_challenge_03(){

    let a="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let b="Cooking MC's like a pound of bacon";
    let a_hex =convert_hexa_to_vec(a);
    
    let result = xor_one_string(&a_hex);

    assert_eq!(vec_to_ascii(&result),b)

}


fn set_1_challenge_04(){//not interesting

//not interesting

}


#[test]

fn set_1_challenge_05(){

let a = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";
let key = "ICE";

let expected_result ="0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20690a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
let vec_expected_result = convert_hexa_to_vec(expected_result);



let key_vec = ascii_to_vec(key);
let message = ascii_to_vec(a);
let answer = encrypt_repeating_key(&message,&key_vec);
assert_eq!(answer,vec_expected_result);
}

#[test]

fn parity(){
let a = "this is a test";
let b = "wokka wokka!!!";

let a_vec = ascii_to_vec(a);
let b_vec = ascii_to_vec(b);
let dist = hamming_distance(&a_vec,&b_vec);
assert_eq!(dist,37);

}

#[test]
fn set_1_challenge_06(){
let expected_result =  read_file_to_string("criptopal_result_6.txt");
let base64_file = read_file_to_string("criptopal_challenge_6.txt");
let file = convert_hexa_to_vec(&convert_base64_to_hexstring(&base64_file));
let solved = Vigenere(&file,29);
let result = vec_to_ascii(&solved);
assert_eq!(result,expected_result)
}


#[test]
fn set_1_challenge_07(){
let key = b"YELLOW SUBMARINE"; // 16 bytes = AES-128

let b64_file = read_file_to_string("criptopal_challenge_7.txt");
let results = read_file_to_string("criptopal_result_7.txt");


let file = convert_hexa_to_vec(&convert_base64_to_hexstring(&b64_file));

let decrypted = aes_ecb_decrypt(key, &file);


assert_eq!(results,String::from_utf8_lossy(&remove_padding(&decrypted)));

}

fn set_1_challenge_08(){//not running as test because that would make no sense 

    let lines = read_file_lines("criptopal_challenge_8.txt");
    let mut vec_lines:Vec<Vec<u8>>= vec![];
    let mut groups: Vec<Vec<u8>> = vec![Vec::new(); 20]; //nb of 16 bit block per line

    let mut distance;
    let mut min_distance = 40000000;
    let mut hamming;
    let mut max_nb_of_repeat=0;

    for (_i,line) in lines.iter().enumerate(){
        vec_lines.push(convert_hexa_to_vec(&line));
    }
    for (i,line) in vec_lines.iter().enumerate(){

        for group in groups.iter_mut() {
            group.clear();
        }

        for (i, &byte) in line.iter().enumerate() {
            groups[i/16].push(byte);
        }

        distance = 0;
        let mut nb_of_repeated_block =0;
        for i in 2..= 19{
            for j in 1..= (i-1){
            hamming = hamming_distance(&groups[i],&groups[j]);
            if hamming == 0{
                nb_of_repeated_block += 1;
            }
            distance += hamming;
            }
        }
        if distance < min_distance{
            min_distance= distance;
        }
        if nb_of_repeated_block > max_nb_of_repeat{
            max_nb_of_repeat = nb_of_repeated_block;
        }
        
        println!("{}  {}  {}",i, min_distance , nb_of_repeated_block);// when looking at ouput we can say line 132 is encoded by ecb

    }


}

//set2 great

#[test]

fn ECB_check(){

    let key ="YELLOW SUBMARINE";
    let plaintext="
We all live in a yellow submarine
Yellow submarine, yellow submarine
We all live in a yellow submarine
Yellow submarine, yellow submarine
";

let key_vec = ascii_to_vec(key);
let mut plaintext_vec = ascii_to_vec(plaintext);
println!("{}",plaintext_vec.len());
plaintext_vec = padding(&plaintext_vec,144);
let cipher_text = aes_ecb_encrypt(&key_vec,&plaintext_vec);
let result = aes_ecb_decrypt(&key_vec,&cipher_text);

let asc_result = vec_to_ascii(&remove_padding(&result));
assert_eq!(plaintext,asc_result);


}


#[test]
fn set_2_challenge_09(){


    let a = "YELLOW SUBMARINE";
    let veca = ascii_to_vec(&a);
    let result =padding(&veca,20);
    let result_ascii = vec_to_ascii(&result);
    println!("{}",result_ascii);
    assert_eq!(result_ascii.len(),20);
}


#[test]
fn CBC_check(){

let key = "YELLOW SUBMARINE";
let text = "We all live in a yellow submarine
Yellow submarine, yellow submarine
We all live in a yellow submarine
Yellow submarine, yellow submarine
";

let iv = vec![0u8; 16];
let key_vec = ascii_to_vec(&key);
let text_vec = ascii_to_vec(&text);

let encripted = CBC_encrypt(&key_vec,&text_vec,&iv);

let original = remove_padding(&CBC_decrypt(&key_vec,&encripted,&iv));

assert_eq!(text ,vec_to_ascii(&original));
}


fn set_2_challenge_10(){


    let key = "YELLOW SUBMARINE";
    let key_vec = ascii_to_vec(key);
    let file_str = read_file_to_string("criptopal_challenge_10.txt");

    let file_vec = convert_hexa_to_vec(&convert_base64_to_hexstring(&file_str));
    let iv = vec![0u8; 16];

    let result =remove_padding(&CBC_decrypt(&key_vec,&file_vec,&iv));
    let stringoutput = vec_to_ascii(&result);
    let results = read_file_to_string("criptopal_result_7.txt");
    assert_eq!(results,stringoutput)//this is not an error the result is the same than for challenge 7
}

// not a test this would make no sense 
fn set_2_challenge_11(){

    let text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";// repeating key to guess encryption 

    let cleartext = ascii_to_vec(&text);



    let encripted_text = encrypt_random(&cleartext);
    let mut groups: Vec<Vec<u8>> = vec![Vec::new(); encripted_text.len()/16];
    let mut distance;
    let mut nb_of_repeated_block :i32;
    let mut hamming;


    for (i, &byte) in encripted_text.iter().enumerate() {
        groups[i/16].push(byte);
    }
    distance = 0;
    let mut nb_of_repeated_block =0;
    for i in 2..= (encripted_text.len()/16)-1{
        for j in 1..= (i-1){
        hamming = hamming_distance(&groups[i],&groups[j]);
        if hamming == 0{
            nb_of_repeated_block += 1;
        }
        distance += hamming;
        }
    }

    println!("{} {} ",nb_of_repeated_block, distance);


}
//#[test]
fn set_2_challenge_12(){ //this takes somewhat long maybe optimise i think some copy are necessary

    let mut buffer_guess_vec: [u8; 16] = *b"AAAAAAAAAAAAAAAA";
    let buffer_padding = "AAAAAAAAAAAAAAAA"   ;
    let mut buffer_padding_vec = ascii_to_vec(buffer_padding);

    let byte_index = 15;

    let decodable_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    let key ="YELLOW_SUBMARINE" ;// this is supposed to be unknown 
    let key_vec = ascii_to_vec(key);
    let decoded_vec = convert_hexa_to_vec(&convert_base64_to_hexstring(decodable_string));
    let mut last_found_val =0 ;
    let mut decoded_result_vec: Vec<u8> = Vec::new();

    for i in 0..=decodable_string.len(){
        fill_vec_to_length(&mut buffer_padding_vec,15 - i%16 ,65);

        iterate_byte_possibilities_inline(&mut buffer_guess_vec, byte_index, |vec, val| {
            let combined = pad_to_block_size(&combine_3_vec(&vec,&buffer_padding_vec,&decoded_vec),16); 
            let encrypted = aes_ecb_encrypt(&key_vec, &combined);
            if detect_repeating(&encrypted) >= 1 {
                    last_found_val = val;
                }
        });
        shift_left_and_append(&mut buffer_guess_vec,last_found_val);
        decoded_result_vec.push(last_found_val)

    }
    assert_eq!(vec_to_ascii(&convert_hexa_to_vec(&convert_base64_to_hexstring(decodable_string))),vec_to_ascii(&remove_trailing_ones(&decoded_result_vec)));

}
#[test]
fn set_2_challenge_13(){
let mut expected = HashMap::new();
expected.insert("uid".to_string(), "10".to_string());
expected.insert("email".to_string(), "leit%40bar.un".to_string());
expected.insert("role".to_string(), "admin".to_string());

let result = challenge13::challenge13();
assert_eq!(result,expected);


}

fn set_2_challenge_14(){
    //seem uninteresting just see how many byte short of 16 the attacking message is 
    // can be interesting if length of prepend is variable 
}
#[test]
fn set_3_challenge_15(){

    let text = b"ICE ICE BABY\x04\x04\x04\x04";
    let text2_vec=remove_padding(text);
    assert_eq!(vec_to_ascii(&text2_vec),"ICE ICE BABY");
    
    let text = b"ICE ICE BABY\x05\x05\x05\x05";

    let result = catch_unwind(|| {
        let text2_vec=remove_padding(text);
    });

    assert!(result.is_err());

    let text = b"ICE ICE BABY\x01\x02\x03\x04";

    let result = catch_unwind(|| {
        let text2_vec=remove_padding(text);
    });

    assert!(result.is_err());

}

#[test]
fn set_3_challenge_16(){

    let random_aes_key = generate_random_key();
    let iv = generate_random_key();
    let prepend = b"comment1=cooking%20MCs;userdata=";
    let append = b";comment2=%20like%20a%20pound%20of%20bacon";
    let user_input ="whatever12345678";//16 byte
    let sanitised_user_input = encode(user_input);
    let sanitised_user_input_vec = ascii_to_vec(&sanitised_user_input);
    let cleartext = combine_3_vec(prepend,&sanitised_user_input_vec,append);
    let mut cyphertext = CBC_encrypt(&random_aes_key,&pad_to_block_size(&cleartext,16),&iv);
    println!("{}",vec_to_ascii(&cyphertext));
    
    let wanted_inject =   b";admin=true;";
    let original_message =b";comment2=%2";
    
    
    let result_vec : Vec<u8>= xor_two(wanted_inject,original_message).try_into().expect("REASON");
    let xor_len = result_vec.len();
    
    let start_index = 32;
    for i in 0..xor_len {
        cyphertext[start_index + i] ^= result_vec[i];
    }
    
    let decripted = CBC_decrypt(&random_aes_key,&cyphertext,&iv);
    let is_admin = is_admin_tuple(&vec_to_ascii(&decripted));
    assert_eq!(true,is_admin)

}
#[test]
fn set_3_challenge_17(){


    set_hook(Box::new(|_| {}));
    let (full_ciphertext, iv) = client();

    let decrypted_message = decrypt_cbc_with_padding_attack(iv, &full_ciphertext);
    let decrypted_ascii = vec_to_ascii(&remove_padding(&decrypted_message));
    let expected = "000002Quick to the point, to the point, no faking";
    println!("Decrypted: {:?}", decrypted_ascii);
    println!("Expected : {:?}", expected);
    assert_eq!(decrypted_ascii,expected)
}

#[test]
fn set_3_challenge_18(){


    let message= b"Yo, VIP Let's kick  Ice, Ice, baby Ice, Ice, baby";
    let key:[u8;16] = *b"YELLOW SUBMARINE";

    let output = ctr_construct(key, message);

    let origin = ctr_construct(key, &output);


    assert_eq!(origin,message)
}

fn set_3_challenge_19(){// this is good enough ,scoring function is bad but whatever good POC 

    //a second pass technique would also be interesting ,like a valid word flag for each byte 
    //apparently i did the smart solution of problem 20 OH WELL
    //(also i padded instead of cutting whatever)

    let messages = read_file_lines("criptopal_challenge_19.txt");
    let key = *b"YELLOW_SUBMARINE";



    let mut vecs: Vec<Vec<u8>> = Vec::new();

    println!("{:?}",messages.len());
    for message in messages {
        let bytes = ctr_construct(key,&convert_base64_to_vec(&message));
        vecs.push(bytes);
    }


    let transposed = transpose_pad(&vecs);





    let key: Vec<u8> = transposed
    .iter()
    .map(|row| get_best_key(row))
    .collect();

    let results: Vec<Vec<u8>> = vecs
    .iter()
    .map(|line| xor_two(&key, line))
    .collect();

    for result in &results {
        println!("{}", vec_to_ascii(result));
    }




}
fn set_3_challenge_22(){

    let random;
    random = generate_random();
    let mut current_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards")
    .as_secs();
    let mut found = false;
    while !found {
        let mut rng = Mt19937::new(current_time as u32);
        rng.next_u32();
        if rng.next_u32() == random {
            println!("Seed found: {}", current_time);
            found = true;
        } else {
            current_time -= 1;
        }
    }
}

#[test]
fn set_3_challenge_23(){


    let seed = 5489; // any seed
    let mut original = Mt19937::new(seed);

    let mut clone = clone_mt19937(&mut original);

    for i in 0..1000 {
        assert_eq!(original.next_u32(), clone.next_u32());
    }

    println!("Cloning successful! Future outputs match.");

}

//#[test]
fn set_3_challenge_24(){
    let message = b"hvcasdvbadcjvbaschnaoAAAAAAAAAAAA";//random +32 A //53length 1 = 4 bit 
    let key = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards")
    .as_secs();


    let cypher = MT19937_construct(key.try_into().unwrap(),message);
    println!("{}",vec_to_ascii(&cypher));

    let len = cypher.len();
    let last_4_cypher =  last_full_u32(&cypher);
    let random_result = u32::from_le_bytes(xor_two(last_4_cypher,b"AAAA").try_into().unwrap()) ;
    let mut found = false;

    sleep_random_5_to_10_seconds();
    let mut  current_time = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards")
    .as_secs();


    let mut tested_seed =0;
    let mut found = false;
    while !found {
        let mut rng = Mt19937::new(current_time.try_into().unwrap());

        for _ in 0..(len/4)-1 {
            rng.next_u32();
        }
        tested_seed = rng.next_u32();
        if tested_seed == random_result{
            println!("Seed found: {}", current_time);
            found = true;
        } else {

            current_time -= 1;
        }
    }



    let decripted = MT19937_construct(current_time.try_into().unwrap(),&cypher);
    assert_eq!(vec_to_ascii(&decripted),vec_to_ascii(message));

}

#[test]
fn set_4_challenge_25() {

    let key = *b"YELLOW_SUBMARINE";
    let cleartext = read_file_to_string("criptopal_challenge_10.txt");

    let vec_original = convert_base64_to_vec(&cleartext);
    let zero_vec = vec![0u8; vec_original.len()];

    let encrypted = ctr_construct(key, &vec_original);


    let mut  stream = edit_atacker(&encrypted,key,0,&zero_vec);

    stream.truncate(vec_original.len());

    let decoded_vec = xor_two(&stream,&encrypted);

    assert_eq!(vec_to_ascii(&vec_original),vec_to_ascii(&decoded_vec))




}

fn edit_atacker(ciphertext: &[u8],key: [u8;16], offset: usize, newtext: &[u8]) -> Vec<u8>{

    let mut cleartext = ctr_construct(key, &ciphertext);

    cleartext.splice(offset..offset, newtext.iter().cloned());


    // Re-encrypt the modified cleartext
    let re_encrypted = ctr_construct(key, &cleartext);
    re_encrypted
}

#[test]
fn set_4_challenge_26(){

    let random_aes_key = generate_random_key();
    let iv = generate_random_key();
    let prepend = b"comment1=cooking%20MCs;userdata=";
    let append = b";comment2=%20like%20a%20pound%20of%20bacon";
    let user_input ="whatever12345678";//16 byte
    let sanitised_user_input = encode(user_input);
    let sanitised_user_input_vec = ascii_to_vec(&sanitised_user_input);
    let cleartext = combine_3_vec(prepend,&sanitised_user_input_vec,append);

    let mut cyphertext = ctr_construct(random_aes_key,&cleartext);


    
    let wanted_inject =   b";admin=true;";
    let original_message =b";comment2=%2";
    
    
    let result_vec : Vec<u8>= xor_two(wanted_inject,original_message).try_into().expect("REASON");
    let xor_len = result_vec.len();
    
    let start_index = 48;
    for i in 0..xor_len {
        cyphertext[start_index + i] ^= result_vec[i];
    }
    
    let decripted = ctr_construct(random_aes_key,&cyphertext);
    let is_admin = is_admin_tuple(&vec_to_ascii(&decripted));
    assert_eq!(is_admin,true)

}


fn check_for_error(encrypted: &[u8], key: &[u8]) -> Result<bool, Vec<u8>> {
    let message = CBC_decrypt(key, encrypted, key); 
    if message.iter().any(|&b| b > 127) {
        Err(message)
    } else {
        Ok(true) 
    }
}
#[test]
fn set_4_challenge_27(){

    let random_aes_key = generate_random_key();
    let iv = random_aes_key;



    let prepend = b"comment1=cooking";
    let append =  b";comment2=%20lik";
    let user_input ="whatever12345678";//16 byte

    let sanitised_user_input = encode(user_input);
    let sanitised_user_input_vec = ascii_to_vec(&sanitised_user_input);
    let cleartext = combine_3_vec(prepend,&sanitised_user_input_vec,append);
    let mut cyphertext = CBC_encrypt(&random_aes_key,&pad_to_block_size(&cleartext,16),&iv);
    //finish client 
    let first_block = &cyphertext[..16];
    let empty_vec = vec![0u8; 16];
    let corupted_message = combine_3_vec(first_block,&empty_vec,first_block);


    //oracle

    let guessed_iv = match check_for_error(&corupted_message, &random_aes_key) {
        Ok(_) => {
            println!("No error detected.");
            return; // exits the function early, or replace with `None`, etc.
        }
        Err(msg) => xor_two(&msg[..16], &msg[32..48]),
    };
    


    assert_eq!(iv,*guessed_iv);
}
#[test]
fn set_4_challenge_29(){
    let key = b"YELLOW SUBMARINE";
    let original = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    let glue_padding = sha1_padding(key.len()+original.len());
    let new_message= b";user=admin";
    
    let mut secret_message = Vec::new();
    secret_message.extend_from_slice(key);
    secret_message.extend_from_slice(original);

    let mut padded = Sha1::new();
    padded.update(&secret_message);
    println!("original : SHA-1 digest: {:?}",padded.digest().bytes() );
    let user_state = digest_to_state(&padded.digest().bytes());

    let mut sha1_state = Sha1::with_state(user_state,128 );// 2 64 block are occupied
    sha1_state.update(new_message);

    println!("forged : SHA-1 digest: {:?}",sha1_state.digest().bytes() );

    secret_message.extend_from_slice(&glue_padding);
    secret_message.extend_from_slice(new_message);

    let mut padded2 = Sha1::new();
    padded2.update(&secret_message);
    

    println!("SHA-1 digest expected : {:?}",padded2.digest().bytes() );

    assert_eq!(padded2.digest().bytes(),sha1_state.digest().bytes())
}


//fn set_4_challenge_31(){//doesn't workthe implementation of MD4 is a pain to modify //pading may be wrong
//
//
//    let key = b"YELLOW SUBMARINE";
//    let original = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
//    let glue_padding = sha1_padding(key.len()+original.len());
//    let new_message= b";user=admin";
//    
//    let mut secret_message = Vec::new();
//    secret_message.extend_from_slice(key);
//    secret_message.extend_from_slice(original);
//
//    let mut padded = Md4::new();
//    padded.update(&secret_message);
//    let result = padded.finalize();
//    println!("original : SHA-1 digest: {:?}",result );
//    
//    let user_state =digest_md4_to_state(&result.as_slice().try_into().unwrap());
//    let custom_block_len = 0;
//    
//    let md4 = Md4Core::init(user_state,0);
//    let mut hasher = CoreWrapper::from_core(md4);
//
//
//    hasher.update(new_message);
//    let result = hasher.finalize();
//    println!("original : SHA-1 digest: {:?}",result );
//
//
//    secret_message.extend_from_slice(&glue_padding);
//    secret_message.extend_from_slice(new_message);
//
//    let mut padded2 = Md4::new();
//    padded2.update(&secret_message);
//    let result = padded2.finalize();
//    println!("original : SHA-1 digest: {:?}",result );

    //let mut sha1_state = Sha1::with_state(user_state,128 );// 2 64 block are occupied
    //sha1_state.update(new_message);
//
    //println!("forged : SHA-1 digest: {:?}",sha1_state.digest().bytes() );
//
    //secret_message.extend_from_slice(&glue_padding);
    //secret_message.extend_from_slice(new_message);
//
    //let mut padded2 = Sha1::new();
    //padded2.update(&secret_message);
    //
//
    //println!("SHA-1 digest expected : {:?}",padded2.digest().bytes() );
//
    //assert_eq!(padded2.digest().bytes(),sha1_state.digest().bytes())
//}

fn digest_md4_to_state(digest: &[u8; 16]) -> [u32; 4] {
    let mut state = [0u32; 4];
    for (i, chunk) in digest.chunks(4).enumerate() {
        state[i] = (chunk[0] as u32)
            | ((chunk[1] as u32) << 8)
            | ((chunk[2] as u32) << 16)
            | ((chunk[3] as u32) << 24);
    }
    state
}


fn sha1_padding(original_message_len: usize) -> Vec<u8> {
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

#[test]
fn set_5_challenge_32() {
    // Hex prime modulus string (no newlines inside)
    let hex_string = "\
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";

    let p = BigUint::parse_bytes(hex_string.as_bytes(), 16).expect("Invalid hex string");
    let g = 5u32.to_biguint().unwrap();

    let mut rng = thread_rng();


    let a = rng.gen_biguint_below(&p);
    let b = rng.gen_biguint_below(&p);


    let A = modular_exponentiation(&g, &a, &p);
    let B = modular_exponentiation(&g, &b, &p);


    let s = modular_exponentiation(&B, &a, &p);
    let s2 = modular_exponentiation(&A, &b, &p);

    println!("Shared secret s  = {}", s);
    println!("Shared secret s2 = {}", s2);
    assert_eq!(s, s2);  // They should be equal
}
fn set_5_challenge_33(){
let hex_string = "\
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";

    let p = BigUint::parse_bytes(hex_string.as_bytes(), 16).unwrap();
    let g = 5u32.to_biguint().unwrap();
    let mut M = Participant::new(&p, &g);
    M.set_shared_key(0.to_biguint().unwrap());

    // Create participants A and B
    let mut A = Participant::new(&p, &g);
    let (p_sent, g_sent, A_pub_sent) = A.export_public();

    // A "sends" p, g, A_pub to B
    println!("--- A sends p, g, A_pub ---");


    // B receives p, g, and M false key
    let mut B = Participant::new(&p_sent, &g_sent);
    B.receive_public(p_sent.clone(), g_sent.clone(), p_sent.clone());

    // B sends its public key to A
    let B_pub_sent = B.export_public_key();
    println!("--- B sends B_pub ---");

    // A receives M false key
    A.receive_public_key(p_sent.clone());

    // A sends message to B
    let message_from_A = b"hello world";
    println!("A sends: {}", vec_to_ascii(message_from_A));
    let encrypted_A = A.encrypt_message(message_from_A);

    println!("attacker saw : {}",vec_to_ascii(&M.decrypt_message(&encrypted_A)));

    // B receives message from A
    let decrypted_A = B.decrypt_message(&encrypted_A);
    println!("B received: {}", vec_to_ascii(&decrypted_A));

    // B sends reply to A
    let message_from_B = b"world answer";
    println!("B sends: {}", vec_to_ascii(message_from_B));
    let encrypted_B = B.encrypt_message(message_from_B);


    println!("attacker saw : {}",vec_to_ascii(&M.decrypt_message(&encrypted_B)));
    // A receives message from B
    let decrypted_B = A.decrypt_message(&encrypted_B);
    println!("A received: {}", vec_to_ascii(&decrypted_B));
}



fn set_5_challenge_34(){

    let hex_string = "\
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";

    let p = BigUint::parse_bytes(hex_string.as_bytes(), 16).unwrap();
    let g = &p ;//1.to_biguint().unwrap();//5u32.to_biguint().unwrap();
    let mut M = Participant::new(&p, &g);
    M.set_shared_key(0.to_biguint().unwrap());


    //g = 1 //key become 1
    //g = p // key become 0
    //g = p - 1 // key become 1
    // Create participants A and B
    let mut A = Participant::new(&p, &g);
    let (p_sent, g_sent, A_pub_sent) = A.export_public();

    // A "sends" p, g, A_pub to B
    println!("--- A sends p, g, A_pub ---");


    // B receives p, g, and M false key
    let mut B = Participant::new(&p_sent, &g_sent);

    B.receive_public(p_sent.clone(), g_sent.clone(),A_pub_sent);

    // B sends its public key to A
    let B_pub_sent = B.export_public_key();
    println!("--- B sends B_pub ---");


    A.receive_public_key(B_pub_sent);

    // A sends message to B
    let message_from_A = b"hello world let it be";
    println!("A sends: {}", vec_to_ascii(message_from_A));
    let encrypted_A = A.encrypt_message(message_from_A);

    println!("attacker saw : {}",vec_to_ascii(&M.decrypt_message(&encrypted_A)));

    // B receives message from A
    let decrypted_A = B.decrypt_message(&encrypted_A);
    println!("B received: {}", vec_to_ascii(&decrypted_A));

    // B sends reply to A
    let message_from_B = b"world answer";
    println!("B sends: {}", vec_to_ascii(message_from_B));
    let encrypted_B = B.encrypt_message(message_from_B);


    println!("attacker saw : {}",vec_to_ascii(&M.decrypt_message(&encrypted_B)));
    // A receives message from B
    let decrypted_B = A.decrypt_message(&encrypted_B);
    println!("A received: {}", vec_to_ascii(&decrypted_B));
}


#[test]
fn set_5_challenge_35(){ // ignored the hmac sha256 because not relevant for our breaking(also just forgot )

    let hex_string = "\
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";

    let n = BigUint::parse_bytes(hex_string.as_bytes(), 16).unwrap();
    let g = 2.to_biguint().unwrap();
    let k = 3.to_biguint().unwrap();
    let email = b"something_original@thing";
    let password =b"YELLOW_SUBMARINE";
    let input = b"hello";


    let mut S = secure_remote_password::new(n.clone(),g.clone(),k.clone(),email,password);
    S.generate_hash();



    let mut C = secure_remote_password::new(n.clone(),g.clone(),k.clone(),email,password);

    C.generate_client_key();
    let (email,public_key_C) = C.send_auth_client();
    // C.set_public_key (BigUint::one());
    // c sends I and public_key 

    S.generate_public_key();
    let (salt,public_key_S) = S.send_auth_server();





    S.generate_public_shared_key(public_key_S.clone(),public_key_C.clone());
    C.generate_public_shared_key(public_key_S.clone(),public_key_C.clone());

    let output1 = C.generate_shared_private_key_client(salt , public_key_S);
    let output2 = S.generate_shared_private_key_server(public_key_C);
    println!("{:?} \n{:?}",output1,output2);

    assert_eq!(output1,output2);
}

fn set_5_challenge_37(){

    let hex_string = "\
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
fffffffffffff";

    let n = BigUint::parse_bytes(hex_string.as_bytes(), 16).unwrap();
    let g = 2.to_biguint().unwrap();
    let k = 3.to_biguint().unwrap();
    let email = b"something_original@thing";
    let password =b"YELLOW_SUBMARINE";
    let input = b"hello";


    let mut S = secure_remote_password::new(n.clone(),g.clone(),k.clone(),email,password);
    S.generate_hash();



    let mut C = secure_remote_password::new(n.clone(),g.clone(),k.clone(),email,password);

    C.generate_client_key();
    let (email,mut public_key_C) = C.send_auth_client();
    C.set_public_key (BigUint::zero());
    let (email,mut public_key_C) = C.send_auth_client();
    // c sends I and public_key 

    S.generate_public_key();
    let (salt,public_key_S) = S.send_auth_server();


    S.generate_public_shared_key(public_key_S.clone(),public_key_C.clone());
    C.generate_public_shared_key(public_key_S.clone(),public_key_C.clone());

    let output1 =sha256::digest(BigUint::zero().to_bytes_be());
    let output2 = S.generate_shared_private_key_server(public_key_C);//083026d9af916f6cef9497f33a5f6652f5c62bc53c5780b6e675579a003896cc
    println!("{:?} \n{:?}",output1,output2);

    assert_eq!(ascii_to_vec(&output1),output2);
}
#[test]
fn set_5_challenge_39() {
    let (public_key, private_key) = generate_keypair(128);
    let (e, n) = public_key;
    let (d, _) = private_key;

    let message = b"hello world this is a longer message";


    let ciphertext_blocks = rsa_encrypt_blocks(message, &e, &n);


    let decrypted_bytes = rsa_decrypt_blocks(&ciphertext_blocks, &d, &n);
    let recovered = String::from_utf8(decrypted_bytes).expect("Invalid UTF-8");

    assert_eq!( vec_to_ascii(message),recovered);
}


#[test]
fn set_5_challenge_40() {
    let (public_key, private_key) = generate_keypair(128);
    let (e1, n1) = public_key;
    let (public_key, private_key) = generate_keypair(128);
    let (e2, n2) = public_key;
    let (public_key, private_key) = generate_keypair(128);
    let (e3, n3) = public_key;

    let message = b"I love javascrip";


    let ciphertext_blocks_1 = rsa_encrypt(message, &e1, &n1);
    let ciphertext_blocks_2 = rsa_encrypt(message, &e2, &n2);
    let ciphertext_blocks_3 = rsa_encrypt(message, &e3, &n3);



    let result = (ciphertext_blocks_1 * &n2*&n3 *mul_inv( &n2*&n3 , n1.clone())+
    ciphertext_blocks_2 * &n1*&n3 * mul_inv( &n1*&n3 , n2.clone()) +
    ciphertext_blocks_3 * &n1*&n2 * mul_inv( &n1*&n2 , n3.clone()) )% (&n1*&n2*&n3);

    let decrypted_bytes = integer_cube_root(&result).to_bytes_be();
    assert_eq!(message, &*decrypted_bytes.1);
}

#[test]
fn set_6_challenge_41() {

    let text = b"{
        time:1356304276,
        social:'555-55-5555',
    }
    ";
    let (public_key, private_key) = generate_keypair(300);
    let (e, n) = public_key;
    let (p ,_) = private_key;
    
    let mut rng = thread_rng();
    let S = rng.gen_bigint(200).abs() % n.clone() ;//stupid i know but it's for the principle  
    
    
    let ciphertext = rsa_encrypt(text,&e,&n);
    
    let base = modular_exponentiation(&S.to_biguint().unwrap(),&e.to_biguint().unwrap(),&n.to_biguint().unwrap());
    
    let ciphertext2 = (&base.to_bigint().unwrap() * &ciphertext ) % &n;
    let decript2 = rsa_decrypt(&ciphertext2.to_bigint().unwrap(),&p,&n);
    let result = group_div(&decript2,&S.to_biguint().unwrap(),&n.to_biguint().unwrap());
    
    println!("{:?}",vec_to_ascii(&result.expect("REASON").to_be_bytes()));
    }
    
    

fn set_6_challenge42() { // this is unfinished need to find a better way of doing the bruteforce attack on the padding 

    // this is actually the implementation of another type of attack but it is way worste 
    let text = b"useless information";
    let (public_key, private_key) = generate_keypair(512);
    let (e, n) = public_key;
    let (p ,_) = private_key;


    let byte_length = n.to_bytes_be().1.len();
    println!("n is {} bytes long", byte_length);

    let padding_len = byte_length - 3 - text.len();


    let ps_len = 4;
    let forged_text =b"hello_mom; it is nice to meet you please ignore the rest of this message it is really important ";
    let total = 1u128 << (8 * ps_len);


    // p0 is the trailing zeros to fill the block
    let mut p0 = vec![0x00; byte_length - 3 - ps_len - forged_text.len()];
    let mut ps = vec![0x00; 4];
    let mut forged = Vec::new();
    forged.push(0x00);
    forged.push(0x02);
    forged.extend_from_slice(&ps);
    forged.push(0x00);
    forged.extend_from_slice(forged_text);
    forged.append(&mut p0);

    println!("{:?}",vec_to_ascii(&forged));
    let biguintforged = BigUint::from_bytes_be(&forged);


    let cypher_forged = cube_root_floor(&biguintforged) ;//- BigUint::from(256u32);


    println!("cubed {}",vec_to_ascii(&(BigUint::to_be_bytes(&(&cypher_forged * &cypher_forged* &cypher_forged)) )));

    //let difference = &cypher_forged - &biguintforged;


    let unsigned = modular_exponentiation(&cypher_forged.to_biguint().unwrap(),&e.to_biguint().unwrap(),&n.to_biguint().unwrap());

    let mut result_bytes = BigUint::to_be_bytes(&unsigned);
    if result_bytes.len() < byte_length {
        let mut padded = vec![0u8; byte_length - result_bytes.len()];
        padded.extend(result_bytes);
        result_bytes = padded;
    }
    println!("{:?}",result_bytes);
    println!("{:?}",vec_to_ascii(&result_bytes))
}
    