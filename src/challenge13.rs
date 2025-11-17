
use crate::HashMap;
use crate::*;
pub fn challenge13() -> HashMap<String, String> {


    let admin_block = get_admin_block();
    let mut role_block = get_role_separated();
    for i in 0..16 {
    role_block[32 + i] = admin_block[i+16];
    }

    let role = decode_user_profile(&role_block);
    role
}

fn get_admin_block()-> Vec<u8>{

    let email= make_admin_email_string();
    let encoded = create_encoded_user_profile(&email);
    encoded
}



fn make_admin_email_string() -> String {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"0123456789admin"); 
    //bytes.extend(std::iter::repeat(0x0b).take(11));                            
    String::from_utf8_lossy(&bytes).to_string()
}


fn get_role_separated() -> Vec<u8>{
    let email = "leit@bar.un"; 
    let encoded = create_encoded_user_profile(email);
    encoded
}

fn working_normally(){

    let email = "foo@bar.com";
    let encoded = create_encoded_user_profile(&email);
    let server_profile = decode_user_profile(&encoded);
    println!("{:?}",server_profile)

}


fn create_encoded_user_profile( email: &str)-> Vec<u8>{

    let key :[u8; 16] = *b"YELLOW_SUBMARINE";
    let profile_str = profile_for(&email);
    let mut profile_vec = ascii_to_vec(&profile_str);
    profile_vec = pad_to_block_size(&profile_vec,16);

    let encrypted_vec = aes_ecb_encrypt(&key,&profile_vec);
    
    encrypted_vec
}

fn decode_user_profile(encrypted_vec : &[u8]) -> HashMap<String, String>{

    let key : [u8; 16] = *b"YELLOW_SUBMARINE";
    let profile_vec = aes_ecb_decrypt(&key,&encrypted_vec);
    let profile_str = vec_to_ascii((&profile_vec));
    
    parse_kv_string(&profile_str)
}