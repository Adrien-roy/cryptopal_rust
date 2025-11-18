#![allow(unused_imports)]


use std::collections::HashMap;
use cryptopal_chalenge::*;
use num_bigint::{BigInt,BigUint, RandBigInt, ToBigUint,ToBigInt,Sign};
use num_traits::{Zero, One,ToBytes,Signed,ToPrimitive};
use rand::thread_rng;
use sha2::{Sha256};
pub mod sha1;
use crate::sha1::Sha1;
use num_primes::Generator;
use std::ops::{Shr, Add, Sub, Mul,Rem};

//T         1  octet
//Q        20  octets    // is a prime 
//P        64 + T*8  octets
//G        64 + T*8  octets
//Y        64 + T*8  octets


fn main() {

    let t = 8;
    let q_hex = "f4f47f05794b256174bba6e9b396a7707e563c5b";
    let g_hex = "5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119\
    458fef538b8fa4046c8db53039db620c094c9fa077ef389b5\
    322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047\
    0f5b64c36b625a097f1651fe775323556fe00b3608c887892\
    878480e99041be601a62166ca6894bdd41a7054ec89f756ba\
    9fc95302291";
    let p_hex = "800000000000000089e1855218a0e7dac38136ffafa72eda7\
    859f2171e25e65eac698c1702578b07dc2a1076da241c76c6\
    2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe\
    ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2\
    b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87\
    1a584471bb1";

    let x_hex = "a4f9a8fda812ab59494232c7d2";// private key 

    let pubkey_hex = "84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17";
    let q = BigUint::parse_bytes(q_hex.as_bytes(), 16).unwrap();
    let g = BigUint::parse_bytes(g_hex.as_bytes(), 16).unwrap();
    let p = BigUint::parse_bytes(p_hex.as_bytes(), 16).unwrap();
    let x = BigUint::parse_bytes(x_hex.as_bytes(), 16).unwrap();
    
    let pubkey = BigUint::parse_bytes(pubkey_hex.as_bytes(), 16).unwrap();
    let mut k = modular_exponentiation(&g,&x ,&p);// k public key x private key 


    println!("{}",x);

    let data = b"For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
";

    let mut padded = Sha1::new();
    padded.update(data);
    let result = &padded.digest();
    let expected = "d2d0714f014a9784047eaeccf956520045c45265";
    assert_eq!(expected,result.to_string());
//
    //let sig = dsa_sign(data, &g, &k, &p, &q, &x).expect("sign failed");
    //let (r, s) = sig;
    //println!("signature r={}, s={}", r, s);
//
    //// verify
    //let ok = dsa_verify(data, &g, &p, &q, &k, &r, &s);
    //println!("signature valid? {}", ok);


    k = pubkey;
    let r = BigUint::parse_bytes(b"548099063082341131477253921760299949438196259240", 10).unwrap();
    let s = BigUint::parse_bytes(b"857042759984254168557880549501802188789837994940", 10).unwrap();
    println!("{} {}",r,s);
    let private_key = recover_private_key(data ,&k,&q ,&r,&s);
    assert_eq!(private_key,x);

}

pub fn recover_private_key(data : &[u8],k: &BigUint,q: &BigUint ,r: &BigUint,s: &BigUint) -> BigUint{

    let mut padded = Sha1::new();
    padded.update(&data);
    let h = BigUint::from_bytes_be(
        &digest_to_state(&padded.digest().bytes())
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect::<Vec<u8>>()
    );

    let numerator = ((s * k) -h)% q ;
    let r_inv = modinv(r,q).unwrap();

    let private_key = (r_inv * numerator) % q;
    private_key
}


pub fn dsa_sign(
    data: &[u8],
    g: &BigUint,
    k: &BigUint,
    p: &BigUint,
    q: &BigUint,
    x: &BigUint, // private key
) -> Option<(BigUint, BigUint)> {

    let r = modular_exponentiation(&g, &k,&p)%q;
    if r.is_zero() {
        return None;
    }

    let k_inv = modinv(k, q);
    let mut padded = Sha1::new();
    padded.update(&data);
    let h = BigUint::from_bytes_be(
        &digest_to_state(&padded.digest().bytes())
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect::<Vec<u8>>()
    );


    let xr = (x * &r) % q;
    let hr = (&h + xr) % q;
    let s = (k_inv.as_ref().unwrap() * hr) % q;

    if s.is_zero() {
        return None;
    }

    Some((r, s))
}

// DSA verify: returns true if signature valid
pub fn dsa_verify(
    data: &[u8],
    g: &BigUint,
    p: &BigUint,
    q: &BigUint,
    y: &BigUint, // public key (g^x mod p)
    r: &BigUint,
    s: &BigUint,
) -> bool {
    // check 0 < r < q and 0 < s < q
    if r.is_zero() || s.is_zero() || r >= q || s >= q {
        return false;
    }

    // w = s^{-1} mod q
    let w = match modinv(s, q) {
        Some(w) => w,
        None => return false,
    };

    let mut padded = Sha1::new();
    padded.update(&data);
    let h = BigUint::from_bytes_be(
        &digest_to_state(&padded.digest().bytes())
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect::<Vec<u8>>()
    );

    // u1 = (H * w) mod q
    // u2 = (r * w) mod q
    let u1 = (&h * &w) % q;
    let u2 = (r * &w) % q;

    // v = ((g^u1 * y^u2) mod p) mod q
    let gu1 = g.modpow(&u1, p);
    let yu2 = y.modpow(&u2, p);
    let v = (&gu1 * &yu2) % p % q;

    &v == r
}



fn reverse_modular_exponantiation(expected: &BigUint,g: &BigUint,p : &BigUint) -> BigUint{
    let total = u16::MAX ;
    let mut x :BigUint = BigUint::zero();
    for x in 0..=total {
        println!("{}",x);
        let k = modular_exponentiation(&g,&x.to_biguint().expect("REASON") ,&p);
        if k == *expected{
            return x.to_biguint().expect("REASON");
        }
    }
    return x.to_biguint().expect("REASON");
}