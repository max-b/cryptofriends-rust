use std::fs::File;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;
use std::str;
use std::u8;
use utils::bytes::*;
use utils::crypto::ecb_decrypt;
use utils::files::read_base64_file_as_bytes;
use utils::misc::*;

pub fn detect_single_char_xor() -> String {
    let mut strings_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    strings_path.push("data");
    strings_path.push("set_1");
    strings_path.push("4.txt");

    let strings_file = File::open(&strings_path).expect("Error reading strings file.");

    let strings_file_as_reader = BufReader::new(strings_file);

    let mut best_score = None;
    let mut best_decoded = String::from("");

    for line in strings_file_as_reader.lines() {
        if let Ok((decoded, score, _)) = word_scorer_string(&line.expect("error reading line")) {
            if let Some(best) = best_score {
                if score < best {
                    best_score = Some(score);
                    best_decoded = decoded;
                }
            } else {
                best_score = Some(score);
                best_decoded = decoded;
            }
        }
    }

    match best_score {
        None => panic!("Word scorer wasn't able to find a single valid xored string"),
        Some(_) => best_decoded,
    }
}

pub fn challenge_6() -> String {
    let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ciphertext_path.push("data");
    ciphertext_path.push("set_1");
    ciphertext_path.push("6.txt");

    let base64_decoded_ciphertext = read_base64_file_as_bytes(&ciphertext_path);

    match break_repeating_xor(&base64_decoded_ciphertext) {
        Ok(result) => result,
        Err(err) => panic!("Couldn't break repeating xor: {}", err),
    }
}

pub fn break_repeating_xor(ciphertext: &[u8]) -> Result<String, Error> {
    let keysize = find_keysize(ciphertext).unwrap();

    let mut transposed: Vec<Vec<u8>> = vec![vec![]; keysize];
    for slice in ciphertext.chunks(keysize) {
        if slice.len() == keysize {
            for i in 0..slice.len() {
                let item = slice[i];
                transposed[i].push(item);
            }
        }
    }

    let mut key_vector: Vec<u8> = Vec::new();

    for block in transposed {
        if let Ok((_, _, key)) = word_scorer_bytes(&block[..]) {
            key_vector.push(key);
        } else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Can't run word_scorer on this block",
            ));
        }
    }

    let decrypted_buf = repeating_key_xor(&ciphertext, &key_vector[..]);

    let decrypted_string =
        &str::from_utf8(&decrypted_buf).expect("Error converting decrypted buffer to string");

    Ok(decrypted_string.to_string())
}

pub fn aes_ecb() -> String {
    let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    ciphertext_path.push("data");
    ciphertext_path.push("set_1");
    ciphertext_path.push("7.txt");

    let base64_decoded_ciphertext = read_base64_file_as_bytes(&ciphertext_path);

    let key = b"YELLOW SUBMARINE";

    let decrypted = ecb_decrypt(key, &base64_decoded_ciphertext);

    let decrypted = str::from_utf8(&decrypted).expect("Error converting decrypted bytes to string");

    decrypted[..].to_string()
}

pub fn detect_aes_ecb() -> Option<String> {
    let mut strings_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    strings_path.push("data");
    strings_path.push("set_1");
    strings_path.push("8.txt");

    let strings_file = File::open(&strings_path).expect("Error reading strings file.");

    let strings_file_as_reader = BufReader::new(strings_file);

    for line in strings_file_as_reader.lines() {
        let line = line.unwrap();
        let line_bytes = hex_to_bytes(&line[..]);

        let mut blocks: Vec<&[u8]> = Vec::with_capacity(line_bytes.len() / 16);

        for block in line_bytes.chunks(16) {
            {
                let mut iter = blocks.iter_mut();

                if iter.any(|&mut x| block == x) {
                    return Some(line);
                }
            }

            blocks.push(block)
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::crypto::ecb_encrypt;

    struct Setup {
        decryption_answer: String,
    }

    impl Setup {
        fn new() -> Self {
            let answer = String::from(
                "I'm back and I'm ringin' the bell
A rockin' on the mike while the fly girls yell
In ecstasy in the back of me
Well that's my DJ Deshay cuttin' all them Z's
Hittin' hard and the girlies goin' crazy
Vanilla's on the mike, man I'm not lazy.

I'm lettin' my drug kick in
It controls my mouth and I begin
To just let it flow, let my concepts go
My posse's to the side yellin', Go Vanilla Go!

Smooth 'cause that's the way I will be
And if you don't give a damn, then
Why you starin' at me
So get off 'cause I control the stage
There's no dissin' allowed
I'm in my own phase
The girlies sa y they love me and that is ok
And I can dance better than any kid n' play

Stage 2 -- Yea the one ya' wanna listen to
It's off my head so let the beat play through
So I can funk it up and make it sound good
1-2-3 Yo -- Knock on some wood
For good luck, I like my rhymes atrocious
Supercalafragilisticexpialidocious
I'm an effect and that you can bet
I can take a fly girl and make her wet.

I'm like Samson -- Samson to Delilah
There's no denyin', You can try to hang
But you'll keep tryin' to get my style
Over and over, practice makes perfect
But not if you're a loafer.

You'll get nowhere, no place, no time, no girls
Soon -- Oh my God, homebody, you probably eat
Spaghetti with a spoon! Come on and say it!

VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino
Intoxicating so you stagger like a wino
So punks stop trying and girl stop cryin'
Vanilla Ice is sellin' and you people are buyin'
'Cause why the freaks are jockin' like Crazy Glue
Movin' and groovin' trying to sing along
All through the ghetto groovin' this here song
Now you're amazed by the VIP posse.

Steppin' so hard like a German Nazi
Startled by the bases hittin' ground
There's no trippin' on mine, I'm just gettin' down
Sparkamatic, I'm hangin' tight like a fanatic
You trapped me once and I thought that
You might have it
So step down and lend me your ear
'89 in my time! You, '90 is my year.

You're weakenin' fast, YO! and I can tell it
Your body's gettin' hot, so, so I can smell it
So don't be mad and don't be sad
'Cause the lyrics belong to ICE, You can call me Dad
You're pitchin' a fit, so step back and endure
Let the witch doctor, Ice, do the dance to cure
So come up close and don't be square
You wanna battle me -- Anytime, anywhere

You thought that I was weak, Boy, you're dead wrong
So come on, everybody and sing this song

Say -- Play that funky music Say, go white boy, go white boy go
play that funky music Go white boy, go white boy, go
Lay down and boogie and play that funky music till you die.

Play that funky music Come on, Come on, let me hear
Play that funky music white boy you say it, say it
Play that funky music A little louder now
Play that funky music, white boy Come on, Come on, Come on
Play that funky music",
            ).replace("\n", "")
            .replace(" ", "");

            Self {
                decryption_answer: answer,
            }
        }
    }

    #[test]
    fn challenge_1() {
        let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let base64_encoded = hex_to_base64(hex);
        let answer_bytes = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(base64_encoded, answer_bytes);
    }

    #[test]
    fn challenge_2() {
        let hex1 = "1c0111001f010100061a024b53535009181c";
        let hex2 = "686974207468652062756c6c277320657965";
        let xor_result = xor_hex_strings(hex1, hex2);
        let answer_bytes = "746865206b696420646f6e277420706c6179";
        assert_eq!(xor_result, answer_bytes);
    }

    #[test]
    fn challenge_3() {
        let hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let (decode_result, _, _) = word_scorer_string(hex).unwrap();
        let decoded_answer = "Cooking MC's like a pound of bacon";
        assert_eq!(decode_result, decoded_answer);
    }

    #[test]
    fn challenge_4() {
        let xored_decrypt = detect_single_char_xor();
        let decoded_answer = "Now that the party is jumping\n";
        assert_eq!(xored_decrypt, decoded_answer);
    }

    #[test]
    fn challenge_5() {
        let plaintext =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let repeated_xor_bytes =
            repeating_key_xor(&(plaintext.as_bytes()), &(String::from("ICE").as_bytes()));
        let repeated_xor_string = bytes_to_hex(&repeated_xor_bytes);
        let encrypted_answer = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(repeated_xor_string, encrypted_answer);
    }

    #[test]
    fn challenge_6() {
        let setup = Setup::new();

        let decoded = super::challenge_6().replace("\n", "").replace(" ", "");

        assert_eq!(decoded, setup.decryption_answer);
    }

    #[test]
    fn challenge_7() {
        let setup = Setup::new();

        let decrypted = aes_ecb().replace("\n", "").replace(" ", "");

        assert_eq!(decrypted, setup.decryption_answer);
    }

    #[test]
    fn ecb_encrypt_valid() {
        let mut ciphertext_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        ciphertext_path.push("data");
        ciphertext_path.push("set_1");
        ciphertext_path.push("7.txt");

        let base64_decoded_ciphertext: Vec<u8> = read_base64_file_as_bytes(&ciphertext_path);

        let key = b"YELLOW SUBMARINE";

        let decrypted: Vec<u8> = ecb_decrypt(key, &base64_decoded_ciphertext);

        let encrypted: Vec<u8> = ecb_encrypt(key, &decrypted[..]);

        assert_eq!(&encrypted[..], &base64_decoded_ciphertext[..]);
    }

    #[test]
    fn challenge_8() {
        let aes_ecb_answer = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a";

        match detect_aes_ecb() {
            Some(string) => assert_eq!(string, aes_ecb_answer),
            None => panic!("No aes ecb string found."),
        }
    }
}
