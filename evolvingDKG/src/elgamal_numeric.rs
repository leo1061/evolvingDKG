use num_bigint::{BigInt, RandBigInt};
use num_traits::{Zero, One};
use rand::thread_rng;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalPublicKey {
    pub p: BigInt,  // Prime modulus
    pub g: BigInt,  // Generator
    pub y: BigInt,  // Public key (g^x mod p)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalPrivateKey {
    pub p: BigInt,  // Prime modulus
    pub g: BigInt,  // Generator
    pub y: BigInt,  // Public key (g^x mod p)
    pub x: BigInt,  // Private key
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ElGamalCiphertext {
    pub c1: BigInt,  // g^k mod p
    pub c2: BigInt,  // m * y^k mod p
}

impl ElGamalPublicKey {
    pub fn new(p: BigInt, g: BigInt, y: BigInt) -> Self {
        Self { p, g, y }
    }

    /// Encrypt a message using the public key with a specified k value
    pub fn encrypt_with_k(&self, message: &BigInt, k: &BigInt) -> ElGamalCiphertext {
        // c1 = g^k mod p
        let c1 = self.g.modpow(k, &self.p);
        
        // c2 = m * y^k mod p
        let y_k = self.y.modpow(k, &self.p);
        let c2 = (message * y_k) % &self.p;
        
        ElGamalCiphertext { c1, c2 }
    }

    /// Encrypt a message using the public key with a random k
    pub fn encrypt(&self, message: &BigInt) -> ElGamalCiphertext {
        let mut rng = thread_rng();
        // Generate random k in range [1, p-2]
        let k = rng.gen_bigint_range(&BigInt::one(), &(&self.p - 1));
        self.encrypt_with_k(message, &k)
    }
}

impl ElGamalPrivateKey {
    pub fn new(p: BigInt, g: BigInt, y: BigInt, x: BigInt) -> Self {
        Self { p, g, y, x }
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> ElGamalPublicKey {
        ElGamalPublicKey {
            p: self.p.clone(),
            g: self.g.clone(),
            y: self.y.clone(),
        }
    }

    /// Decrypt a ciphertext using the private key
    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> BigInt {
        // Calculate c1^x mod p
        let c1_x = ciphertext.c1.modpow(&self.x, &self.p);
        
        // Calculate modular inverse of c1^x mod p
        let c1_x_inv = mod_inverse(&c1_x, &self.p).expect("Modular inverse should exist");
        
        // m = c2 * (c1^x)^(-1) mod p
        (&ciphertext.c2 * c1_x_inv) % &self.p
    }

    /// Encrypt a message using the private key's public part with specified k
    pub fn encrypt_with_k(&self, message: &BigInt, k: &BigInt) -> ElGamalCiphertext {
        self.public_key().encrypt_with_k(message, k)
    }

    /// Encrypt a message using the private key's public part with random k
    pub fn encrypt(&self, message: &BigInt) -> ElGamalCiphertext {
        self.public_key().encrypt(message)
    }
}

/// Calculate modular inverse using extended Euclidean algorithm
fn mod_inverse(a: &BigInt, m: &BigInt) -> Option<BigInt> {
    fn extended_gcd(a: BigInt, b: BigInt) -> (BigInt, BigInt, BigInt) {
        if a == BigInt::zero() {
            (b, BigInt::zero(), BigInt::one())
        } else {
            let (g, y, x) = extended_gcd(&b % &a, a.clone());
            (g, x - (&b / &a) * &y, y)
        }
    }

    let (g, x, _) = extended_gcd(a.clone(), m.clone());
    if g != BigInt::one() {
        None // Modular inverse doesn't exist
    } else {
        Some(((x % m) + m) % m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[derive(Deserialize)]
    struct TestVector {
        vector_number: u32,
        description: String,
        message: String,
        k: u64,
        ciphertext: TestCiphertext,
        decrypted: String,
        success: bool,
    }

    #[derive(Deserialize)]
    struct TestCiphertext {
        c1: String,
        c2: String,
    }

    #[derive(Deserialize)]
    struct KeyParameters {
        p: String,
        g: String,
        y: String,
        x: String,
        key_size_bits: u32,
    }

    #[derive(Deserialize)]
    struct TestVectorFile {
        key_parameters: KeyParameters,
        test_vectors: Vec<TestVector>,
    }

    fn load_test_vectors() -> TestVectorFile {
        let test_data = r#"{
  "key_parameters": {
    "p": "11377013425765373585527479526440310619783424543116198075850940498445736597867029505213419454942264627982955395183548978841192094023275482113064601528253067",
    "g": "2275501910717178856412583893483747162403109438656666659799455805982355206535967432302852663645569480747259362308057560906439771229027138614777254613506949",
    "y": "10772617222387863946958187470043757155898323144451774489570668767135058108630986193799225604767745202810125346990540730704329694729743612216346637929421275",
    "x": "11210647390901718653197845823883958151379529283139770459625719402411999296816435504208241145620265133248694454922458601228395433140780698108633704275670172",
    "key_size_bits": 512
  },
  "test_vectors": [
    {
      "vector_number": 1,
      "description": "Minimal message",
      "message": "1",
      "k": 124,
      "ciphertext": {
        "c1": "9777549642447552092649141610126293859222602442854331799232942021089155038562490345557897627216414936332024378755064504844823290677466262242084320905887401",
        "c2": "7747577313020015401067022152064306952793914105066006453920192180327927146773175573896657264898715430982905534437776709899518071470591628635072881465915335"
      },
      "decrypted": "1",
      "success": true
    },
    {
      "vector_number": 2,
      "description": "Small integer",
      "message": "42",
      "k": 124,
      "ciphertext": {
        "c1": "9777549642447552092649141610126293859222602442854331799232942021089155038562490345557897627216414936332024378755064504844823290677466262242084320905887401",
        "c2": "6841871225410186450045503646372194663408505205518724940821737617292315424196547957683860387362638517759281381247250408226380369113134903507252178777358194"
      },
      "decrypted": "42",
      "success": true
    },
    {
      "vector_number": 3,
      "description": "One byte max",
      "message": "255",
      "k": 124,
      "ciphertext": {
        "c1": "9777549642447552092649141610126293859222602442854331799232942021089155038562490345557897627216414936332024378755064504844823290677466262242084320905887401",
        "c2": "7408892162694296975836690702224535739915650832729378627436299752508990996163666941726036844160654259589627914879087684850875958974206896383408709420629834"
      },
      "decrypted": "255",
      "success": true
    },
    {
      "vector_number": 4,
      "description": "Half of modulus",
      "message": "5688506712882686792763739763220155309891712271558099037925470249222868298933514752606709727471132313991477697591774489420596047011637741056532300764126533",
      "k": 124,
      "ciphertext": {
        "c1": "9777549642447552092649141610126293859222602442854331799232942021089155038562490345557897627216414936332024378755064504844823290677466262242084320905887401",
        "c2": "1814718056372679092230228687188001833494755219025095810965374159058904725546926965658381095021774598500024930372886134470837011276341926738995860031168866"
      },
      "decrypted": "5688506712882686792763739763220155309891712271558099037925470249222868298933514752606709727471132313991477697591774489420596047011637741056532300764126533",
      "success": true
    },
    {
      "vector_number": 5,
      "description": "Near maximum",
      "message": "11377013425765373585527479526440310619783424543116198075850940498445736597867029505213419454942264627982955395183548978841192094023275482113064601528253065",
      "k": 124,
      "ciphertext": {
        "c1": "9777549642447552092649141610126293859222602442854331799232942021089155038562490345557897627216414936332024378755064504844823290677466262242084320905887401",
        "c2": "7258872225490716368920914748752007333979020876100383243861496636235618902187707862633524380087098394000099721491544537883348045105367706955983440124675464"
      },
      "decrypted": "11377013425765373585527479526440310619783424543116198075850940498445736597867029505213419454942264627982955395183548978841192094023275482113064601528253065",
      "success": true
    }
  ]
}"#;
        serde_json::from_str(test_data).expect("Failed to parse test data")
    }

    #[test]
    fn test_key_creation() {
        let test_data = load_test_vectors();
        let params = &test_data.key_parameters;
        
        let p = BigInt::from_str(&params.p).unwrap();
        let g = BigInt::from_str(&params.g).unwrap();
        let y = BigInt::from_str(&params.y).unwrap();
        let x = BigInt::from_str(&params.x).unwrap();
        
        let private_key = ElGamalPrivateKey::new(p.clone(), g.clone(), y.clone(), x);
        let public_key = private_key.public_key();
        
        assert_eq!(public_key.p, p);
        assert_eq!(public_key.g, g);
        assert_eq!(public_key.y, y);
    }

    #[test]
    fn test_encryption_decryption_with_test_vectors() {
        let test_data = load_test_vectors();
        let params = &test_data.key_parameters;
        
        let p = BigInt::from_str(&params.p).unwrap();
        let g = BigInt::from_str(&params.g).unwrap();
        let y = BigInt::from_str(&params.y).unwrap();
        let x = BigInt::from_str(&params.x).unwrap();
        
        let private_key = ElGamalPrivateKey::new(p, g, y, x);
        
        for test_vector in &test_data.test_vectors {
            println!("Testing vector {}: {}", test_vector.vector_number, test_vector.description);
            
            let message = BigInt::from_str(&test_vector.message).unwrap();
            let k = BigInt::from(test_vector.k);
            
            // Test encryption with known k
            let ciphertext = private_key.encrypt_with_k(&message, &k);
            
            let expected_c1 = BigInt::from_str(&test_vector.ciphertext.c1).unwrap();
            let expected_c2 = BigInt::from_str(&test_vector.ciphertext.c2).unwrap();
            
            assert_eq!(ciphertext.c1, expected_c1, "c1 mismatch for vector {}", test_vector.vector_number);
            assert_eq!(ciphertext.c2, expected_c2, "c2 mismatch for vector {}", test_vector.vector_number);
            
            // Test decryption
            let decrypted = private_key.decrypt(&ciphertext);
            let expected_decrypted = BigInt::from_str(&test_vector.decrypted).unwrap();
            
            assert_eq!(decrypted, expected_decrypted, "Decryption mismatch for vector {}", test_vector.vector_number);
            assert_eq!(decrypted, message, "Decrypted message doesn't match original for vector {}", test_vector.vector_number);
        }
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let test_data = load_test_vectors();
        let params = &test_data.key_parameters;
        
        let p = BigInt::from_str(&params.p).unwrap();
        let g = BigInt::from_str(&params.g).unwrap();
        let y = BigInt::from_str(&params.y).unwrap();
        let x = BigInt::from_str(&params.x).unwrap();
        
        let private_key = ElGamalPrivateKey::new(p, g, y, x);
        
        // Test with various messages
        let test_messages = vec![
            BigInt::from(1),
            BigInt::from(42),
            BigInt::from(255),
            BigInt::from(65536),
            BigInt::from_str("123456789012345678901234567890").unwrap(),
        ];
        
        for message in test_messages {
            let ciphertext = private_key.encrypt(&message);
            let decrypted = private_key.decrypt(&ciphertext);
            assert_eq!(message, decrypted, "Roundtrip failed for message: {}", message);
        }
    }

    #[test]
    fn test_public_key_encryption() {
        let test_data = load_test_vectors();
        let params = &test_data.key_parameters;
        
        let p = BigInt::from_str(&params.p).unwrap();
        let g = BigInt::from_str(&params.g).unwrap();
        let y = BigInt::from_str(&params.y).unwrap();
        let x = BigInt::from_str(&params.x).unwrap();
        
        let private_key = ElGamalPrivateKey::new(p, g, y, x);
        let public_key = private_key.public_key();
        
        let message = BigInt::from(12345);
        let k = BigInt::from(124);
        
        // Encrypt with public key
        let ciphertext = public_key.encrypt_with_k(&message, &k);
        
        // Decrypt with private key
        let decrypted = private_key.decrypt(&ciphertext);
        
        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_modular_inverse() {
        // Test with known values
        let a = BigInt::from(3);
        let m = BigInt::from(11);
        let inv = mod_inverse(&a, &m).unwrap();
        assert_eq!((&a * &inv) % &m, BigInt::from(1));
        
        // Test with no inverse (gcd != 1)
        let a = BigInt::from(6);
        let m = BigInt::from(9);
        assert!(mod_inverse(&a, &m).is_none());
    }
}

// Add to Cargo.toml:
/*
[dependencies]
num-bigint = { version = "0.4", features = ["rand"] }
num-traits = "0.2"
rand = "0.8"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
*/