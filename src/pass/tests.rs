use super::{
    std_default, std_nist, Algorithm, HashBuilder, LengthCalculationMethod, Normalization,
    PasswordStorageStandard, DEFAULT_USER_VERSION, INTERNAL_VERSION, XHMAC,
};
use crate::hash::HashFunction;

#[cfg(feature = "stderror")]
#[test]
fn test_stderror() {
    let err = super::Error::PasswordTooLong {
        max: 128,
        actual: 1024,
    };
    assert_eq!(
        err.to_string(),
        "Password was longer than the maximal length (actual 1024, max 128)"
    );
}

#[test]
fn test_default_hashbuilder() {
    let hb = HashBuilder::new();
    assert_eq!(hb.min_len, std_default::DEFAULT_PASSWORD_MIN_LEN);
    assert_eq!(hb.max_len, std_default::DEFAULT_PASSWORD_MAX_LEN);
    assert_eq!(hb.version, DEFAULT_USER_VERSION + INTERNAL_VERSION);
    assert_eq!(hb.ref_salt, None);
    assert_eq!(hb.ref_hash, None);
    assert_eq!(hb.xhmac, XHMAC::None);
    match hb.standard {
        PasswordStorageStandard::NoStandard => assert!(true),
        _ => assert!(false),
    }
    match hb.normalization {
        Normalization::Nfkc => assert!(true),
        _ => assert!(false),
    }
    match hb.algorithm {
        Algorithm::Argon2 => assert!(true),
        _ => assert!(false),
    }
}

#[test]
fn test_nist_hashbuilder() {
    let hb = HashBuilder::new_std(PasswordStorageStandard::Nist80063b);
    assert_eq!(hb.min_len, std_nist::DEFAULT_PASSWORD_MIN_LEN);
    assert_eq!(hb.max_len, std_nist::DEFAULT_PASSWORD_MAX_LEN);
    assert_eq!(hb.version, DEFAULT_USER_VERSION + INTERNAL_VERSION);
    assert_eq!(hb.ref_salt, None);
    assert_eq!(hb.ref_hash, None);
    assert_eq!(hb.xhmac, XHMAC::None);
    match hb.length_calculation {
        std_nist::DEFAULT_LENGTH_CALCULATION => assert!(true),
        _ => assert!(false),
    };
    match hb.standard {
        PasswordStorageStandard::Nist80063b => assert!(true),
        _ => assert!(false),
    }
    match hb.normalization {
        Normalization::Nfkc => assert!(true),
        _ => assert!(false),
    }
    match hb.algorithm {
        Algorithm::Pbkdf2 => assert!(true),
        _ => assert!(false),
    }
}

#[test]
fn test_params() {
    let mut b = HashBuilder::new_std(PasswordStorageStandard::Nist80063b);
    let hb = b
        .min_len(42)
        .max_len(256)
        .version(5)
        .length_calculation(LengthCalculationMethod::Characters)
        .normalization(Normalization::Nfkd)
        .algorithm(Algorithm::Pbkdf2)
        .add_param("iter", "80000")
        .add_param("hmac", "sha512t256");
    assert_eq!(hb.min_len, 42);
    assert_eq!(hb.max_len, 256);
    assert_eq!(hb.ref_salt, None);
    assert_eq!(hb.ref_hash, None);
    assert_eq!(hb.version, 5 + INTERNAL_VERSION);
    assert_eq!(hb.xhmac, XHMAC::None);
    match hb.length_calculation {
        LengthCalculationMethod::Characters => assert!(true),
        _ => assert!(false),
    };
    match hb.standard {
        PasswordStorageStandard::Nist80063b => assert!(true),
        _ => assert!(false),
    }
    match hb.normalization {
        Normalization::Nfkd => assert!(true),
        _ => assert!(false),
    }
    match hb.algorithm {
        Algorithm::Pbkdf2 => assert!(true),
        _ => assert!(false),
    }
    match hb.parameters.get("hmac") {
        Some(h) => match h.as_str() {
            "sha512t256" => assert!(true),
            v => assert!(false, "{} invalid hmac parameter value", v),
        },
        None => assert!(false, "hmac: parameter not found"),
    }
    match hb.parameters.get("iter") {
        Some(i) => match i.as_str() {
            "80000" => assert!(true),
            v => assert!(false, "{} invalid iter parameter value", v),
        },
        None => assert!(false, "iter: parameter not found"),
    }
}

#[test]
fn test_default_version() {
    let data = "$argon2$passes=3,len-calc=chars,lanes=4,mem=12,pmax=128,len=128,pmin=8,norm=nfkc$F3rmE8Z867gmmeJJ+LfJJQ$/VuD5U8nEqLR+j87PH0b1uBvri2Zu5O+C6juhFZ8BYbjt5ZLuhQz91uMEqyvzMaKtJCeoMpWwi4xvXbYGomdlQw3ETqq6tA4UKiT5cjcmwm4yLwm6S5H/b04XcxIAbvhLfthIq6IRX1YRWQyVce8TVpz4McI40dbruE/7r9EwhM";
    let c = HashBuilder::from_phc(data).unwrap();
    assert_eq!(c.version, DEFAULT_USER_VERSION + INTERNAL_VERSION);
    assert!(!c.needs_update(None));
}

#[test]
fn test_version() {
    let data = "$argon2$passes=3,len-calc=chars,lanes=4,mem=12,pmax=128,len=128,pmin=8,ver=5,norm=nfkc$F3rmE8Z867gmmeJJ+LfJJQ$/VuD5U8nEqLR+j87PH0b1uBvri2Zu5O+C6juhFZ8BYbjt5ZLuhQz91uMEqyvzMaKtJCeoMpWwi4xvXbYGomdlQw3ETqq6tA4UKiT5cjcmwm4yLwm6S5H/b04XcxIAbvhLfthIq6IRX1YRWQyVce8TVpz4McI40dbruE/7r9EwhM";
    let c = HashBuilder::from_phc(data).unwrap();
    assert_eq!(c.version, 4 + INTERNAL_VERSION);
    assert!(c.needs_update(Some(42)));
    assert!(c.needs_update(Some(5)));
    assert!(!c.needs_update(Some(4)));
    assert!(!c.needs_update(Some(3)));
    assert!(!c.needs_update(Some(1)));
    assert!(!c.needs_update(Some(0)));
    assert!(!c.needs_update(None));
}

#[test]
fn test_phc_params() {
    let password = "correct horse battery staple";
    let reference = "$argon2$lanes=4,mem=12,len=128,len-calc=chars,pmax=42,pmin=10,passes=3,norm=nfkc$DHoZJMA/bttSBYs6s4yySw$pojoDCKFKD6E0NGjfpM5pZjaRklmo3ZkIiW//kxKQ09eookzRtJGQbeEeT207IT8LzWnlAnq4yJO8tgVm1K44DrzLesy0VCOPwf0SBvr1QFlmpv2g8X80hlEMI6vSGTP7gJdjMGMztnO0OKbFuS/r5DVOiUp+KeSwvLBhr8thqY";
    let checker = HashBuilder::from_phc(reference).unwrap();

    assert!(checker.is_valid(password));
    assert_eq!(checker.min_len, 10);
    assert_eq!(checker.max_len, 42);
}

#[test]
fn test_nfkc() {
    let s1 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 97,
    ])
    .unwrap(); // "test nfkd ä P  ̈a"
    let s2 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 98,
    ])
    .unwrap();
    let s3 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 97,
    ])
    .unwrap(); // "test nfkd ä P  ̈a"
    let s4 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 98,
    ])
    .unwrap();
    let hasher = HashBuilder::new()
        .normalization(Normalization::Nfkc)
        .finalize()
        .unwrap();
    let stored_password = hasher.hash(&s1).unwrap();
    let checker = HashBuilder::from_phc(stored_password.as_str()).unwrap();
    assert!(checker.is_valid(&s1));
    assert!(!checker.is_valid(&s2));
    assert!(checker.is_valid(&s3));
    assert!(!checker.is_valid(&s4));
}

#[test]
fn test_nfkd() {
    let s1 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 97,
    ])
    .unwrap(); // "test nfkd ä P  ̈a"
    let s2 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 98,
    ])
    .unwrap();
    let s3 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 97,
    ])
    .unwrap(); // "test nfkd ä P  ̈a"
    let s4 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 98,
    ])
    .unwrap();
    let hasher = HashBuilder::new()
        .normalization(Normalization::Nfkd)
        .finalize()
        .unwrap();
    let stored_password = hasher.hash(&s1).unwrap();
    let checker = HashBuilder::from_phc(stored_password.as_str()).unwrap();
    assert!(checker.is_valid(&s1));
    assert!(!checker.is_valid(&s2));
    assert!(checker.is_valid(&s3));
    assert!(!checker.is_valid(&s4));
}

#[test]
fn test_no_normalize() {
    let s1 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 97,
    ])
    .unwrap(); // "test nfkd ä P  ̈a"
    let s2 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 195, 164, 32, 80, 32, 32, 204, 136, 98,
    ])
    .unwrap();
    let s3 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 97,
    ])
    .unwrap(); // "test nfkd ä P  ̈a"
    let s4 = String::from_utf8(vec![
        116, 101, 115, 116, 32, 110, 102, 107, 100, 32, 97, 204, 136, 32, 80, 32, 32, 204, 136, 98,
    ])
    .unwrap();
    let hasher = HashBuilder::new()
        .normalization(Normalization::None)
        .finalize()
        .unwrap();
    let stored_password = hasher.hash(&s1).unwrap();
    let checker = HashBuilder::from_phc(stored_password.as_str()).unwrap();
    assert!(checker.is_valid(&s1));
    assert!(!checker.is_valid(&s2));
    assert!(!checker.is_valid(&s3));
    assert!(!checker.is_valid(&s4));
}

#[test]
#[should_panic]
fn test_nist_invalid_min_len() {
    HashBuilder::new_std(PasswordStorageStandard::Nist80063b)
        .min_len(7)
        .finalize()
        .unwrap();
}

#[test]
#[should_panic]
fn test_nist_invalid_max_len() {
    HashBuilder::new_std(PasswordStorageStandard::Nist80063b)
        .max_len(63)
        .finalize()
        .unwrap();
}

#[test]
#[should_panic]
fn test_nist_invalid_len_calc() {
    HashBuilder::new_std(PasswordStorageStandard::Nist80063b)
        .length_calculation(LengthCalculationMethod::Bytes)
        .finalize()
        .unwrap();
}

#[test]
#[should_panic]
fn test_nist_invalid_normalization_nfc() {
    HashBuilder::new_std(PasswordStorageStandard::Nist80063b)
        .normalization(Normalization::Nfc)
        .finalize()
        .unwrap();
}

#[test]
#[should_panic]
fn test_nist_invalid_normalization_nfd() {
    HashBuilder::new_std(PasswordStorageStandard::Nist80063b)
        .normalization(Normalization::Nfd)
        .finalize()
        .unwrap();
}

#[test]
#[should_panic]
fn test_nist_invalid_algorithm() {
    HashBuilder::new_std(PasswordStorageStandard::Nist80063b)
        .algorithm(Algorithm::Argon2)
        .finalize()
        .unwrap();
}

#[test]
#[should_panic]
fn test_nist_invalid_salt_len() {
    HashBuilder::new_std(PasswordStorageStandard::Nist80063b)
        .salt_len(3)
        .finalize()
        .unwrap();
}

#[test]
#[should_panic]
fn test_nist_invalid_iter() {
    HashBuilder::new_std(PasswordStorageStandard::Nist80063b)
        .algorithm(Algorithm::Pbkdf2)
        .add_param("iter", "8000")
        .finalize()
        .unwrap();
}

#[test]
fn test_xhmac_none() {
    let password = "correct horse battery staple";
    let hasher = HashBuilder::new().finalize().unwrap();
    let hpass = hasher.hash(password).unwrap();
    let checker = HashBuilder::from_phc(hpass.as_str()).unwrap();
    assert!(checker.is_valid(password));
    assert!(hpass.contains("xhmac=none"));
}

#[test]
fn test_xhmac_before() {
    let password = "correct horse battery staple";
    let extra_salt = b"somesalt";
    let hasher = HashBuilder::new()
        .xhmac(HashFunction::Sha384)
        .xhmac_before(extra_salt)
        .finalize()
        .unwrap();
    let hpass = hasher.hash(password).unwrap();
    let checker = HashBuilder::from_phc_xhmac(hpass.as_str(), extra_salt).unwrap();
    assert!(checker.is_valid(password));
    assert!(hpass.contains("xhmac=before"));
    assert!(hpass.contains("xhmac-alg=sha384"));
}

#[test]
fn test_xhmac_after() {
    let password = "correct horse battery staple";
    let extra_salt = b"somesalt";
    let hasher = HashBuilder::new()
        .xhmac(HashFunction::Sha384)
        .xhmac_after(extra_salt)
        .finalize()
        .unwrap();
    let hpass = hasher.hash(password).unwrap();
    let checker = HashBuilder::from_phc_xhmac(hpass.as_str(), extra_salt).unwrap();
    assert!(checker.is_valid(password));
    assert!(hpass.contains("xhmac=after"));
    assert!(hpass.contains("xhmac-alg=sha384"));
}

#[test]
#[should_panic]
fn test_xhmac_no_salt_check() {
    let password = "correct horse battery staple";
    let extra_salt = b"somesalt";
    let hasher = HashBuilder::new()
        .xhmac(HashFunction::Sha384)
        .xhmac_after(extra_salt)
        .finalize()
        .unwrap();
    let hpass = hasher.hash(password).unwrap();
    let checker = HashBuilder::from_phc(hpass.as_str()).unwrap();
    assert!(!checker.is_valid(password));
}

#[test]
#[should_panic]
fn test_xhmac_no_salt_create() {
    let password = "correct horse battery staple";
    let extra_salt = b"somesalt";
    let hasher = HashBuilder::new().finalize().unwrap();
    let hpass = hasher.hash(password).unwrap();
    let checker = HashBuilder::from_phc_xhmac(hpass.as_str(), extra_salt).unwrap();
    assert!(!checker.is_valid(password));
}
