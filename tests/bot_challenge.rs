use bearust::bot_challenge::{ChallengeService, VerifyError, DIFFICULTY};
use sha2::{Digest, Sha256};

fn solution(token: &str) -> String {
    let nonce = token.split('.').nth(1).unwrap();
    for i in 0..1_000_000u32 { let s=i.to_string(); let mut h=Sha256::new(); h.update(nonce.as_bytes()); h.update(s.as_bytes()); if hex::encode(h.finalize()).starts_with(&"0".repeat(DIFFICULTY as usize)){ return s; } }
    panic!("pow")
}
#[tokio::test]
async fn issuance_and_valid_solution_are_one_time() {
 let s=ChallengeService::from_key(b"test-key".to_vec()).unwrap(); let c=s.issue_challenge("abcdef0123456789",100).await.unwrap(); assert_eq!(c.fingerprint_prefix,"abcdef0123456789"); let p=solution(&c.token); assert!(s.verify_solution(&c.token,"abcdef0123456789",&p,101).await.is_ok()); assert_eq!(s.verify_solution(&c.token,"abcdef0123456789",&p,101).await,Err(VerifyError::Replay));
}
#[tokio::test]
async fn rejects_tamper_expiry_and_wrong_fingerprint() {
 let s=ChallengeService::from_key(b"test-key".to_vec()).unwrap(); let c=s.issue_challenge("abcdef",100).await.unwrap(); let p=solution(&c.token); assert_eq!(s.verify_solution(&(c.token.clone()+"x"),"abcdef",&p,101).await,Err(VerifyError::Invalid)); assert_eq!(s.verify_solution(&c.token,"abcdef",&p,401).await,Err(VerifyError::Expired)); let c=s.issue_challenge("abcdef",100).await.unwrap(); assert_eq!(s.verify_solution(&c.token,"zzz",&solution(&c.token),101).await,Err(VerifyError::FingerprintMismatch));
}
#[tokio::test]
async fn caps_attempts() {
 let s=ChallengeService::from_key(b"test-key".to_vec()).unwrap(); let c=s.issue_challenge("abcdef",100).await.unwrap(); for _ in 0..5 { assert_eq!(s.verify_solution(&c.token,"abcdef","bad",101).await,Err(VerifyError::Invalid)); } assert_eq!(s.verify_solution(&c.token,"abcdef","bad",101).await,Err(VerifyError::AttemptsExceeded));
}
