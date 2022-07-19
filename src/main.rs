/*
 * Copyright 2021 Fluence Labs Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::convert::TryInto;

use ecvrf::{keygen, prove, verify, VrfPk, VrfProof, VrfSk};
//  https://docs.rs/ecvrf/0.4.3/src/ecvrf/lib.rs.html#32
use marine_rs_sdk::{marine, module_manifest, WasmLoggerBuilder};

module_manifest!();

pub fn main() {
    WasmLoggerBuilder::new().build().unwrap();
}

#[marine]
pub struct ProofResult {
    pub pk: Vec<u8>,
    pub proof: Vec<u8>,
    pub output: Vec<u8>,
    pub stderr: String,
}
#[marine]
pub struct VerificationResult {
    pub verified: bool,
    pub stderr: String,
}

#[marine]
fn vrf_proof(payload: Vec<u8>) -> ProofResult {
    let (sk, pk) = keygen();
    let (output, proof) = prove(&payload, &sk);
    ProofResult {
        pk: pk.to_bytes().to_vec(),
        proof: proof.to_bytes().to_vec(),
        output: output.to_vec(),
        stderr: "".to_string(),
    }
}

#[marine]
fn verify_vrf(
    pk: Vec<u8>,
    payload: Vec<u8>,
    output: Vec<u8>,
    proof: Vec<u8>,
) -> VerificationResult {
    let mut error: &str;

    let b_pk = match pk[..].try_into() {
        Ok(r) => match VrfPk::from_bytes(r) {
            Ok(r) => r,
            Err(e) => {
                return VerificationResult {
                    verified: false,
                    stderr: format!("pk from bytes error: {}", e),
                };
            }
        },
        Err(e) => {
            return VerificationResult {
                verified: false,
                stderr: format!("pk error: {}", e),
            };
        }
    };

    let b_output: [u8; 32] = match output[..].try_into() {
        Ok(r) => r,
        Err(e) => {
            return VerificationResult {
                verified: false,
                stderr: format!("output error: {}", e),
            }
        }
    };

    let b_proof: [u8; 96] = match proof[..].try_into() {
        Ok(r) => r,
        Err(e) => {
            return VerificationResult {
                verified: false,
                stderr: format!("proof error: {}", e),
            }
        }
    };

    let proof_from_bytes = match VrfProof::from_bytes(&b_proof) {
        Ok(r) => r,
        Err(e) => {
            return VerificationResult {
                verified: false,
                stderr: format!("proof error: {}", e),
            };
        }
    };

    let verified = verify(&payload, &b_pk, &b_output, &proof_from_bytes);

    VerificationResult {
        verified,
        stderr: "".to_string(),
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
    use marine_rs_sdk_test::marine_test;

    /*
    #[test]
    fn test_proof_code() {
        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        let result: ProofResult = vrf_proof(payload.clone());

        assert_eq!(result.pk.len(), 32);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.proof.len(), 96);
    }
    */
    #[marine_test(config_path = "../configs/Config.toml", modules_dir = "../artifacts")]
    fn test_proof_module(vrfun: marine_test_env::vrfun::ModuleInterface) {
        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        let result = vrfun.vrf_proof(payload.clone());

        assert_eq!(result.pk.len(), 32);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.proof.len(), 96);
    }

    #[marine_test(config_path = "../configs/Config.toml", modules_dir = "../artifacts")]
    fn verify_proof_module(vrfun: marine_test_env::vrfun::ModuleInterface) {
        let payload = vec![0xde, 0xad, 0xbe, 0xef];
        let result = vrfun.vrf_proof(payload.clone());

        let verified = vrfun.verify_vrf(
            result.pk.clone().to_vec(),
            payload.clone().to_vec(),
            result.output.clone().to_vec(),
            result.proof.clone().to_vec(),
        );
        assert_eq!(verified.stderr, "".to_string());
        assert!(verified.verified);

        let bad_payload = vec![0xde, 0xad, 0xbe, 0xed];
        let verified = vrfun.verify_vrf(
            result.pk.to_vec(),
            bad_payload.to_vec(),
            result.output.to_vec(),
            result.proof.to_vec(),
        );
        assert!(!verified.verified);
    }
}
