// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

mod native {
    use qtv_crypto::ml_dsa;
    use wasm_bindgen::prelude::*;
    use zeroize::Zeroize;

    const CONTEXT: &[u8] = b"quantova/qconsent/1";
    const SCRUB_FRAME: usize = 16_384;
    const SCRUB_FRAMES: usize = 16;
    static SIZES: [usize; 2] = [ml_dsa::PUBLIC_KEY_BYTES, ml_dsa::SIGNATURE_BYTES];

    fn wipe(buf: &mut [u8]) {
        buf.zeroize();
    }

    #[inline(never)]
    fn scrub_stack(frames: usize) {
        let mut area = [0u8; SCRUB_FRAME];
        core::hint::black_box(&mut area);
        wipe(&mut area);
        if frames > 1 {
            scrub_stack(core::hint::black_box(frames - 1));
        }
        core::hint::black_box(&area);
    }

    struct Seed([u8; ml_dsa::SEED_BYTES]);

    impl Drop for Seed {
        fn drop(&mut self) {
            wipe(&mut self.0);
        }
    }

    fn load_seed(mut bytes: Vec<u8>, into: &mut Seed) -> Result<(), JsError> {
        let ok = bytes.len() == ml_dsa::SEED_BYTES;
        if ok {
            into.0.copy_from_slice(&bytes);
        }
        wipe(&mut bytes);
        if !ok {
            return Err(JsError::new("a signing key is a 32 byte seed"));
        }
        Ok(())
    }

    fn public_key_of(seed: &Seed) -> Vec<u8> {
        let mut secret = [0u8; ml_dsa::SECRET_KEY_BYTES];
        let public = ml_dsa::keygen_into(&seed.0, &mut secret);
        wipe(&mut secret);
        public.to_vec()
    }

    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(seed_bytes: Vec<u8>) -> Result<Vec<u8>, JsError> {
        let mut s = Seed([0u8; ml_dsa::SEED_BYTES]);
        load_seed(seed_bytes, &mut s)?;
        let out = public_key_of(&s);
        wipe(&mut s.0);
        scrub_stack(SCRUB_FRAMES);
        Ok(out)
    }

    #[wasm_bindgen]
    pub fn sign(
        seed_bytes: Vec<u8>,
        message: &[u8],
        mut randomness: Vec<u8>,
    ) -> Result<Vec<u8>, JsError> {
        let mut s = Seed([0u8; ml_dsa::SEED_BYTES]);
        load_seed(seed_bytes, &mut s)?;
        let length_ok = randomness.len() == 32;
        let nonzero = randomness.iter().any(|b| *b != 0);
        let mut rnd = [0u8; 32];
        if length_ok {
            rnd.copy_from_slice(&randomness);
        }
        wipe(&mut randomness);
        if !length_ok {
            return Err(JsError::new(
                "signing randomness is 32 bytes from a secure random source",
            ));
        }
        if !nonzero {
            wipe(&mut rnd);
            return Err(JsError::new(
                "signing randomness is all zero, so the random source is not working",
            ));
        }
        let signature =
            ml_dsa::sign_from_seed(&s.0, message, CONTEXT, &rnd).map(|sig| sig.to_vec());
        wipe(&mut rnd);
        wipe(&mut s.0);
        scrub_stack(SCRUB_FRAMES);
        signature.ok_or_else(|| JsError::new("the message could not be signed"))
    }

    #[wasm_bindgen]
    pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(public) = <&ml_dsa::PublicKey>::try_from(public_key) else {
            return false;
        };
        let Ok(signature) = <&ml_dsa::Signature>::try_from(signature) else {
            return false;
        };
        ml_dsa::verify_strict(public, message, signature, CONTEXT)
    }

    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes() -> usize {
        SIZES[0]
    }

    #[wasm_bindgen(js_name = signatureBytes)]
    pub fn signature_bytes() -> usize {
        SIZES[1]
    }
}
