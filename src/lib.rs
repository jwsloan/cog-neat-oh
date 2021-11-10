use anyhow;
use data_encoding::HEXUPPER;
use hex::{decode, encode_upper};
use ring::digest::{Context, SHA256};

// # https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L22
const N_HEX: &'static str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
    29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
    EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
    E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
    EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
    C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
    83655D23DCA3AD961C62F356208552BB9ED529077096966D\
    670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
    E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
    DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
    15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64\
    ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
    ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B\
    F12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
    BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31\
    43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";

// # https://github.com/aws/amazon-cognito-identity-js/blob/master/src/AuthenticationHelper.js#L49
const G_HEX: &'static str = "2";

const INFO_BITS: &[u8] = &"Caldera Derived Key".as_bytes();

fn hash_sha256(buf: Vec<u8>) -> String {
    let mut context = Context::new(&SHA256);
    context.update(&buf);
    let digest = context.finish();
    encode_upper(digest.as_ref())
}

fn hex_hash(hex_str: &str) -> anyhow::Result<String> {
    let hex_val = decode(hex_str)?;
    Ok(hash_sha256(hex_val))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_hex_hash() {
        let hash = hex_hash("abc123");
        assert_eq!(
            hash.unwrap(),
            "6BF0FC7EA6D884895DEE9D0E1C423531924C2123F497514849AAF7350B37CC9E".to_owned()
        );
    }
}
