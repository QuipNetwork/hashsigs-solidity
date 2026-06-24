use hashsigs_rs::shrincs::{PublicKey, ShrincsSigner, StatefulSignature, StatelessSignature};
use sha3::{Digest, Keccak256};
use std::process::Command;
use std::time::Instant;

const HASH_SUITE_KECCAK_256: u32 = 1;

fn main() {
    let mut args = std::env::args().skip(1);
    let mode = args.next().expect("mode");

    let encoded = match mode.as_str() {
        "stateful-key" => stateful_key_calldata(),
        "stateful" => stateful_calldata(&message_arg(args.next())),
        "stateful-stats" => stateful_stats(),
        "stateful-full-stats" => stateful_full_stats(),
        "stateful-commitment" => stateful_commitment(),
        "stateful-account-call" => stateful_account_call(&address_arg(args.next())),
        "stateful-library-call" => stateful_library_call(&address_arg(args.next())),
        "stateful-raw-call" => stateful_raw_call(&address_arg(args.next())),
        "stateless-key" => stateless_key_calldata(),
        "stateless" => stateless_calldata(&message_arg(args.next())),
        "stateless-stats" => stateless_stats(),
        "stateless-full-stats" => stateless_full_stats(),
        "stateless-commitment" => stateless_commitment(),
        "stateless-account-call" => stateless_account_call(&address_arg(args.next())),
        "stateless-library-call" => stateless_library_call(&address_arg(args.next())),
        "stateless-raw-call" => stateless_raw_call(&address_arg(args.next())),
        _ => panic!("unsupported mode: {mode}"),
    };
    print!("{encoded}");
}

fn stateful_key_calldata() -> String {
    let (_, public_key) = ShrincsSigner::keygen(b"shrincs gas stateful seed", 4).expect("stateful keygen");
    let encoded = &public_key.stateful_public_key;
    let hash_len = (encoded.len() - 4) / 2;
    let key = format!(
        "({},{},{})",
        hex(&encoded[0..hash_len]),
        hex(&encoded[hash_len..2 * hash_len]),
        u32::from_be_bytes(encoded[2 * hash_len..2 * hash_len + 4].try_into().expect("max signatures"))
    );
    cast_abi_encode("f((bytes,bytes,uint32))", &[key])
}

fn stateful_calldata(message: &[u8]) -> String {
    let (mut key, public_key) = ShrincsSigner::keygen(b"shrincs gas stateful seed", 4).expect("stateful keygen");
    let signature = ShrincsSigner::sign_stateful_raw(&mut key, message).expect("stateful signature");
    let encoded = &public_key.stateful_public_key;
    let hash_len = (encoded.len() - 4) / 2;
    let key = format!(
        "({},{},{})",
        hex(&encoded[0..hash_len]),
        hex(&encoded[hash_len..2 * hash_len]),
        u32::from_be_bytes(encoded[2 * hash_len..2 * hash_len + 4].try_into().expect("max signatures"))
    );
    let sig = format!(
        "({},{},{},{})",
        hex(&signature.randomizer),
        signature.counter,
        fixed_array(signature.chains.iter().map(|chain| hex(chain))),
        fixed_array(signature.auth_path.iter().map(|node| hex(node)))
    );
    cast_abi_encode(
        "f((bytes,bytes,uint32),bytes,(bytes,uint32,bytes[],bytes[]))",
        &[key, hex(message), sig],
    )
}

fn stateful_stats() -> String {
    let (mut key, _public_key) = ShrincsSigner::keygen(b"shrincs gas stateful seed", 4).expect("stateful keygen");
    let message = keccak_packed(&[b"shrincs gas stateful stats"]);
    let start = Instant::now();
    let signature = ShrincsSigner::sign_stateful_raw(&mut key, &message).expect("stateful signature");
    let micros = start.elapsed().as_micros();
    format!(
        "{{\"sign_us\":{},\"signature_bytes\":{}}}",
        micros,
        stateful_signature_bytes(&signature)
    )
}

fn stateful_full_stats() -> String {
    let start = Instant::now();
    let (mut key, _public_key) = ShrincsSigner::keygen(b"shrincs gas stateful seed", 4).expect("stateful keygen");
    let message = keccak_packed(&[b"shrincs gas stateful stats"]);
    let signature = ShrincsSigner::sign_stateful_raw(&mut key, &message).expect("stateful signature");
    let micros = start.elapsed().as_micros();
    format!(
        "{{\"keygen_plus_sign_us\":{},\"signature_bytes\":{}}}",
        micros,
        stateful_signature_bytes(&signature)
    )
}

fn stateful_commitment() -> String {
    let (_, public_key) = ShrincsSigner::keygen(b"shrincs gas stateful seed", 4).expect("stateful keygen");
    hex(&public_key_commitment(&public_key))
}

fn stateful_account_call(account: &[u8; 20]) -> String {
    let (mut key, public_key) = ShrincsSigner::keygen(b"shrincs gas stateful seed", 4).expect("stateful keygen");
    let message = stateful_action_message_hash(&public_key, account);
    let signature = ShrincsSigner::sign_stateful_raw(&mut key, &message).expect("stateful signature");
    cast_calldata(
        "verifyStatefulAction((bytes,bytes,bytes,bytes),bytes32,bytes32,(bytes,uint32,bytes[],bytes[]))",
        &[
            public_key_full_cast(&public_key),
            action_type(),
            payload_hash(),
            stateful_signature_cast(&signature),
        ],
    )
}

fn stateful_library_call(account: &[u8; 20]) -> String {
    let (mut key, public_key) = ShrincsSigner::keygen(b"shrincs gas stateful seed", 4).expect("stateful keygen");
    let message = stateful_action_message_hash(&public_key, account);
    let signature = ShrincsSigner::sign_stateful_raw(&mut key, &message).expect("stateful signature");
    cast_calldata(
        "verifyStateful(bytes32,(bytes,bytes,bytes,bytes),(bytes32,uint256,uint256,bytes32,bytes32),(bytes,uint32,bytes[],bytes[]))",
        &[
            hex(&public_key_commitment(&public_key)),
            public_key_full_cast(&public_key),
            action_context_cast(account),
            stateful_signature_cast(&signature),
        ],
    )
}

fn stateful_raw_call(account: &[u8; 20]) -> String {
    let (mut key, public_key) = ShrincsSigner::keygen(b"shrincs gas stateful seed", 4).expect("stateful keygen");
    let message = stateful_action_message_hash(&public_key, account);
    let signature = ShrincsSigner::sign_stateful_raw(&mut key, &message).expect("stateful signature");
    cast_calldata(
        "verifyStatefulUncheckedMessage(bytes32,(bytes,bytes,bytes,bytes),bytes,(bytes,uint32,bytes[],bytes[]))",
        &[
            hex(&public_key_commitment(&public_key)),
            public_key_full_cast(&public_key),
            hex(&message),
            stateful_signature_cast(&signature),
        ],
    )
}

fn stateless_key_calldata() -> String {
    let (_, public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateless seed", 256).expect("stateless keygen");
    cast_abi_encode("f((bytes,bytes,bytes))", &[public_key_cast(&public_key)])
}

fn stateless_calldata(message: &[u8]) -> String {
    let (key, public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateless seed", 256).expect("stateless keygen");
    let signature = ShrincsSigner::sign_stateless_raw(&key, message).expect("stateless signature");
    cast_abi_encode(
        "f((bytes,bytes,bytes),bytes,((bytes,uint32,(bytes,bytes[])[]),(uint64,uint32,bytes,(bytes,uint32,bytes[]),bytes[])[]))",
        &[public_key_cast(&public_key), hex(message), stateless_signature_cast(&signature)],
    )
}

fn stateless_stats() -> String {
    let (key, _public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateless seed", 256).expect("stateless keygen");
    let message = keccak_packed(&[b"shrincs gas stateless stats"]);
    let start = Instant::now();
    let signature = ShrincsSigner::sign_stateless_raw(&key, &message).expect("stateless signature");
    let micros = start.elapsed().as_micros();
    format!(
        "{{\"sign_us\":{},\"signature_bytes\":{}}}",
        micros,
        stateless_signature_bytes(&signature)
    )
}

fn stateless_full_stats() -> String {
    let start = Instant::now();
    let (key, _public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateless seed", 256).expect("stateless keygen");
    let message = keccak_packed(&[b"shrincs gas stateless stats"]);
    let signature = ShrincsSigner::sign_stateless_raw(&key, &message).expect("stateless signature");
    let micros = start.elapsed().as_micros();
    format!(
        "{{\"keygen_plus_sign_us\":{},\"signature_bytes\":{}}}",
        micros,
        stateless_signature_bytes(&signature)
    )
}

fn stateless_commitment() -> String {
    let (_, public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateless seed", 256).expect("stateless keygen");
    hex(&public_key_commitment(&public_key))
}

fn stateless_account_call(account: &[u8; 20]) -> String {
    let (key, public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateless seed", 256).expect("stateless keygen");
    let message = stateless_action_message_hash(&public_key, account);
    let signature = ShrincsSigner::sign_stateless_raw(&key, &message).expect("stateless signature");
    cast_calldata(
        "verifyStatelessAction((bytes,bytes,bytes,bytes),bytes32,bytes32,((bytes,uint32,(bytes,bytes[])[]),(uint64,uint32,bytes,(bytes,uint32,bytes[]),bytes[])[]))",
        &[public_key_full_cast(&public_key), action_type(), payload_hash(), stateless_signature_cast(&signature)],
    )
}

fn stateless_library_call(account: &[u8; 20]) -> String {
    let (key, public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateless seed", 256).expect("stateless keygen");
    let message = stateless_action_message_hash(&public_key, account);
    let signature = ShrincsSigner::sign_stateless_raw(&key, &message).expect("stateless signature");
    cast_calldata(
        "verifyStateless(bytes32,(bytes,bytes,bytes,bytes),(bytes32,uint256,uint256,bytes32,bytes32),((bytes,uint32,(bytes,bytes[])[]),(uint64,uint32,bytes,(bytes,uint32,bytes[]),bytes[])[]))",
        &[
            hex(&public_key_commitment(&public_key)),
            public_key_full_cast(&public_key),
            action_context_cast(account),
            stateless_signature_cast(&signature),
        ],
    )
}

fn stateless_raw_call(account: &[u8; 20]) -> String {
    let (key, public_key) =
        ShrincsSigner::keygen(b"shrincs solidity vector stateless seed", 256).expect("stateless keygen");
    let message = stateless_action_message_hash(&public_key, account);
    let signature = ShrincsSigner::sign_stateless_raw(&key, &message).expect("stateless signature");
    cast_calldata(
        "verifyStatelessUncheckedMessage(bytes32,(bytes,bytes,bytes,bytes),bytes,((bytes,uint32,(bytes,bytes[])[]),(uint64,uint32,bytes,(bytes,uint32,bytes[]),bytes[])[]))",
        &[
            hex(&public_key_commitment(&public_key)),
            public_key_full_cast(&public_key),
            hex(&message),
            stateless_signature_cast(&signature),
        ],
    )
}

fn public_key_cast(public_key: &PublicKey) -> String {
    format!(
        "({},{},{})",
        hex(&public_key.stateful_public_key),
        hex(&public_key.pk_seed),
        hex(&public_key.hypertree_root)
    )
}

fn public_key_full_cast(public_key: &PublicKey) -> String {
    format!(
        "({},{},{},{})",
        hex(&public_key.stateful_public_key),
        hex(&public_key_commitment(public_key)),
        hex(&public_key.pk_seed),
        hex(&public_key.hypertree_root)
    )
}

fn public_key_commitment(public_key: &PublicKey) -> [u8; 32] {
    keccak_packed(&[
        b"shrincs-public-key",
        &public_key.stateful_public_key,
        &public_key.pk_seed,
        &public_key.hypertree_root,
    ])
}

fn stateful_action_message_hash(public_key: &PublicKey, account: &[u8; 20]) -> [u8; 32] {
    let commitment = public_key_commitment(public_key);
    let domain = domain_separator(account);
    keccak_packed(&[
        &keccak_packed(&[b"shrincs-verify-stateful"]),
        &HASH_SUITE_KECCAK_256.to_be_bytes(),
        &commitment,
        &domain,
        &[0u8; 32],
        &[0u8; 32],
        &decode_hex_word(&action_type()),
        &decode_hex_word(&payload_hash()),
    ])
}

fn stateless_action_message_hash(public_key: &PublicKey, account: &[u8; 20]) -> [u8; 32] {
    let commitment = public_key_commitment(public_key);
    let domain = domain_separator(account);
    keccak_packed(&[
        &keccak_packed(&[b"shrincs-verify-stateless"]),
        &HASH_SUITE_KECCAK_256.to_be_bytes(),
        &commitment,
        &domain,
        &[0u8; 32],
        &[0u8; 32],
        &decode_hex_word(&action_type()),
        &decode_hex_word(&payload_hash()),
    ])
}

fn action_context_cast(account: &[u8; 20]) -> String {
    format!(
        "({},{},{},{},{})",
        hex(&domain_separator(account)),
        0,
        0,
        action_type(),
        payload_hash()
    )
}

fn domain_separator(account: &[u8; 20]) -> [u8; 32] {
    let mut encoded = Vec::with_capacity(96);
    encoded.extend_from_slice(&keccak_packed(&[b"shrincs-account-v1"]));
    encoded.extend_from_slice(&chain_id_word());
    encoded.extend_from_slice(&[0u8; 12]);
    encoded.extend_from_slice(account);
    keccak(&encoded)
}

fn chain_id_word() -> [u8; 32] {
    let chain_id = std::env::var("CHAIN_ID")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(31_337);
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&chain_id.to_be_bytes());
    word
}

fn action_type() -> String {
    hex(&keccak_packed(&[b"execute"]))
}

fn payload_hash() -> String {
    hex(&keccak_packed(&[b"payload"]))
}

fn stateless_signature_cast(signature: &StatelessSignature) -> String {
    let fors_entries = signature.fors.entries.iter().map(|entry| {
        format!(
            "({},{})",
            hex(&entry.secret_leaf),
            fixed_array(entry.auth_path.iter().map(|node| hex(node)))
        )
    });
    let fors = format!(
        "({},{},{})",
        hex(&signature.fors.randomizer),
        signature.fors.counter,
        fixed_array(fors_entries)
    );
    let layers = signature.hypertree.iter().map(|layer| {
        let wots = format!(
            "({},{},{})",
            hex(&layer.wots_c_signature.randomizer),
            layer.wots_c_signature.counter,
            fixed_array(layer.wots_c_signature.chains.iter().map(|chain| hex(chain)))
        );
        format!(
            "({},{},{},{},{})",
            layer.tree_index,
            layer.leaf_index,
            hex(&layer.wots_c_pk_hash),
            wots,
            fixed_array(layer.auth_path.iter().map(|node| hex(node)))
        )
    });
    format!("({},{})", fors, fixed_array(layers))
}

fn stateful_signature_cast(signature: &StatefulSignature) -> String {
    format!(
        "({},{},{},{})",
        hex(&signature.randomizer),
        signature.counter,
        fixed_array(signature.chains.iter().map(|chain| hex(chain))),
        fixed_array(signature.auth_path.iter().map(|node| hex(node)))
    )
}

fn stateful_signature_bytes(signature: &StatefulSignature) -> usize {
    signature.randomizer.len()
        + 4
        + signature.chains.iter().map(|chain| chain.len()).sum::<usize>()
        + signature.auth_path.iter().map(|node| node.len()).sum::<usize>()
}

fn stateless_signature_bytes(signature: &StatelessSignature) -> usize {
    let fors = signature.fors.randomizer.len()
        + 4
        + signature
            .fors
            .entries
            .iter()
            .map(|entry| entry.secret_leaf.len() + entry.auth_path.iter().map(|node| node.len()).sum::<usize>())
            .sum::<usize>();
    let hypertree = signature
        .hypertree
        .iter()
        .map(|layer| {
            8 + 4
                + layer.wots_c_pk_hash.len()
                + layer.wots_c_signature.randomizer.len()
                + 4
                + layer.wots_c_signature.chains.iter().map(|chain| chain.len()).sum::<usize>()
                + layer.auth_path.iter().map(|node| node.len()).sum::<usize>()
        })
        .sum::<usize>();
    fors + hypertree
}

fn fixed_array(values: impl Iterator<Item = String>) -> String {
    format!("[{}]", values.collect::<Vec<_>>().join(","))
}

fn cast_abi_encode(signature: &str, args: &[String]) -> String {
    let output = Command::new("cast")
        .arg("abi-encode")
        .arg(signature)
        .args(args)
        .output()
        .expect("run cast abi-encode");
    assert!(
        output.status.success(),
        "cast abi-encode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("cast output")
        .trim()
        .to_owned()
}

fn cast_calldata(signature: &str, args: &[String]) -> String {
    let output = Command::new("cast")
        .arg("calldata")
        .arg(signature)
        .args(args)
        .output()
        .expect("run cast calldata");
    assert!(
        output.status.success(),
        "cast calldata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("cast output")
        .trim()
        .to_owned()
}

fn message_arg(value: Option<String>) -> Vec<u8> {
    let message_hex = value.expect("32-byte message hex");
    let message = decode_hex(&message_hex);
    assert_eq!(message.len(), 32, "message must be 32 bytes");
    message
}

fn decode_hex(value: &str) -> Vec<u8> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    assert_eq!(raw.len() % 2, 0, "hex input must have even length");
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn decode_hex_word(value: &str) -> [u8; 32] {
    decode_hex(value).try_into().expect("32-byte word")
}

fn address_arg(value: Option<String>) -> [u8; 20] {
    decode_hex(&value.expect("address hex"))
        .try_into()
        .expect("20-byte address")
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn keccak_packed(parts: &[&[u8]]) -> [u8; 32] {
    let len = parts.iter().map(|part| part.len()).sum();
    let mut packed = Vec::with_capacity(len);
    for part in parts {
        packed.extend_from_slice(part);
    }
    keccak(&packed)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
