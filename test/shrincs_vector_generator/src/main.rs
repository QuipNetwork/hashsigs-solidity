use ethers::{
    abi::{encode, Token},
    types::{Bytes, U256},
    utils::keccak256,
};
use sha3::{Digest, Keccak256};
use std::{env, fs};

#[derive(Clone, Copy)]
struct Params {
    n_bytes: usize,
    h: u8,
    d: u8,
    a: u8,
    k: u8,
    w: u16,
    l: u16,
    target_sum: u32,
}

#[derive(Clone)]
struct PublicKey {
    composite_public_key: Vec<u8>,
    stateful_public_key: Vec<u8>,
    message_pk_seed: Vec<u8>,
    message_root: Vec<u8>,
    hypertree_pk_seed: Vec<u8>,
    hypertree_root: Vec<u8>,
}

#[derive(Clone)]
struct ForsEntry {
    sk: Vec<u8>,
    auth: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct ForsSignature {
    randomizer: Vec<u8>,
    counter: u32,
    entries: Vec<ForsEntry>,
}

#[derive(Clone)]
struct WotsCSignature {
    randomizer: Vec<u8>,
    counter: u32,
    chains: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct HypertreeLayer {
    tree_index: u64,
    leaf_index: u32,
    wots_c_pk_hash: Vec<u8>,
    wots_c_signature: WotsCSignature,
    auth_path: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct StatelessSignature {
    fors: ForsSignature,
    hypertree: Vec<HypertreeLayer>,
}

#[derive(Clone)]
struct StatelessVector {
    params: Params,
    public_key: PublicKey,
    message: Vec<u8>,
    signature: StatelessSignature,
}

#[derive(Clone)]
struct StatefulPublicKey {
    pk_seed: Vec<u8>,
    root: Vec<u8>,
    max_signatures: u32,
}

#[derive(Clone)]
struct StatefulSignature {
    randomizer: Vec<u8>,
    counter: u32,
    chains: Vec<Vec<u8>>,
    auth_path: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct StatefulVector {
    public_key: StatefulPublicKey,
    message: Vec<u8>,
    signature: StatefulSignature,
}

struct ForsDigest {
    xmss_tree: u64,
    xmss_keypair: u32,
    indices: Vec<u32>,
}

fn main() {
    let out_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "test/test_vectors/shrincs_sphincs_256s_keccak.json".to_string());
    let params = Params {
        n_bytes: 32,
        h: 64,
        d: 8,
        a: 14,
        k: 22,
        w: 16,
        l: 64,
        target_sum: 480,
    };

    let stateful = make_stateful_vector(params, 1);
    let stateless = make_stateless_vector(params, 0);

    let mut stateful_wrong_message = stateful.clone();
    stateful_wrong_message.message[0] ^= 0x01;
    let mut stateful_wrong_public_key = stateful.clone();
    stateful_wrong_public_key.public_key.root[0] ^= 0x01;
    let mut stateful_corrupted_signature = stateful.clone();
    stateful_corrupted_signature.signature.chains[0][0] ^= 0x01;

    let mut stateless_wrong_message = stateless.clone();
    stateless_wrong_message.message[0] ^= 0x01;
    let mut stateless_wrong_composite_public_key = stateless.clone();
    stateless_wrong_composite_public_key.public_key.composite_public_key[0] ^= 0x01;
    let mut stateless_tampered_component_public_key = stateless.clone();
    stateless_tampered_component_public_key.public_key.message_root[0] ^= 0x01;
    let mut stateless_tampered_fors = stateless.clone();
    stateless_tampered_fors.signature.fors.entries[0].sk[0] ^= 0x01;
    let mut stateless_bad_wots_pk_hash = stateless.clone();
    stateless_bad_wots_pk_hash.signature.hypertree[0].wots_c_pk_hash[0] ^= 0x01;
    let mut stateless_bad_auth = stateless.clone();
    stateless_bad_auth.signature.hypertree[0].auth_path[0][0] ^= 0x01;

    let json = format!(
        concat!(
            "{{\n",
            "  \"params\": {},\n",
            "  \"stateful\": {{\n",
            "    \"publicKey\": {},\n",
            "    \"message\": \"{}\",\n",
            "    \"signature\": {},\n",
            "    \"cases\": {{\n",
            "      \"valid\": {{\"calldata\": \"{}\"}},\n",
            "      \"wrongMessage\": {{\"message\": \"{}\", \"calldata\": \"{}\"}},\n",
            "      \"wrongPublicKey\": {{\"publicKey\": {}, \"calldata\": \"{}\"}},\n",
            "      \"corruptedSignature\": {{\"signature\": {}, \"calldata\": \"{}\"}}\n",
            "    }}\n",
            "  }},\n",
            "  \"stateless\": {{\n",
            "    \"publicKey\": {},\n",
            "    \"message\": \"{}\",\n",
            "    \"signature\": {},\n",
            "    \"cases\": {{\n",
            "      \"valid\": {{\"calldata\": \"{}\"}},\n",
            "      \"wrongMessage\": {{\"message\": \"{}\", \"calldata\": \"{}\"}},\n",
            "      \"wrongCompositePublicKey\": {{\"publicKey\": {}, \"calldata\": \"{}\"}},\n",
            "      \"tamperedComponentPublicKey\": {{\"publicKey\": {}, \"calldata\": \"{}\"}},\n",
            "      \"tamperedFors\": {{\"fors\": {}, \"calldata\": \"{}\"}},\n",
            "      \"tamperedHypertreeWotsPkHash\": {{\"hypertreeLayer\": {}, \"calldata\": \"{}\"}},\n",
            "      \"tamperedHypertreeAuth\": {{\"hypertreeLayer\": {}, \"calldata\": \"{}\"}}\n",
            "    }}\n",
            "  }}\n",
            "}}\n"
        ),
        params_json(params),
        stateful_public_key_json(&stateful.public_key),
        hex_prefixed(&stateful.message),
        stateful_signature_json(&stateful.signature),
        hex_prefixed(&stateful_calldata(&stateful)),
        hex_prefixed(&stateful_wrong_message.message),
        hex_prefixed(&stateful_calldata(&stateful_wrong_message)),
        stateful_public_key_json(&stateful_wrong_public_key.public_key),
        hex_prefixed(&stateful_calldata(&stateful_wrong_public_key)),
        stateful_signature_json(&stateful_corrupted_signature.signature),
        hex_prefixed(&stateful_calldata(&stateful_corrupted_signature)),
        public_key_json(&stateless.public_key),
        hex_prefixed(&stateless.message),
        stateless_signature_json(&stateless.signature),
        hex_prefixed(&stateless_calldata(&stateless)),
        hex_prefixed(&stateless_wrong_message.message),
        hex_prefixed(&stateless_calldata(&stateless_wrong_message)),
        public_key_json(&stateless_wrong_composite_public_key.public_key),
        hex_prefixed(&stateless_calldata(&stateless_wrong_composite_public_key)),
        public_key_json(&stateless_tampered_component_public_key.public_key),
        hex_prefixed(&stateless_calldata(&stateless_tampered_component_public_key)),
        fors_signature_json(&stateless_tampered_fors.signature.fors),
        hex_prefixed(&stateless_calldata(&stateless_tampered_fors)),
        hypertree_layer_json(&stateless_bad_wots_pk_hash.signature.hypertree[0]),
        hex_prefixed(&stateless_calldata(&stateless_bad_wots_pk_hash)),
        hypertree_layer_json(&stateless_bad_auth.signature.hypertree[0]),
        hex_prefixed(&stateless_calldata(&stateless_bad_auth)),
    );

    fs::write(out_path, json).expect("write vector JSON");
}

fn make_stateless_vector(params: Params, sample: u32) -> StatelessVector {
    let message = keccak(&[b"shrincs-stateless-message", &sample.to_be_bytes()], 32);
    let hypertree_seed = seed(b"hypertree", params.n_bytes);
    let hypertree_public_key = hypertree_public_key(params, &hypertree_seed);
    let (message_pk, fors, bottom_tree, bottom_leaf) =
        sign_fors_c(params, &seed(b"fors-c", params.n_bytes), &message, &hypertree_public_key.root);
    let (hypertree_pk, hypertree) = sign_hypertree(params, &hypertree_seed, &message_pk.root, bottom_tree, bottom_leaf);
    let stateful_public_key = stateful_public_key_bytes(params, sample);
    let composite_public_key = hash_n(
        b"shrincs-public-key",
        &[],
        &[
            stateful_public_key.as_slice(),
            message_pk.pk_seed.as_slice(),
            message_pk.root.as_slice(),
            hypertree_pk.pk_seed.as_slice(),
            hypertree_pk.root.as_slice(),
        ]
        .concat(),
        params.n_bytes,
    );
    StatelessVector {
        params,
        public_key: PublicKey {
            composite_public_key,
            stateful_public_key,
            message_pk_seed: message_pk.pk_seed,
            message_root: message_pk.root,
            hypertree_pk_seed: hypertree_pk.pk_seed,
            hypertree_root: hypertree_pk.root,
        },
        message,
        signature: StatelessSignature { fors, hypertree },
    }
}

fn make_stateful_vector(params: Params, sample: u32) -> StatefulVector {
    let pk_seed = hash_n(b"stateful-pk-seed", &sample.to_be_bytes(), &[], 32);
    let sk_seed = hash_n(b"stateful-sk-seed", &sample.to_be_bytes(), &[], 32);
    let leaf_index = 1u32;
    let message = keccak(&[b"shrincs-stateful-message", &sample.to_be_bytes()], 32);
    let pk_hash = stateful_wots_public_key(params, &pk_seed, &sk_seed, leaf_index);
    let randomizer = hash_n(b"stateful-wots-randomizer", &sk_seed, &message, 32);
    let counter = grind_stateful_wots_counter(&pk_seed, leaf_index, &randomizer, &message, params.target_sum);
    let chains = stateful_wots_signature_chains(params, &pk_seed, &sk_seed, leaf_index, &randomizer, counter, &message);
    let auth_path = vec![hash_n(b"stateful-auth-sibling", &pk_seed, &sample.to_be_bytes(), 32)];
    let root = stateful_parent_hash(&pk_seed, leaf_index, &pk_hash, &auth_path[0]);
    StatefulVector {
        public_key: StatefulPublicKey {
            pk_seed,
            root,
            max_signatures: leaf_index,
        },
        message,
        signature: StatefulSignature {
            randomizer,
            counter,
            chains,
            auth_path,
        },
    }
}

fn sign_fors_c(
    params: Params,
    seed_material: &[u8],
    message: &[u8],
    hypertree_root: &[u8],
) -> (ComponentPublicKey, ForsSignature, u64, u32) {
    let sk_seed = hash_n(b"fors-sk", seed_material, &[], params.n_bytes);
    let pk_seed = hash_n(b"fors-pk", seed_material, &[], params.n_bytes);
    let signed_trees = usize::from(params.k - 1);
    let randomizer = hash_n(b"fors-randomizer", &sk_seed, message, params.n_bytes);
    let (counter, digest) = (0u32..(1 << 24))
        .map(|counter| {
            (
                counter,
                fors_digest(params, &pk_seed, hypertree_root, message, &randomizer, counter),
            )
        })
        .find(|(_, digest)| digest.indices.last() == Some(&0))
        .expect("FORS+C grinding failed");
    let mut roots = Vec::new();
    for tree in 0..signed_trees {
        roots.extend(fors_virtual_node(
            params,
            &pk_seed,
            &sk_seed,
            digest.xmss_tree,
            digest.xmss_keypair,
            tree as u64,
            u32::from(params.a),
            0,
        ));
    }
    let pk = ComponentPublicKey {
        pk_seed: pk_seed.clone(),
        root: hash_n(b"fors-pk", &pk_seed, &roots, params.n_bytes),
    };
    let entries = (0..signed_trees)
        .map(|tree| {
            let leaf = digest.indices[tree];
            let sk = fors_leaf_secret(params, &pk_seed, &sk_seed, digest.xmss_tree, digest.xmss_keypair, tree as u64, leaf);
            let auth = fors_virtual_auth_path(params, &pk_seed, &sk_seed, digest.xmss_tree, digest.xmss_keypair, tree as u64, leaf);
            ForsEntry { sk, auth }
        })
        .collect();
    (
        pk,
        ForsSignature {
            randomizer,
            counter,
            entries,
        },
        digest.xmss_tree,
        digest.xmss_keypair,
    )
}

#[derive(Clone)]
struct ComponentPublicKey {
    pk_seed: Vec<u8>,
    root: Vec<u8>,
}

fn fors_digest(params: Params, pk_seed: &[u8], hypertree_root: &[u8], msg: &[u8], randomizer: &[u8], counter: u32) -> ForsDigest {
    let index_bits = u32::from(params.k) * u32::from(params.a);
    let subtree_height = u32::from(params.h / params.d);
    let tree_bits = u32::from(params.h) - subtree_height;
    let digest_bytes = ((index_bits + u32::from(params.h)) as usize + 7) / 8;
    let digest = hash_n(
        b"fors-digest",
        pk_seed,
        &[hypertree_root, randomizer, &counter.to_be_bytes(), msg].concat(),
        digest_bytes,
    );
    let indices = (0..params.k)
        .map(|i| read_bits(&digest, i as usize * params.a as usize, params.a as u32))
        .collect::<Vec<_>>();
    let mut cursor = index_bits as usize;
    let xmss_tree = read_bits_u64(&digest, cursor, tree_bits);
    cursor += tree_bits as usize;
    let xmss_keypair = read_bits(&digest, cursor, subtree_height);
    ForsDigest {
        xmss_tree,
        xmss_keypair,
        indices,
    }
}

fn fors_virtual_node(
    params: Params,
    pk_seed: &[u8],
    sk_seed: &[u8],
    xmss_tree: u64,
    xmss_keypair: u32,
    tree: u64,
    height: u32,
    index: u32,
) -> Vec<u8> {
    if height == 0 {
        return fors_leaf_hash(params, pk_seed, sk_seed, xmss_tree, xmss_keypair, tree, index);
    }
    let left = fors_virtual_node(params, pk_seed, sk_seed, xmss_tree, xmss_keypair, tree, height - 1, index << 1);
    let right = fors_virtual_node(params, pk_seed, sk_seed, xmss_tree, xmss_keypair, tree, height - 1, (index << 1) | 1);
    fors_node(params, xmss_tree, xmss_keypair, tree, height, index, &left, &right, pk_seed)
}

fn fors_virtual_auth_path(
    params: Params,
    pk_seed: &[u8],
    sk_seed: &[u8],
    xmss_tree: u64,
    xmss_keypair: u32,
    tree: u64,
    leaf: u32,
) -> Vec<Vec<u8>> {
    (0..u32::from(params.a))
        .map(|level| {
            let sibling = (leaf >> level) ^ 1;
            fors_virtual_node(params, pk_seed, sk_seed, xmss_tree, xmss_keypair, tree, level, sibling)
        })
        .collect()
}

fn fors_node(
    params: Params,
    xmss_tree: u64,
    xmss_keypair: u32,
    tree: u64,
    height: u32,
    index: u32,
    left: &[u8],
    right: &[u8],
    pk_seed: &[u8],
) -> Vec<u8> {
    let tree_index = fors_tree_index(tree as u32, u32::from(params.a), height, index);
    hash_n(
        b"fors-node",
        pk_seed,
        &[&address_word(0, xmss_tree, 3, xmss_keypair, height, tree_index), left, right].concat(),
        params.n_bytes,
    )
}

fn fors_leaf_secret(params: Params, pk_seed: &[u8], sk_seed: &[u8], xmss_tree: u64, xmss_keypair: u32, tree: u64, leaf: u32) -> Vec<u8> {
    let tree_index = fors_tree_index(tree as u32, u32::from(params.a), 0, leaf);
    hash_n(
        b"fors-sk",
        sk_seed,
        &[pk_seed, &address_word(0, xmss_tree, 6, xmss_keypair, 0, tree_index)].concat(),
        params.n_bytes,
    )
}

fn fors_leaf_hash(params: Params, pk_seed: &[u8], sk_seed: &[u8], xmss_tree: u64, xmss_keypair: u32, tree: u64, leaf: u32) -> Vec<u8> {
    let sk = fors_leaf_secret(params, pk_seed, sk_seed, xmss_tree, xmss_keypair, tree, leaf);
    let tree_index = fors_tree_index(tree as u32, u32::from(params.a), 0, leaf);
    hash_n(
        b"fors-leaf",
        pk_seed,
        &[&address_word(0, xmss_tree, 3, xmss_keypair, 0, tree_index), sk.as_slice()].concat(),
        params.n_bytes,
    )
}

fn hypertree_public_key(params: Params, seed_material: &[u8]) -> ComponentPublicKey {
    let pk_seed = hash_n(b"hypertree-pk-seed", seed_material, &[], 32);
    let mut layer_seeds = Vec::new();
    for layer in 0..params.d {
        layer_seeds.push(hash_n(b"hypertree-layer-seed", seed_material, &u32::from(layer).to_be_bytes(), 32));
    }
    let top_layer = u32::from(params.d - 1);
    let top_tree = u64::from(top_layer + 1);
    let root = hypertree_virtual_node(params, &pk_seed, &layer_seeds[top_layer as usize], top_layer, top_tree, u32::from(params.h / params.d), 0);
    ComponentPublicKey { pk_seed, root }
}

fn sign_hypertree(
    params: Params,
    seed_material: &[u8],
    msg_root: &[u8],
    bottom_tree: u64,
    bottom_leaf: u32,
) -> (ComponentPublicKey, Vec<HypertreeLayer>) {
    let pk_seed = hash_n(b"hypertree-pk-seed", seed_material, &[], 32);
    let root = hypertree_public_key(params, seed_material).root;
    let leaf_count = 1u32 << (params.h / params.d);
    let mut layer_seeds = Vec::new();
    for layer in 0..params.d {
        layer_seeds.push(hash_n(b"hypertree-layer-seed", seed_material, &u32::from(layer).to_be_bytes(), 32));
    }

    let mut layers = Vec::new();
    let mut current = msg_root.to_vec();
    for layer in 0..u32::from(params.d) {
        let (tree, leaf) = if layer == 0 {
            (bottom_tree, bottom_leaf)
        } else {
            (u64::from(layer + 1), (layer + 1) % leaf_count)
        };
        let leaf_seed = hash_n(b"hypertree-leaf-seed", &layer_seeds[layer as usize], &[tree.to_be_bytes().as_slice(), leaf.to_be_bytes().as_slice()].concat(), params.n_bytes);
        let sk_seed = hash_n(b"hypertree-wots-sk-seed", &leaf_seed, &[], 32);
        let pk_hash = wots_c_public_key(params, &pk_seed, &sk_seed, layer, tree, leaf);
        let wots_c_signature = wots_c_sign(params, &pk_seed, &sk_seed, &pk_hash, layer, tree, leaf, &current);
        let auth_path = hypertree_virtual_auth_path(params, &pk_seed, &layer_seeds[layer as usize], layer, tree, leaf);
        current = hypertree_virtual_node(params, &pk_seed, &layer_seeds[layer as usize], layer, tree, u32::from(params.h / params.d), 0);
        layers.push(HypertreeLayer {
            tree_index: tree,
            leaf_index: leaf,
            wots_c_pk_hash: pk_hash,
            wots_c_signature,
            auth_path,
        });
    }
    (ComponentPublicKey { pk_seed, root }, layers)
}

fn hypertree_virtual_auth_path(params: Params, pk_seed: &[u8], layer_seed: &[u8], layer: u32, tree: u64, leaf: u32) -> Vec<Vec<u8>> {
    let subtree_height = u32::from(params.h / params.d);
    (0..subtree_height)
        .map(|level| {
            let sibling = (leaf >> level) ^ 1;
            hypertree_virtual_node(params, pk_seed, layer_seed, layer, tree, level, sibling)
        })
        .collect()
}

fn hypertree_virtual_node(params: Params, pk_seed: &[u8], layer_seed: &[u8], layer: u32, tree: u64, height: u32, index: u32) -> Vec<u8> {
    if height == 0 {
        return hypertree_leaf(params, pk_seed, layer_seed, layer, tree, index);
    }
    let left = hypertree_virtual_node(params, pk_seed, layer_seed, layer, tree, height - 1, index << 1);
    let right = hypertree_virtual_node(params, pk_seed, layer_seed, layer, tree, height - 1, (index << 1) | 1);
    hypertree_node(params, layer, tree, height, index, &left, &right, pk_seed)
}

fn hypertree_leaf(params: Params, pk_seed: &[u8], layer_seed: &[u8], layer: u32, tree: u64, leaf: u32) -> Vec<u8> {
    let leaf_seed = hash_n(b"hypertree-leaf-seed", layer_seed, &[tree.to_be_bytes().as_slice(), leaf.to_be_bytes().as_slice()].concat().as_slice(), params.n_bytes);
    let sk_seed = hash_n(b"hypertree-wots-sk-seed", &leaf_seed, &[], 32);
    wots_c_public_key(params, pk_seed, &sk_seed, layer, tree, leaf)
}

fn hypertree_node(params: Params, layer: u32, tree: u64, height: u32, index: u32, left: &[u8], right: &[u8], pk_seed: &[u8]) -> Vec<u8> {
    hash_n(
        b"hypertree-node",
        pk_seed,
        &[&address_word(layer, tree, 2, 0, height, index), left, right].concat(),
        params.n_bytes,
    )
}

fn wots_c_public_key(params: Params, pk_seed: &[u8], sk_seed: &[u8], layer: u32, tree: u64, keypair: u32) -> Vec<u8> {
    let mut endpoints = Vec::new();
    for chain in 0..params.l {
        let sk = wots_c_secret(sk_seed, u32::from(chain));
        endpoints.extend(wots_c_chain(params, pk_seed, layer, tree, keypair, u32::from(chain), &sk, 0, u32::from(params.w - 1)));
    }
    hash_n(b"wots-c-pk", pk_seed, &endpoints, params.n_bytes)
}

fn wots_c_sign(params: Params, pk_seed: &[u8], sk_seed: &[u8], pk_hash: &[u8], layer: u32, tree: u64, keypair: u32, msg: &[u8]) -> WotsCSignature {
    let randomizer = hash_n(b"wots-c-randomizer", sk_seed, msg, 32);
    let digest_bytes = (usize::from(params.l) * 4 + 7) / 8;
    for counter in 0u32..(1 << 24) {
        let digest = hash_n(b"wots-c-msg", pk_seed, &[pk_hash, &randomizer, &counter.to_be_bytes(), msg].concat(), digest_bytes);
        let digits = (0..usize::from(params.l)).map(|i| base_w16(&digest, i)).collect::<Vec<_>>();
        if digits.iter().sum::<u32>() != params.target_sum {
            continue;
        }
        let chains = digits
            .iter()
            .enumerate()
            .map(|(chain, digit)| {
                let sk = wots_c_secret(sk_seed, chain as u32);
                wots_c_chain(params, pk_seed, layer, tree, keypair, chain as u32, &sk, 0, *digit)
            })
            .collect();
        return WotsCSignature {
            randomizer,
            counter,
            chains,
        };
    }
    panic!("WOTS+C grinding failed");
}

fn wots_c_secret(sk_seed: &[u8], chain: u32) -> Vec<u8> {
    hash_n(b"wots-c-secret", sk_seed, &chain.to_be_bytes(), 32)
}

fn wots_c_chain(params: Params, pk_seed: &[u8], layer: u32, tree: u64, keypair: u32, chain: u32, value: &[u8], start: u32, steps: u32) -> Vec<u8> {
    let mut out = value.to_vec();
    for step in start..start + steps {
        out = keccak(&[b"wots-c-chain", pk_seed, &address_word(layer, tree, 0, keypair, chain, step), &out], params.n_bytes);
    }
    out
}

fn stateful_wots_public_key(params: Params, pk_seed: &[u8], sk_seed: &[u8], leaf_index: u32) -> Vec<u8> {
    let mut endpoints = Vec::new();
    for chain in 0..params.l {
        let sk = hash_n(b"stateful-wots-secret", sk_seed, &u32::from(chain).to_be_bytes(), 32);
        endpoints.extend(stateful_wots_chain(params, pk_seed, leaf_index, u32::from(chain), &sk, 0, u32::from(params.w - 1)));
    }
    keccak(&[b"uxmss-wots-pk", pk_seed, &leaf_index.to_be_bytes(), &endpoints], 32)
}

fn stateful_wots_signature_chains(params: Params, pk_seed: &[u8], sk_seed: &[u8], leaf_index: u32, randomizer: &[u8], counter: u32, msg: &[u8]) -> Vec<Vec<u8>> {
    let digest = keccak(&[b"uxmss-wots-digits", pk_seed, &leaf_index.to_be_bytes(), randomizer, &counter.to_be_bytes(), msg], 32);
    (0..params.l)
        .map(|chain| {
            let digit = base_w16(&digest, usize::from(chain));
            let sk = hash_n(b"stateful-wots-secret", sk_seed, &u32::from(chain).to_be_bytes(), 32);
            stateful_wots_chain(params, pk_seed, leaf_index, u32::from(chain), &sk, 0, digit)
        })
        .collect()
}

fn grind_stateful_wots_counter(pk_seed: &[u8], leaf_index: u32, randomizer: &[u8], msg: &[u8], target_sum: u32) -> u32 {
    for counter in 0u32..(1 << 24) {
        let digest = keccak(&[b"uxmss-wots-digits", pk_seed, &leaf_index.to_be_bytes(), randomizer, &counter.to_be_bytes(), msg], 32);
        let sum = (0..64).map(|i| base_w16(&digest, i)).sum::<u32>();
        if sum == target_sum {
            return counter;
        }
    }
    panic!("stateful WOTS+C grinding failed");
}

fn stateful_wots_chain(params: Params, pk_seed: &[u8], leaf_index: u32, chain: u32, value: &[u8], start: u32, steps: u32) -> Vec<u8> {
    let mut out = value.to_vec();
    for step in start..start + steps {
        out = keccak(&[b"wots-c-chain", pk_seed, &address_word(0, 0, 0, leaf_index, chain, step), &out], params.n_bytes);
    }
    out
}

fn stateful_parent_hash(pk_seed: &[u8], left_leaf_index: u32, left: &[u8], right: &[u8]) -> Vec<u8> {
    keccak(&[b"uxmss-node", pk_seed, &left_leaf_index.to_be_bytes(), left, right], 32)
}

fn stateful_public_key_bytes(params: Params, sample: u32) -> Vec<u8> {
    let pk_seed = hash_n(b"shrincs-stateful-pk-seed", &sample.to_be_bytes(), &[], 32);
    let root = hash_n(b"shrincs-stateful-root", &pk_seed, &[], 32);
    let max_signatures = 1u32 << u32::from(params.h / params.d);
    [pk_seed.as_slice(), root.as_slice(), max_signatures.to_be_bytes().as_slice()].concat()
}

fn keccak(parts: &[&[u8]], n: usize) -> Vec<u8> {
    if n <= 32 {
        let mut h = Keccak256::new();
        for part in parts {
            h.update(part);
        }
        return h.finalize()[..n].to_vec();
    }
    let mut out = Vec::with_capacity(n);
    let mut counter = 0u32;
    while out.len() < n {
        let mut h = Keccak256::new();
        for part in parts {
            h.update(part);
        }
        h.update(counter.to_be_bytes());
        let block = h.finalize();
        let chunk = (n - out.len()).min(32);
        out.extend_from_slice(&block[..chunk]);
        counter = counter.wrapping_add(1);
    }
    out
}

fn hash_n(domain: &[u8], seed_value: &[u8], data: &[u8], n: usize) -> Vec<u8> {
    keccak(&[domain, seed_value, data], n)
}

fn seed(label: &[u8], n: usize) -> Vec<u8> {
    keccak(&[b"shrincs-slh-dsa-gas-seed", label], n)
}

fn address_word(layer: u32, tree: u64, ty: u32, keypair: u32, chain: u32, step: u32) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..4].copy_from_slice(&layer.to_be_bytes());
    out[8..16].copy_from_slice(&tree.to_be_bytes());
    out[16..20].copy_from_slice(&ty.to_be_bytes());
    out[20..24].copy_from_slice(&keypair.to_be_bytes());
    out[24..28].copy_from_slice(&chain.to_be_bytes());
    out[28..32].copy_from_slice(&step.to_be_bytes());
    out
}

fn fors_tree_index(tree: u32, fors_height: u32, node_height: u32, node_index: u32) -> u32 {
    (tree << (fors_height - node_height)) + node_index
}

fn read_bits(input: &[u8], start_bit: usize, bit_len: u32) -> u32 {
    let mut out = 0u32;
    for offset in 0..bit_len as usize {
        let bit_index = start_bit + offset;
        let bit = (input[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
        out = (out << 1) | u32::from(bit);
    }
    out
}

fn read_bits_u64(input: &[u8], start_bit: usize, bit_len: u32) -> u64 {
    let mut out = 0u64;
    for offset in 0..bit_len as usize {
        let bit_index = start_bit + offset;
        let bit = (input[bit_index / 8] >> (7 - (bit_index % 8))) & 1;
        out = (out << 1) | u64::from(bit);
    }
    out
}

fn base_w16(digest: &[u8], index: usize) -> u32 {
    let b = digest[index >> 1];
    if index & 1 == 0 {
        u32::from(b >> 4)
    } else {
        u32::from(b & 0x0f)
    }
}

fn params_json(_: Params) -> String {
    concat!(
        "{\"name\":\"sphincs-256s\",",
        "\"h\":64,",
        "\"d\":8,",
        "\"subtreeHeight\":8,",
        "\"a\":14,",
        "\"k\":22,",
        "\"nBits\":256,",
        "\"wotsW\":16,",
        "\"l\":64,",
        "\"targetSum\":480}"
    )
    .to_string()
}

fn public_key_json(pk: &PublicKey) -> String {
    format!(
        concat!(
            "{{",
            "\"compositePublicKey\":\"{}\",",
            "\"statefulPublicKey\":\"{}\",",
            "\"messagePkSeed\":\"{}\",",
            "\"messageRoot\":\"{}\",",
            "\"hypertreePkSeed\":\"{}\",",
            "\"hypertreeRoot\":\"{}\"",
            "}}"
        ),
        hex_prefixed(&pk.composite_public_key),
        hex_prefixed(&pk.stateful_public_key),
        hex_prefixed(&pk.message_pk_seed),
        hex_prefixed(&pk.message_root),
        hex_prefixed(&pk.hypertree_pk_seed),
        hex_prefixed(&pk.hypertree_root),
    )
}

fn stateful_public_key_json(pk: &StatefulPublicKey) -> String {
    format!(
        "{{\"pkSeed\":\"{}\",\"root\":\"{}\",\"maxSignatures\":{}}}",
        hex_prefixed(&pk.pk_seed),
        hex_prefixed(&pk.root),
        pk.max_signatures,
    )
}

fn fors_signature_json(sig: &ForsSignature) -> String {
    format!(
        "{{\"randomizer\":\"{}\",\"counter\":{},\"entries\":{}}}",
        hex_prefixed(&sig.randomizer),
        sig.counter,
        json_array(sig.entries.iter().map(fors_entry_json).collect()),
    )
}

fn fors_entry_json(entry: &ForsEntry) -> String {
    format!(
        "{{\"sk\":\"{}\",\"auth\":{}}}",
        hex_prefixed(&entry.sk),
        hex_bytes_array_json(&entry.auth),
    )
}

fn wots_c_signature_json(sig: &WotsCSignature) -> String {
    format!(
        "{{\"randomizer\":\"{}\",\"counter\":{},\"chains\":{}}}",
        hex_prefixed(&sig.randomizer),
        sig.counter,
        hex_bytes_array_json(&sig.chains),
    )
}

fn hypertree_layer_json(layer: &HypertreeLayer) -> String {
    format!(
        concat!(
            "{{",
            "\"treeIndex\":{},",
            "\"leafIndex\":{},",
            "\"wotsCPkHash\":\"{}\",",
            "\"wotsCSignature\":{},",
            "\"authPath\":{}",
            "}}"
        ),
        layer.tree_index,
        layer.leaf_index,
        hex_prefixed(&layer.wots_c_pk_hash),
        wots_c_signature_json(&layer.wots_c_signature),
        hex_bytes_array_json(&layer.auth_path),
    )
}

fn stateless_signature_json(sig: &StatelessSignature) -> String {
    format!(
        "{{\"fors\":{},\"hypertree\":{}}}",
        fors_signature_json(&sig.fors),
        json_array(sig.hypertree.iter().map(hypertree_layer_json).collect()),
    )
}

fn stateful_signature_json(sig: &StatefulSignature) -> String {
    format!(
        "{{\"randomizer\":\"{}\",\"counter\":{},\"chains\":{},\"authPath\":{}}}",
        hex_prefixed(&sig.randomizer),
        sig.counter,
        hex_bytes_array_json(&sig.chains),
        hex_bytes_array_json(&sig.auth_path),
    )
}

fn hex_bytes_array_json(values: &[Vec<u8>]) -> String {
    json_array(values.iter().map(|value| format!("\"{}\"", hex_prefixed(value))).collect())
}

fn json_array(values: Vec<String>) -> String {
    format!("[{}]", values.join(","))
}

fn params_token(p: Params) -> Token {
    Token::Tuple(vec![
        Token::Uint(U256::from(p.n_bytes)),
        Token::Uint(U256::from(p.h)),
        Token::Uint(U256::from(p.d)),
        Token::Uint(U256::from(p.a)),
        Token::Uint(U256::from(p.k)),
        Token::Uint(U256::from(p.w)),
        Token::Uint(U256::from(p.l)),
        Token::Uint(U256::from(p.target_sum)),
    ])
}

fn public_key_token(pk: &PublicKey) -> Token {
    Token::Tuple(vec![
        Token::Bytes(pk.composite_public_key.clone()),
        Token::Bytes(pk.stateful_public_key.clone()),
        Token::Bytes(pk.message_pk_seed.clone()),
        Token::Bytes(pk.message_root.clone()),
        Token::Bytes(pk.hypertree_pk_seed.clone()),
        Token::Bytes(pk.hypertree_root.clone()),
    ])
}

fn fors_token(sig: &ForsSignature) -> Token {
    Token::Tuple(vec![
        Token::Bytes(sig.randomizer.clone()),
        Token::Uint(U256::from(sig.counter)),
        Token::Array(
            sig.entries
                .iter()
                .map(|entry| {
                    Token::Tuple(vec![
                        Token::Bytes(entry.sk.clone()),
                        Token::Array(entry.auth.iter().cloned().map(Token::Bytes).collect()),
                    ])
                })
                .collect(),
        ),
    ])
}

fn wots_c_token(sig: &WotsCSignature) -> Token {
    Token::Tuple(vec![
        Token::Bytes(sig.randomizer.clone()),
        Token::Uint(U256::from(sig.counter)),
        Token::Array(sig.chains.iter().cloned().map(Token::Bytes).collect()),
    ])
}

fn hypertree_token(layers: &[HypertreeLayer]) -> Token {
    Token::Array(
        layers
            .iter()
            .map(|layer| {
                Token::Tuple(vec![
                    Token::Uint(U256::from(layer.tree_index)),
                    Token::Uint(U256::from(layer.leaf_index)),
                    Token::Bytes(layer.wots_c_pk_hash.clone()),
                    wots_c_token(&layer.wots_c_signature),
                    Token::Array(layer.auth_path.iter().cloned().map(Token::Bytes).collect()),
                ])
            })
            .collect(),
    )
}

fn stateless_signature_token(sig: &StatelessSignature) -> Token {
    Token::Tuple(vec![fors_token(&sig.fors), hypertree_token(&sig.hypertree)])
}

fn stateful_public_key_token(pk: &StatefulPublicKey) -> Token {
    Token::Tuple(vec![
        Token::FixedBytes(pk.pk_seed.clone()),
        Token::FixedBytes(pk.root.clone()),
        Token::Uint(U256::from(pk.max_signatures)),
    ])
}

fn stateful_signature_token(sig: &StatefulSignature) -> Token {
    Token::Tuple(vec![
        Token::FixedBytes(sig.randomizer.clone()),
        Token::Uint(U256::from(sig.counter)),
        Token::FixedArray(sig.chains.iter().cloned().map(Token::FixedBytes).collect()),
        Token::Array(sig.auth_path.iter().cloned().map(Token::FixedBytes).collect()),
    ])
}

fn stateless_calldata(vector: &StatelessVector) -> Bytes {
    let selector = &keccak256(b"verify((uint16,uint8,uint8,uint8,uint8,uint16,uint16,uint32),(bytes,bytes,bytes,bytes,bytes,bytes),bytes,((bytes,uint32,(bytes,bytes[])[]),(uint64,uint32,bytes,(bytes,uint32,bytes[]),bytes[])[]))")[0..4];
    let mut out = selector.to_vec();
    out.extend(encode(&[
        params_token(vector.params),
        public_key_token(&vector.public_key),
        Token::Bytes(vector.message.clone()),
        stateless_signature_token(&vector.signature),
    ]));
    Bytes::from(out)
}

fn stateful_calldata(vector: &StatefulVector) -> Bytes {
    let selector = &keccak256(b"verify((bytes32,bytes32,uint32),bytes,(bytes32,uint32,bytes32[64],bytes32[]))")[0..4];
    let mut out = selector.to_vec();
    out.extend(encode(&[
        stateful_public_key_token(&vector.public_key),
        Token::Bytes(vector.message.clone()),
        stateful_signature_token(&vector.signature),
    ]));
    Bytes::from(out)
}

fn hex_prefixed(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
