import re

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

kem_adapter_path = r'C:\DROP\src\pqc_engine\kem_adapter.c'
content = read_file(kem_adapter_path)

# Fix 1: Update ML-KEM function calls to pass workspace explicitly
# The macros KEM_KEYPAIR_FN, KEM_ENCAP_FN, KEM_DECAP_FN are called without workspace
# We need to pass the workspace pointer to these functions

# For keypair: KEM_KEYPAIR_FN(keypair->public_key, keypair->secret_key)
# Should become: KEM_KEYPAIR_FN(keypair->public_key, keypair->secret_key, ws->data)
content = content.replace(
    'int ret = KEM_KEYPAIR_FN(keypair->public_key, keypair->secret_key);',
    'int ret = KEM_KEYPAIR_FN(keypair->public_key, keypair->secret_key, ws->data);'
)

# For encapsulate: KEM_ENCAP_FN(encap->ciphertext, encap->shared_secret, public_key)
# Should become: KEM_ENCAP_FN(encap->ciphertext, encap->shared_secret, public_key, ws->data)
content = content.replace(
    'int ret = KEM_ENCAP_FN(encap->ciphertext, encap->shared_secret, public_key);',
    'int ret = KEM_ENCAP_FN(encap->ciphertext, encap->shared_secret, public_key, ws->data);'
)

# For decapsulate: KEM_DECAP_FN(shared_secret, ciphertext, secret_key)
# Should become: KEM_DECAP_FN(shared_secret, ciphertext, secret_key, ws->data)
content = content.replace(
    'int ret = KEM_DECAP_FN(shared_secret, ciphertext, secret_key);',
    'int ret = KEM_DECAP_FN(shared_secret, ciphertext, secret_key, ws->data);'
)

# Fix 2: HKDF context separation - use constructed info buffers instead of bare labels
# The info buffers are already constructed but not used. Fix the hkdf_expand calls.

# kem_adapter_derive_session_key: uses info parameter from caller, keep as is but ensure it uses the info properly
# Current: hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_SESSION_KEY, strlen(KDF_LABEL_SESSION_KEY), session_key, 32);
# Should use the passed info parameter
content = content.replace(
    'hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_SESSION_KEY, strlen(KDF_LABEL_SESSION_KEY), session_key, 32);',
    'hkdf_expand(prk, 32, info, info_len, session_key, 32);'
)

# kem_adapter_derive_pairwise_mask_seed: uses constructed info but passes label
# Current: hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_PAIRWISE_MASK, strlen(KDF_LABEL_PAIRWISE_MASK), mask_seed, 32);
# Should use: hkdf_expand(prk, 32, info, info_len, mask_seed, 32);
# But need to prepend the label to info as per RFC: label || round_id || client_A || client_B
# The current info buffer has: client_a, client_b, round_id (4 bytes)
# Need to construct: label || round_id (4 bytes) || client_A || client_B
# So we need to rebuild the info buffer properly

# Let's fix the pairwise function entirely
old_pairwise = '''pqc_status_t kem_adapter_derive_pairwise_mask_seed(const uint8_t* shared_secret, uint8_t client_id_a, uint8_t client_id_b, uint32_t round_id, uint8_t* mask_seed) {
    if (!shared_secret || !mask_seed) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[64];
    size_t info_len = 0;
    info[info_len++] = client_id_a;
    info[info_len++] = client_id_b;
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_PAIRWISE_MASK, strlen(KDF_LABEL_PAIRWISE_MASK), mask_seed, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}'''

new_pairwise = '''pqc_status_t kem_adapter_derive_pairwise_mask_seed(const uint8_t* shared_secret, uint8_t client_id_a, uint8_t client_id_b, uint32_t round_id, uint8_t* mask_seed) {
    if (!shared_secret || !mask_seed) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[80];
    size_t info_len = 0;
    const uint8_t* label = (const uint8_t*)KDF_LABEL_PAIRWISE_MASK;
    size_t label_len = strlen(KDF_LABEL_PAIRWISE_MASK);
    for (size_t i = 0; i < label_len; i++) info[info_len++] = label[i];
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    info[info_len++] = client_id_a;
    info[info_len++] = client_id_b;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, info, info_len, mask_seed, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}'''

content = content.replace(old_pairwise, new_pairwise)

# Fix stream mask seed
old_stream = '''pqc_status_t kem_adapter_derive_stream_mask_seed(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint8_t* stream_seed) {
    if (!shared_secret || !stream_seed) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[64];
    size_t info_len = 0;
    info[info_len++] = client_id;
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    info[info_len++] = (chunk_index >> 8) & 0xFF;
    info[info_len++] = chunk_index & 0xFF;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_STREAM_MASK, strlen(KDF_LABEL_STREAM_MASK), stream_seed, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}'''

new_stream = '''pqc_status_t kem_adapter_derive_stream_mask_seed(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint8_t* stream_seed) {
    if (!shared_secret || !stream_seed) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[80];
    size_t info_len = 0;
    const uint8_t* label = (const uint8_t*)KDF_LABEL_STREAM_MASK;
    size_t label_len = strlen(KDF_LABEL_STREAM_MASK);
    for (size_t i = 0; i < label_len; i++) info[info_len++] = label[i];
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    info[info_len++] = client_id;
    info[info_len++] = (chunk_index >> 8) & 0xFF;
    info[info_len++] = chunk_index & 0xFF;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, info, info_len, stream_seed, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}'''

content = content.replace(old_stream, new_stream)

# Fix shamir secret
old_shamir = '''pqc_status_t kem_adapter_derive_shamir_secret(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint8_t* shamir_secret) {
    if (!shared_secret || !shamir_secret) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[64];
    size_t info_len = 0;
    info[info_len++] = client_id;
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_SHAMIR_SECRET, strlen(KDF_LABEL_SHAMIR_SECRET), shamir_secret, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}'''

new_shamir = '''pqc_status_t kem_adapter_derive_shamir_secret(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint8_t* shamir_secret) {
    if (!shared_secret || !shamir_secret) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[80];
    size_t info_len = 0;
    const uint8_t* label = (const uint8_t*)KDF_LABEL_SHAMIR_SECRET;
    size_t label_len = strlen(KDF_LABEL_SHAMIR_SECRET);
    for (size_t i = 0; i < label_len; i++) info[info_len++] = label[i];
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    info[info_len++] = client_id;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, info, info_len, shamir_secret, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}'''

content = content.replace(old_shamir, new_shamir)

write_file(kem_adapter_path, content)
print("Modified kem_adapter.c successfully")

# Also need to update kem_adapter.h to reflect the session_key function signature change
# The session_key function currently takes info and info_len but the implementation was ignoring them
# Now it uses them, so the signature is already correct.

# Verify the changes
updated_content = read_file(kem_adapter_path)
print("--- Updated kem_adapter.c key sections ---")
# Print the modified functions
for func_name in ['kem_adapter_keypair', 'kem_adapter_encapsulate', 'kem_adapter_decapsulate', 
                  'kem_adapter_derive_session_key', 'kem_adapter_derive_pairwise_mask_seed',
                  'kem_adapter_derive_stream_mask_seed', 'kem_adapter_derive_shamir_secret']:
    idx = updated_content.find(func_name)
    if idx >= 0:
        end_idx = updated_content.find('\n\n', idx)
        if end_idx == -1:
            end_idx = idx + 500
        print(updated_content[idx:end_idx])
        print("---")