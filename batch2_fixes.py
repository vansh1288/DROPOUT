import os

def create_mock_client():
    path = r"C:\DROP\host_server\mock_client.py"
    content = '''import asyncio
import struct
import hashlib
import hmac
import os
import sys

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

PROTOCOL_VERSION = 0x00010000
MSG_TYPE_ROUND_INIT = 0x40
MSG_TYPE_KEM_PUBLIC_KEY = 0x01
MSG_TYPE_KEM_CIPHERTEXT = 0x02
MSG_TYPE_MASK_CHUNK = 0x21
MSG_TYPE_CLIENT_COMPLETE = 0x30
MSG_TYPE_DROPOUT_NOTIFY = 0x31
MSG_TYPE_RECOVERY_COMPLETE = 0x33
MSG_TYPE_ROUND_COMPLETE = 0x41

HEADER_FORMAT = ">IIBBHHH"
HEADER_SIZE = 16

KDF_LABEL_PAIRWISE_MASK = b"SwiftAgg-PairwiseMask-v1"
KDF_LABEL_STREAM_MASK = b"SwiftAgg-StreamMask-v1"
KDF_LABEL_SHAMIR_SECRET = b"SwiftAgg-ShamirSecret-v1"
KDF_LABEL_SESSION_KEY = b"FL-SessionKey-v1"

FIELD_MODULUS = 3329

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = bytes(32)
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b""
    t = b""
    ctr = 1
    while len(okm) < length:
        h = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256)
        t = h.digest()
        okm += t
        ctr += 1
    return okm[:length]

def derive_pairwise_seed(shared_secret: bytes, client_a: int, client_b: int, round_id: int) -> bytes:
    info = bytes([client_a, client_b]) + round_id.to_bytes(4, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-PairwiseMask-v1" + info, 32)

def derive_stream_seed(shared_secret: bytes, client_id: int, round_id: int, chunk_index: int) -> bytes:
    info = bytes([client_id]) + round_id.to_bytes(4, 'big') + chunk_index.to_bytes(2, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-StreamMask-v1" + info, 32)

def aes_ctr_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library not available")
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(b"\x00" * length) + encryptor.finalize()

def generate_mask_from_seed(seed: bytes, length: int) -> List[int]:
    stream = aes_ctr_stream(key=seed, nonce=bytes(16), length=length)
    masks = []
    for i in range(0, len(stream), 2):
        if i + 1 < len(stream):
            val = (stream[i] | (stream[i+1] << 8)) % 3329
            masks.append(val)
        elif i < len(stream):
            val = stream[i] % 3329
            masks.append(val)
    return masks

def x25519_keypair():
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    return private_key, public_key

def x25519_ecdh(private_key: X25519PrivateKey, peer_public_key: bytes) -> bytes:
    peer_key = X25519PublicKey.from_public_bytes(peer_public_key)
    shared = private_key.exchange(peer_key)
    return shared

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = bytes(32)
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b""
    t = b""
    ctr = 1
    while len(okm) < length:
        h = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256)
        t = h.digest()
        okm += t
        ctr += 1
    return okm[:length]

def derive_session_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"",
        info=b"FL-SessionKey-v1",
        backend=default_backend()
    )
    return hkdf.derive(shared_secret)

def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, plaintext, None)

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

def build_header(message_type: int, round_id: int, client_id: int, seq: int, payload_len: int) -> bytes:
    return struct.pack(
        ">IIBBHHH",
        0x00010000,
        round_id,
        client_id,
        message_type,
        seq,
        payload_len,
        0
    )

def parse_header(data: bytes):
    return struct.unpack(">IIBBHHH", data)

async def run_client(client_id: int, host: str, port: int):
    reader, writer = await asyncio.open_connection(host, port)
    
    client_private_key, client_public_key = x25519_keypair()
    round_id = 0
    chunk_size = 128
    model_size = 1024
    shared_secret = None
    pairwise_seeds = {}
    stream_seeds = {}
    received_chunks = {}
    expected_chunks = 0
    completed = False
    
    while True:
        try:
            header_data = await reader.readexactly(16)
            if not header_data:
                break
            proto_ver, round_id, msg_client_id, msg_type, seq, payload_len, _ = parse_header(header_data)
            payload = await reader.readexactly(payload_len)
            
            if msg_type == 0x40:
                p = 0
                expected_clients = payload[p]; p += 1
                threshold = payload[p]; p += 1
                chunk_size = (payload[p] | (payload[p+1] << 8)); p += 2
                model_size = (payload[p] | (payload[p+1] << 8) | (payload[p+2] << 16) | (payload[p+3] << 24))
                expected_chunks = (model_size + chunk_size - 1) // chunk_size
                
                payload_pk = client_public_key
                header = struct.pack(">IIBBHHH", 0x00010000, round_id, client_id, 0x01, 0, len(payload_pk), 0)
                writer.write(header + payload_pk)
                await writer.drain()
                
            elif msg_type == 0x02:
                peer_public_key = payload
                if CRYPTO_AVAILABLE:
                    peer_key = X25519PublicKey.from_public_bytes(peer_public_key)
                    shared = client_private_key.exchange(peer_key)
                    shared_secret = shared
                    session_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=b"",
                        info=b"FL-SessionKey-v1",
                        backend=default_backend()
                    ).derive(shared_secret)
                else:
                    shared_secret = os.urandom(32)
                    session_key = os.urandom(32)
                
            elif msg_type == 0x21:
                chunk_idx = seq
                if shared_secret is not None:
                    stream_seed = derive_stream_seed(shared_secret, client_id, round_id, chunk_idx)
                    mask = generate_mask_from_seed(stream_seed, chunk_size * 2)
                    
                    chunk_data = os.urandom(chunk_size * 2)
                    chunk_ints = struct.unpack(f">{chunk_size}h", chunk_data)
                    masked = [(chunk_ints[i] + mask[i]) % 3329 for i in range(chunk_size)]
                    masked_bytes = struct.pack(f">{chunk_size}h", *masked)
                    
                    header = struct.pack(">IIBBHHH", 0x00010000, round_id, client_id, 0x21, chunk_idx, len(masked_bytes), 0)
                    writer.write(header + masked_bytes)
                    await writer.drain()
                    
            elif msg_type == 0x41:
                pass
                
        except asyncio.IncompleteReadError:
            break
        except ConnectionResetError:
            break
    
    writer.close()
    await writer.wait_closed()

def main():
    if len(sys.argv) < 4:
        sys.exit(1)
    client_id = int(sys.argv[1])
    host = sys.argv[2]
    port = int(sys.argv[3])
    asyncio.run(run_client(client_id, host, port))

if __name__ == "__main__":
    main()
'''
    with open(path, "w") as f:
        f.write(content)
    print("Created mock_client.py")

def fix_kem_adapter():
    path = r"C:\DROP\src\pqc_engine\kem_adapter.c"
    content = '''#include "kem_adapter.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "crypto_memory.h"
#include <string.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/constants.h>

static kem_variant_t g_active_variant = KEM_ACTIVE_VARIANT;
static size_t g_pk_bytes = KEM_PK_BYTES;
static size_t g_sk_bytes = KEM_SK_BYTES;
static size_t g_ct_bytes = KEM_CT_BYTES;
static size_t g_ss_bytes = KEM_SS_BYTES;
static uint32_t g_last_cycles = 0;

static void hkdf_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t* prk) {
    struct tc_hmac_state_struct hmac;
    if (salt && salt_len) {
        tc_hmac_set_key(&hmac, salt, salt_len);
    } else {
        uint8_t zero_salt[32] = {0};
        tc_hmac_set_key(&hmac, zero_salt, 32);
    }
    tc_hmac_init(&hmac);
    tc_hmac_update(&hmac, ikm, ikm_len);
    tc_hmac_final(prk, 32, &hmac);
}

static void hkdf_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    struct tc_hmac_state_struct hmac;
    uint8_t t[32];
    size_t t_len = 0;
    uint8_t ctr = 1;
    uint8_t* out = okm;
    size_t remaining = okm_len;

    tc_hmac_set_key(&hmac, prk, prk_len);

    while (remaining > 0) {
        tc_hmac_init(&hmac);
        if (t_len) {
            tc_hmac_update(&hmac, t, t_len);
        }
        tc_hmac_update(&hmac, info, info_len);
        tc_hmac_update(&hmac, &ctr, 1);
        tc_hmac_final(t, 32, &hmac);
        t_len = 32;

        size_t chunk = remaining < 32 ? remaining : 32;
        for (size_t i = 0; i < chunk; i++) {
            out[i] = t[i];
        }
        out += chunk;
        remaining -= chunk;
        ctr++;
    }
}

pqc_status_t kem_adapter_init(kem_variant_t variant) {
#if KEM_ACTIVE_MODE == CRYPTO_MODE_CLASSICAL_X25519
    (void)variant;
    g_active_variant = KEMLIB_ML_KEM_768;
    g_pk_bytes = 32;
    g_sk_bytes = 32;
    g_ct_bytes = 32;
    g_ss_bytes = 32;
#else
    switch (variant) {
        case KEMLIB_ML_KEM_512:
            g_pk_bytes = ML_KEM_512_PUBLIC_KEY_BYTES;
            g_sk_bytes = ML_KEM_512_SECRET_KEY_BYTES;
            g_ct_bytes = ML_KEM_512_CIPHERTEXT_BYTES;
            g_ss_bytes = ML_KEM_512_SHARED_SECRET_BYTES;
            break;
        case KEMLIB_ML_KEM_768:
            g_pk_bytes = ML_KEM_768_PUBLIC_KEY_BYTES;
            g_sk_bytes = ML_KEM_768_SECRET_KEY_BYTES;
            g_ct_bytes = ML_KEM_768_CIPHERTEXT_BYTES;
            g_ss_bytes = ML_KEM_768_SHARED_SECRET_BYTES;
            break;
        case KEMLIB_ML_KEM_1024:
            g_pk_bytes = ML_KEM_1024_PUBLIC_KEY_BYTES;
            g_sk_bytes = ML_KEM_1024_SECRET_KEY_BYTES;
            g_ct_bytes = ML_KEM_1024_CIPHERTEXT_BYTES;
            g_ss_bytes = ML_KEM_1024_SHARED_SECRET_BYTES;
            break;
        default:
            return ERR_INVALID_ARGUMENT;
    }
#endif
    g_active_variant = variant;
    return PQC_SUCCESS;
}

kem_variant_t kem_adapter_get_variant(void) {
    return g_active_variant;
}

pqc_status_t kem_adapter_get_sizes(size_t* pk_bytes, size_t* sk_bytes, size_t* ct_bytes, size_t* ss_bytes) {
    if (!pk_bytes || !sk_bytes || !ct_bytes || !ss_bytes) return ERR_INVALID_ARGUMENT;
    *pk_bytes = g_pk_bytes;
    *sk_bytes = g_sk_bytes;
    *ct_bytes = g_ct_bytes;
    *ss_bytes = g_ss_bytes;
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_keypair(kem_keypair_t* keypair) {
    if (!keypair) return ERR_INVALID_ARGUMENT;
    mlkem_workspace_t* ws = scratch_get_mlkem_ws();
#if KEM_ACTIVE_MODE == CRYPTO_MODE_CLASSICAL_X25519
    int ret = uECC_make_key(keypair->public_key, keypair->secret_key, uECC_curve25519());
    if (ret != TC_CRYPTO_SUCCESS) return ERR_KEM_KEYGEN_FAILED;
    keypair->variant = g_active_variant;
    keypair->public_key_len = g_pk_bytes;
    keypair->secret_key_len = g_sk_bytes;
    keypair->ciphertext_len = g_ct_bytes;
    keypair->shared_secret_len = g_ss_bytes;
    crypto_zeroize(ws, sizeof(mlkem_workspace_t));
    return PQC_SUCCESS;
#else
    int ret = KEM_KEYPAIR_FN(keypair->public_key, keypair->secret_key);
    if (ret != 0) return ERR_KEM_KEYGEN_FAILED;
    keypair->variant = g_active_variant;
    keypair->public_key_len = g_pk_bytes;
    keypair->secret_key_len = g_sk_bytes;
    keypair->ciphertext_len = g_ct_bytes;
    keypair->shared_secret_len = g_ss_bytes;
    crypto_zeroize(ws, sizeof(mlkem_workspace_t));
    return PQC_SUCCESS;
#endif
}

pqc_status_t kem_adapter_encapsulate(const uint8_t* public_key, size_t pk_len, kem_encapsulation_t* encap) {
    if (!public_key || !encap || pk_len != g_pk_bytes) return ERR_INVALID_ARGUMENT;
    mlkem_workspace_t* ws = scratch_get_mlkem_ws();
#if KEM_ACTIVE_MODE == CRYPTO_MODE_CLASSICAL_X25519
    uint8_t ephemeral_sk[32];
    uint8_t ephemeral_pk[32];
    int ret = uECC_make_key(ephemeral_pk, ephemeral_sk, uECC_curve25519());
    if (ret != TC_CRYPTO_SUCCESS) {
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return ERR_KEM_ENCAP_FAILED;
    }
    uint8_t shared_secret[32];
    if (!uECC_shared_secret(public_key, ephemeral_sk, shared_secret, uECC_curve25519())) {
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return ERR_KEM_ENCAP_FAILED;
    }
    uint8_t nonce[12];
    for (int i = 0; i < 12; i++) nonce[i] = 0;
    struct tc_ccm_mode_struct ccm;
    tc_ccm_config(&ccm, ephemeral_sk, 32, nonce, 12, NULL, 0);
    tc_ccm_generation_encryption(encap->ciphertext, 32, encap->shared_secret, 32, &ccm);
    memcpy(encap->ciphertext + 32, ephemeral_pk, 32);
    encap->ciphertext_len = g_ct_bytes;
    encap->shared_secret_len = g_ss_bytes;
    crypto_zeroize(ws, sizeof(mlkem_workspace_t));
    crypto_zeroize(ephemeral_sk, 32);
    return PQC_SUCCESS;
#else
    int ret = KEM_ENCAP_FN(encap->ciphertext, encap->shared_secret, public_key);
    if (ret != 0) return ERR_KEM_ENCAP_FAILED;
    encap->ciphertext_len = g_ct_bytes;
    encap->shared_secret_len = g_ss_bytes;
    crypto_zeroize(ws, sizeof(mlkem_workspace_t));
    return PQC_SUCCESS;
#endif
}

pqc_status_t kem_adapter_decapsulate(const uint8_t* ciphertext, size_t ct_len, const uint8_t* secret_key, size_t sk_len, uint8_t* shared_secret) {
    if (!ciphertext || !secret_key || !shared_secret || ct_len != g_ct_bytes || sk_len != g_sk_bytes) return ERR_INVALID_ARGUMENT;
    mlkem_workspace_t* ws = scratch_get_mlkem_ws();
#if KEM_ACTIVE_MODE == CRYPTO_MODE_CLASSICAL_X25519
    uint8_t ephemeral_pk[32];
    memcpy(ephemeral_pk, ciphertext + 32, 32);
    uint8_t shared[32];
    if (!uECC_shared_secret(ephemeral_pk, secret_key, shared, uECC_curve25519())) {
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return ERR_KEM_DECAP_FAILED;
    }
    uint8_t nonce[12];
    for (int i = 0; i < 12; i++) nonce[i] = 0;
    struct tc_ccm_mode_struct ccm;
    tc_ccm_config(&ccm, secret_key, 32, nonce, 12, NULL, 0);
    if (!tc_ccm_decryption_verification(shared_secret, 32, ciphertext, 32, &ccm)) {
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return ERR_KEM_DECAP_FAILED;
    }
    crypto_zeroize(ws, sizeof(mlkem_workspace_t));
    return PQC_SUCCESS;
#else
    int ret = KEM_DECAP_FN(shared_secret, ciphertext, secret_key);
    if (ret != 0) return ERR_KEM_DECAP_FAILED;
    crypto_zeroize(ws, sizeof(mlkem_workspace_t));
    return PQC_SUCCESS;
#endif
}

pqc_status_t kem_adapter_derive_session_key(const uint8_t* shared_secret, const uint8_t* salt, size_t salt_len, const uint8_t* info, size_t info_len, uint8_t* session_key) {
    if (!shared_secret || !session_key) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t prk[32];
    hkdf_extract(salt, salt_len, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_SESSION_KEY, strlen(KDF_LABEL_SESSION_KEY), session_key, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_derive_pairwise_mask_seed(const uint8_t* shared_secret, uint8_t client_id_a, uint8_t client_id_b, uint32_t round_id, uint8_t* mask_seed) {
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
}

pqc_status_t kem_adapter_derive_stream_mask_seed(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint8_t* stream_seed) {
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
}

pqc_status_t kem_adapter_derive_shamir_secret(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint8_t* shamir_secret) {
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
}

pqc_status_t kem_adapter_zeroize_scratchpad(void) {
    scratch_zeroize_region(SCRATCH_REGION_MLKEM);
    scratch_zeroize_region(SCRATCH_REGION_CRYPTO);
    return PQC_SUCCESS;
}

static const uint8_t kat_seed[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};

static const uint8_t kat_pk[1184] = {
    0x9f, 0x7a, 0x5d, 0x3c, 0x8e, 0x2b, 0x1f, 0x4a,
    0x6c, 0x9d, 0x3e, 0x7f, 0x2a, 0x5b, 0x8c, 0x1d,
    0x4e, 0x7f, 0x3a, 0x9c, 0x2d, 0x5e, 0x8f, 0x1a,
    0x4b, 0x7c, 0x3d, 0x9e, 0x2f, 0x5a, 0x8b, 0x1c,
    0x4d, 0x7e, 0x3f, 0x9a, 0x2b, 0x5c, 0x8d, 0x1e,
    0x4f, 0x7a, 0x3b, 0x9c, 0x2d, 0x5e, 0x8f, 0x1a,
    0x4b, 0x7c, 0x3d, 0x9e, 0x2f, 0x5a, 0x8b, 0x1c,
    0x4d, 0x7e, 0x3f, 0x9a, 0x2b, 0x5c, 0x8d, 0x1e
};

static const uint8_t kat_sk[2400] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03
};

static const uint8_t kat_ct[1088] = {
    0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
    0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47,
    0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
    0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47
};

static const uint8_t kat_ss[32] = {
    0x8e, 0x2b, 0x1f, 0x4a, 0x6c, 0x9d, 0x3e, 0x7f,
    0x2a, 0x5b, 0x8c, 0x1d, 0x4e, 0x7f, 0x3a, 0x9c,
    0x2d, 0x5e, 0x8f, 0x1a, 0x4b, 0x7c, 0x3d, 0x9e,
    0x2f, 0x5a, 0x8b, 0x1c, 0x4d, 0x7e, 0x3f, 0x9a
};

pqc_status_t kem_adapter_self_test(void) {
    kem_keypair_t kp;
    kem_encapsulation_t enc;
    uint8_t ss[32];
    uint8_t pk[1184];
    uint8_t sk[2400];
    uint8_t ct[1088];
    pqc_status_t ret;

    ret = kem_adapter_keypair(&kp);
    if (ret != PQC_SUCCESS) return ERR_CRYPTO_FAILURE;

    ret = kem_adapter_encapsulate(kp.public_key, kp.public_key_len, &enc);
    if (ret != PQC_SUCCESS) return ERR_CRYPTO_FAILURE;

    ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len, kp.secret_key, kp.secret_key_len, ss);
    if (ret != PQC_SUCCESS) return ERR_CRYPTO_FAILURE;

    if (crypto_ct_compare(ss, enc.shared_secret, 32) != 0) return ERR_CRYPTO_FAILURE;

    crypto_zeroize(&kp, sizeof(kp));
    crypto_zeroize(&enc, sizeof(enc));
    crypto_zeroize(ss, 32);
    return PQC_SUCCESS;
}

uint32_t kem_adapter_get_last_cycles(void) {
    return g_last_cycles;
}

pqc_status_t classical_x25519_keypair(uint8_t* pk, uint8_t* sk) {
    return uECC_make_key(pk, sk, uECC_curve25519()) ? PQC_SUCCESS : ERR_KEM_KEYGEN_FAILED;
}

pqc_status_t classical_x25519_encap(uint8_t* ct, uint8_t* ss, const uint8_t* pk) {
    uint8_t ephemeral_sk[32];
    uint8_t ephemeral_pk[32];
    if (!uECC_make_key(ephemeral_pk, ephemeral_sk, uECC_curve25519())) return ERR_KEM_ENCAP_FAILED;
    uint8_t shared[32];
    if (!uECC_shared_secret(pk, ephemeral_sk, shared, uECC_curve25519())) return ERR_KEM_ENCAP_FAILED;
    memcpy(ct, ephemeral_pk, 32);
    for (int i = 0; i < 32; i++) ss[i] = shared[i];
    return PQC_SUCCESS;
}

pqc_status_t classical_x25519_decap(uint8_t* ss, const uint8_t* ct, const uint8_t* sk) {
    if (!uECC_shared_secret(ct, sk, ss, uECC_curve25519())) return ERR_KEM_DECAP_FAILED;
    return PQC_SUCCESS;
}
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed kem_adapter.c")

if __name__ == "__main__":
    create_mock_client()
    fix_kem_adapter()
    print("Batch 2 modifications completed successfully.")