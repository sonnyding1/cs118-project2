#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool is_client = false;
static char* host = NULL;
static bool is_handshake_done = false;

static bool is_client_hello_sent = false;
static bool is_server_hello_received = false;
static bool is_client_hello_received = false;
static bool is_finished_received = false;

static EVP_PKEY *peer_pubkey = NULL;
static uint8_t client_nonce[NONCE_SIZE];
static uint8_t server_nonce[NONCE_SIZE];
static uint8_t secret[SECRET_SIZE];
static uint8_t enc_key[SECRET_SIZE];
static uint8_t mac_key[SECRET_SIZE];


ssize_t send_client_hello(uint8_t* buf, size_t max_length) {
    tlv *client_hello = create_tlv(CLIENT_HELLO);
    
    generate_nonce(client_nonce, NONCE_SIZE);
    tlv *nonce_tlv = create_tlv(NONCE);
    add_val(nonce_tlv, client_nonce, NONCE_SIZE);
    add_tlv(client_hello, nonce_tlv);
    
    generate_private_key();
    derive_public_key();
    
    tlv *pubkey_tlv = create_tlv(PUBLIC_KEY);
    add_val(pubkey_tlv, public_key, pub_key_size);
    add_tlv(client_hello, pubkey_tlv);
    
    size_t len = serialize_tlv(buf, client_hello);

    fprintf(stderr, "ClientHello TLV structure:\n");
    print_tlv_bytes(buf, len);

    output_io(buf, len);
    free_tlv(client_hello);
    
    return len;
}

void send_server_hello(uint8_t* buf, size_t max_length) {
    
}

void send_finish(uint8_t* buf, size_t max_length) {
    
}

void unpack_client_hello(uint8_t* buf, size_t length) {

}

void unpack_server_hello(uint8_t* buf, size_t length) {

}

void unpack_finish(uint8_t* buf, size_t length) {
    
}

void init_sec(int type, char* host) {
    init_io();
    is_client = type == CLIENT;
    host = host;
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    if (!is_handshake_done) {
        if (is_client) {
            if (!is_client_hello_sent) {
                ssize_t len = send_client_hello(buf, max_length);
                is_client_hello_sent = true;
                return len;
            } 
            else if (is_server_hello_received) {
                send_finish(buf, max_length);
                is_handshake_done = true;
            }
        } else {
            if (is_server_hello_received) {
                send_server_hello(buf, max_length);
            }
        }
    }
    else {
        return input_io(buf, max_length);
    }
}

void output_sec(uint8_t* buf, size_t length) {
    if (!is_handshake_done) {
        if (is_client) {
            if (!is_server_hello_received) {
                unpack_server_hello(buf, length);
                is_server_hello_received = true;
            }
        } else {
            if (!is_client_hello_received) {
                unpack_client_hello(buf, length);
                is_client_hello_received = true;
            }
            else if (!is_finished_received) {
                unpack_finish(buf, length);
                is_finished_received = true;
                is_handshake_done = true;
            }
        }
    } else {
        output_io(buf, length);
    }
}

