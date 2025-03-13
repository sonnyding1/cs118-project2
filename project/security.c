#include "consts.h"
#include "io.h"
#include "libsecurity.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

bool is_client = false;
bool is_handshake_done = false;

bool is_client_hello_sent = false;
bool is_server_hello_received = false;
bool is_client_hello_received = false;
bool is_finished_receive = false;

void init_sec(int type, char* host) {
    init_io();
}

ssize_t input_sec(uint8_t* buf, size_t max_length) {
    
    return input_io(buf, max_length);
}

void output_sec(uint8_t* buf, size_t length) {
    output_io(buf, length);
}

