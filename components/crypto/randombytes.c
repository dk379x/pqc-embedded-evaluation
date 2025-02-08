#include <string.h>
#include "esp_random.h"  // Dla esp_random()
#include "randombytes.h"

void randombytes(uint8_t *out, size_t outlen) {
    while (outlen > 0) {
        uint32_t rand_value = esp_random(); // Pobranie losowej liczby 32-bitowej
        size_t bytes_to_copy = (outlen > sizeof(rand_value)) ? sizeof(rand_value) : outlen;
        memcpy(out, &rand_value, bytes_to_copy);
        out += bytes_to_copy;
        outlen -= bytes_to_copy;
    }
}
