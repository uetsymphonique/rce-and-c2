#pragma once

#include <cstdint>

struct xorshift64_state {
    uint64_t s;
};

inline void xorshift64_seed(xorshift64_state* state, uint64_t seed) {
    if (seed == 0) {
        seed = 1;
    }
    state->s = seed;
}

inline uint64_t xorshift64_next(xorshift64_state* state) {
    uint64_t x = state->s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state->s = x;
    return x;
}
