#pragma once
#include <stdint.h>
#include "cat/AllTunnel.hpp"

typedef unsigned long long Leg;
typedef struct _KeyAgreementInitiator {
    int KeyBits;
    uint32_t KeyBytes;
    uint32_t KeyLegs;
    Leg* B;
    Leg* a;
    Leg* A;
    Leg* hB;
    Leg* G_MultPrecomp;
    Leg* B_MultPrecomp;
    Leg* Y_MultPrecomp;
    Leg* A_neutral;
    Leg* B_neutral;
    Leg* I_private;
    Leg* I_public;
} KeyAgreementInitiator;

typedef struct _RawClientEasyHandshake1 {
    void* tls_math;
    void* tls_csprng;
    KeyAgreementInitiator tun_client;
} RawClientEasyHandshake1;

typedef struct _RawClientEasyHandshake2 {
    cat::BigTwistedEdwards* tls_math;
    void* tls_csprng;
    cat::KeyAgreementInitiator tun_client;
} RawClientEasyHandshake2;
