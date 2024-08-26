#pragma once
#include <stdint.h>
#include "cat/AllCrypt.hpp"
class P16AuthenticatedEncryption
{
public:
	// Tunnel overhead bytes
	static const int MAC_BYTES = 0x20;
	static const int IV_BYTES = 3;
	static const uint32_t OVERHEAD_BYTES = IV_BYTES + MAC_BYTES;

	// 1024-bit anti-replay sliding window
	static const int BITMAP_BITS = 1024;
	static const int BITMAP_WORDS = BITMAP_BITS / 64;
	uint64_t iv_bitmap[BITMAP_WORDS];

	// IV constants
	static const int IV_BITS = IV_BYTES * 8;
	static const uint32_t IV_MSB = (1 << IV_BITS);
	static const uint32_t IV_MASK = (IV_MSB - 1);
	static const uint32_t IV_FUZZ = 0xCA7DCA7D;

	cat::Skein *key_hash;

	bool _is_initiator;

	// HMAC-SHA256 keys
	uint8_t local_mac_key[0x20];
	uint8_t remote_mac_key[0x20];

	// AES-128-CBC key
	uint8_t cipher_key[0x10];

	// IV state
	uint64_t local_iv;
	uint64_t remote_iv;

	bool Initialize(cat::Skein *key, bool is_initiator);

	void Dump(const char *filename);
	void InitializeFromDump(const char *filename);

	bool IsValidIV(uint64_t iv);
	void AcceptIV(uint64_t iv);

	bool Decrypt(uint8_t* buffer, uint32_t& buf_bytes);
	bool DecryptAsRemote(uint8_t* buffer, uint32_t& buf_bytes);

	//bool Encrypt(uint8_t* buffer, uint32_t buffer_bytes, uint32_t& msg_bytes);
};

