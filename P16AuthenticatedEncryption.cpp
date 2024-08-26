/*
    P16AuthenticatedEncryption
    based off libcatid's tunnel AuthenticatedEncryption
*/
#include "P16AuthenticatedEncryption.h"
#include "aes.hpp"
#include "hmac_sha256.h"
#include "pkcs7_padding.h"

// defined in P16PacketDecryptor.cpp
void hexdump(const uint8_t* bytes, size_t len);

bool P16AuthenticatedEncryption::Initialize(cat::Skein* key, bool is_initiator)
{
    _is_initiator = is_initiator;
    memset(iv_bitmap, 0, sizeof(iv_bitmap));

    // add key name

    key_hash = new cat::Skein();

    if (!key_hash->SetKey(key)) return false;
    if (!key_hash->BeginKDF()) return false;
    key_hash->CrunchString("NtQuerySystemInformation");
    key_hash->End();

    // generate MAC keys

    cat::Skein kdf;
    if (!kdf.SetKey(key_hash)) return false;
    if (!kdf.BeginKDF()) return false;
    kdf.CrunchString(is_initiator ? "dsound.dll" : "opengl32.dll");
    kdf.End();
    kdf.Generate(local_mac_key, sizeof(local_mac_key));

    if (!kdf.SetKey(key_hash)) return false;
    if (!kdf.BeginKDF()) return false;
    kdf.CrunchString(is_initiator ? "opengl32.dll" : "dsound.dll");
    kdf.End();
    kdf.Generate(remote_mac_key, sizeof(remote_mac_key));

    // generate encryption key

    if (!kdf.SetKey(key_hash)) return false;
    if (!kdf.BeginKDF()) return false;
    kdf.CrunchString("OpenProcessToken");
    kdf.End();
    kdf.Generate(cipher_key, sizeof(cipher_key));

    // random IVs

    if (!kdf.SetKey(key_hash)) return false;
    if (!kdf.BeginKDF()) return false;
    kdf.CrunchString(is_initiator ? "RichEd20.Dll" : "KERNEL32.DLL");
    kdf.End();
    kdf.Generate(&local_iv, sizeof(local_iv));

    if (!kdf.SetKey(key_hash)) return false;
    if (!kdf.BeginKDF()) return false;
    kdf.CrunchString(is_initiator ? "KERNEL32.DLL" : "RichEd20.Dll");
    kdf.End();
    kdf.Generate(&remote_iv, sizeof(remote_iv));

    return true;
}

void P16AuthenticatedEncryption::Dump(const char *filename)
{
    FILE* f = fopen(filename, "wb+");
    fwrite(&_is_initiator, 1, sizeof(_is_initiator), f);
    fwrite(local_mac_key, 1, sizeof(local_mac_key), f);
    fwrite(remote_mac_key, 1, sizeof(remote_mac_key), f);
    fwrite(cipher_key, 1, sizeof(cipher_key), f);
    fwrite(&local_iv, 1, sizeof(local_iv), f);
    fwrite(&remote_iv, 1, sizeof(remote_iv), f);
    fclose(f);
}

void P16AuthenticatedEncryption::InitializeFromDump(const char* filename)
{
    FILE* f = fopen(filename, "rb");
    fread(&_is_initiator, 1, sizeof(_is_initiator), f);
    fread(local_mac_key, 1, sizeof(local_mac_key), f);
    fread(remote_mac_key, 1, sizeof(remote_mac_key), f);
    fread(cipher_key, 1, sizeof(cipher_key), f);
    fread(&local_iv, 1, sizeof(local_iv), f);
    fread(&remote_iv, 1, sizeof(remote_iv), f);
    fclose(f);
}

bool P16AuthenticatedEncryption::IsValidIV(uint64_t iv)
{
    // Check how far in the past this IV is
    int delta = (int)(remote_iv - iv);

    // If it is in the past,
    if (delta >= 0)
    {
        // Check if we have kept a record for this IV
        if (delta >= BITMAP_BITS) return false;

        uint64_t* map = &iv_bitmap[delta >> 6];
        uint64_t mask = (uint64_t)1 << (delta & 63);

        // If it was seen, abort
        if (*map & mask) return false;
    }

    return true;
}

void P16AuthenticatedEncryption::AcceptIV(uint64_t iv)
{
    // Check how far in the past/future this IV is
    int delta = (int)(iv - remote_iv);

    // If it is in the future,
    if (delta > 0)
    {
        // If it would shift out everything we have seen,
        if (delta >= BITMAP_BITS)
        {
            // Set low bit to 1 and all other bits to 0
            iv_bitmap[0] = 1;
            memset(&iv_bitmap[1], 0, sizeof(iv_bitmap) - sizeof(uint64_t));
        }
        else
        {
            int word_shift = delta >> 6;
            int bit_shift = delta & 63;

            // Shift replay window
            uint64_t last = iv_bitmap[BITMAP_WORDS - 1 - word_shift];
            for (int ii = BITMAP_WORDS - 1; ii >= word_shift + 1; --ii)
            {
                uint64_t x = iv_bitmap[ii - word_shift - 1];
                iv_bitmap[ii] = (last << bit_shift) | (x >> (64 - bit_shift));
                last = x;
            }
            iv_bitmap[word_shift] = last << bit_shift;

            // Zero the words we skipped
            for (int ii = 0; ii < word_shift; ++ii)
                iv_bitmap[ii] = 0;

            // Set low bit for this IV
            iv_bitmap[0] |= 1;
        }

        // Only update the IV if the MAC was valid and the new IV is in the future
        remote_iv = iv;
    }
    else // Process an out-of-order packet
    {
        delta = -delta;

        // Set the bit in the bitmap for this IV
        iv_bitmap[delta >> 6] |= (uint64_t)1 << (delta & 63);
    }
}

bool P16AuthenticatedEncryption::Decrypt(uint8_t* buffer, uint32_t& buf_bytes)
{
    if (buf_bytes < OVERHEAD_BYTES) return false;

    uint32_t msg_bytes = buf_bytes - OVERHEAD_BYTES;

    uint8_t* overhead = buffer + msg_bytes;
    // overhead: encrypted { ... MAC(8 bytes) } || truncated IV(3 bytes)

    // De-obfuscate the truncated IV
    uint32_t trunc_iv = ((uint32_t)overhead[MAC_BYTES + 2] << 16) | ((uint32_t)overhead[MAC_BYTES + 1] << 8) | (uint32_t)overhead[MAC_BYTES];
    trunc_iv = IV_MASK & (trunc_iv ^ (*(uint32_t*)overhead) ^ IV_FUZZ);

    // Reconstruct the original, full IV
    uint64_t iv = cat::ReconstructCounter<IV_BITS>(remote_iv, trunc_iv);

    if (!IsValidIV(iv))
    {
        return false;
    }

    // Build the AES IV
    uint8_t aes_iv[0x10];
    memset(aes_iv, 0, sizeof(aes_iv));
    memcpy(aes_iv + 8, &iv, sizeof(iv));

    // Decrypt the message and the MAC
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, cipher_key, aes_iv);
    AES_CBC_decrypt_buffer(&ctx, buffer, buf_bytes - IV_BYTES);
    msg_bytes = pkcs7_padding_data_length(buffer, buf_bytes - IV_BYTES, 16);

    // Generate the expected MAC given the decrypted message and full IV
    uint8_t* mac_buf = (uint8_t *)malloc(sizeof(iv) + msg_bytes - MAC_BYTES);
    if (mac_buf == NULL)
    {
        return false;
    }
    memcpy(mac_buf, &iv, sizeof(iv));
    memcpy(mac_buf + sizeof(iv), buffer, msg_bytes - MAC_BYTES);

    uint8_t expected_mac[MAC_BYTES];
    hmac_sha256(remote_mac_key, sizeof(remote_mac_key), mac_buf, sizeof(iv) + msg_bytes - MAC_BYTES, expected_mac, MAC_BYTES);

    free(mac_buf);

    // Validate the MAC
    if (memcmp(expected_mac, buffer + msg_bytes - MAC_BYTES, MAC_BYTES) != 0)
    {
        //printf("invalid MAC!\n");
        //hexdump(expected_mac, MAC_BYTES);
        //hexdump(buffer + msg_bytes - MAC_BYTES, MAC_BYTES);
        return false;
    }

    AcceptIV(iv);

    // Return the number of message bytes in buf_bytes
    buf_bytes = msg_bytes - MAC_BYTES;
    return true;
}

bool P16AuthenticatedEncryption::DecryptAsRemote(uint8_t* buffer, uint32_t& buf_bytes)
{
    if (buf_bytes < OVERHEAD_BYTES) return false;

    uint32_t msg_bytes = buf_bytes - OVERHEAD_BYTES;

    uint8_t* overhead = buffer + msg_bytes;
    // overhead: encrypted { ... MAC(8 bytes) } || truncated IV(3 bytes)

    // De-obfuscate the truncated IV
    uint32_t trunc_iv = ((uint32_t)overhead[MAC_BYTES + 2] << 16) | ((uint32_t)overhead[MAC_BYTES + 1] << 8) | (uint32_t)overhead[MAC_BYTES];
    trunc_iv = IV_MASK & (trunc_iv ^ (*(uint32_t*)overhead) ^ IV_FUZZ);

    // Reconstruct the original, full IV
    uint64_t iv = cat::ReconstructCounter<IV_BITS>(local_iv, trunc_iv);

    // Build the AES IV
    uint8_t aes_iv[0x10];
    memset(aes_iv, 0, sizeof(aes_iv));
    memcpy(aes_iv + 8, &iv, sizeof(iv));

    // Decrypt the message and the MAC
    AES_ctx ctx;
    AES_init_ctx_iv(&ctx, cipher_key, aes_iv);
    AES_CBC_decrypt_buffer(&ctx, buffer, buf_bytes - IV_BYTES);
    msg_bytes = pkcs7_padding_data_length(buffer, buf_bytes - IV_BYTES, 16);

    // Generate the expected MAC given the decrypted message and full IV
    uint8_t* mac_buf = (uint8_t*)malloc(sizeof(iv) + msg_bytes - MAC_BYTES);
    if (mac_buf == NULL)
    {
        return false;
    }
    memcpy(mac_buf, &iv, sizeof(iv));
    memcpy(mac_buf + sizeof(iv), buffer, msg_bytes - MAC_BYTES);

    uint8_t expected_mac[MAC_BYTES];
    hmac_sha256(local_mac_key, sizeof(local_mac_key), mac_buf, sizeof(iv) + msg_bytes - MAC_BYTES, expected_mac, MAC_BYTES);

    free(mac_buf);

    // Validate the MAC
    if (memcmp(expected_mac, buffer + msg_bytes - MAC_BYTES, MAC_BYTES) != 0)
    {
        //printf("invalid MAC!\n");
        //hexdump(expected_mac, MAC_BYTES);
        //hexdump(buffer + msg_bytes - MAC_BYTES, MAC_BYTES);
        return false;
    }

    local_iv = iv;

    // Return the number of message bytes in buf_bytes
    buf_bytes = msg_bytes - MAC_BYTES;
    return true;
}
