# P16PacketDecryptor

preserving the present p16 for potential prospective packet/protocol probing

## usage

`P16PacketDecryptor.exe packets.pcapng keys.ini output.pcapng`

packets.pcapng must be a PCAPNG format file containing exclusively UDP packets captured from P16 - you can filter in Wireshark by `raknet` and then export all visible packets

keys.ini must contain a ClientPrivateKey for each connection made in packets.pcapng

```ini
; ClientPrivateKey = KeyAgreementInitiator->a, THIS MUST BE DUMPED FROM RAM!
[KeyExchange]
ClientPrivateKey = ddb046b642535bd2101b65779da30f2954f88f9c3a9fb615d6d2f4dd101d363b
ClientPrivateKey = cb909255c37db9f2c1369b47780683aee246f0458cab054fe265187edcd1f113
ClientPrivateKey = ...
```

output.pcapng will be an effective re-creation of packets.pcapng with the encryption stripped so all packets are in their plaintext RakNet format

## obtaining keys

to obtain the private key you need a system that can both connect to online services and have its ram studied during connection establishment. the key is cleared after the response. good luck

TODO: support providing the Skein key or key_hash so RAM taken after connection can be used

## details of encryption

key establishment between client and server follows the "tabby" protocol from libcat's EasyHandshake/KeyAgreement implementaion, validating the public key with a key granted by the s\*\*p server, but diverges from it at the AuthenticatedEncryption stage:

packets are encrypted with 128-bit AES in CBC mode, with a key shared between client and server, padded with PKCS7. the IV is different between client and server.

packets are authenticated with a HMAC-SHA256 over the IV and decrypted packet, the key used is different on the client and the server and the MAC is also encrypted with the above AES key.

see P16AuthenticatedEncryption.cpp for more information

```
+----------------+--------------------------------------+---------------------+
|  packet body   | 32-byte HMAC-SHA256 over packet body | truncated 24-bit IV |
+----------------+--------------------------------------+---------------------+
|      AES encrypted with shared client/server key      | XOR with encry HMAC |
+-------------------------------------------------------+---------------------+
```

as for the origin? i'm not entirely sure - RakNet public sources make no mention of an AES/HMAC-SHA256-based encryption scheme. i think it's custom made for P16.

## raknet compatibility

in theory if you adjusted the main code to use cat::AuthenticatedEncryption instead of P16AuthenticatedEncryption you can use it to decrypt regular RakNet packets

## libraries

tiny-AES-c for AES encryption (Public domain): https://github.com/kokke/tiny-AES-c - included in repo

tiny-AES128-c for PKCS7 implementation (Public domain): https://github.com/bonybrown/tiny-AES128-C - included in repo

hmac_sha256 for HMAC-SHA256 (Public domain): https://github.com/h5p9sl/hmac_sha256 - included in repo, uses code from WjCryptLib, also public domain

inih for INI parsing (New BSD license): https://github.com/benhoyt/inih - included in repo

libcatid for KeyAgreement, EasyHandshake and Skein implementation (BSD-style license): https://github.com/catid/libcatid - commit `19d5367`, compile Common, Crypt, Math and Tunnel in /MT mode and put in "libcat" folder along with "cat" folder for includes, "lib/cat/big_x64.lib" is also required

LightPcapNg for PCAPNG read/write (MIT licensed): https://github.com/rvelea/LightPcapNg - commit `bbde802`, copy src and include folders into "lightpcapng" folder
