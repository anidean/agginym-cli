/*
* Creative Commons License Attribution-NonCommercial-ShareAlike 3.0 Unported (CC BY-NC-SA 3.0)
*
* This is a human-readable summary of the Legal Code.
*
* You are free:
*
*    to Share — to copy, distribute and transmit the work
*    to Remix — to adapt the work
*
* Under the following conditions:
*
*    Attribution — You must attribute the work in the manner specified by the author or licensor (but not in any way that suggests that they endorse you or your use of the work).
*
*    Noncommercial — You may not use this work for commercial purposes.
*
*    Share Alike — If you alter, transform, or build upon this work, you may distribute the resulting work only under the same or similar license to this one.
*
* With the understanding that:
*
*    Waiver — Any of the above conditions can be waived if you get permission from the copyright holder.
*    Public Domain — Where the work or any of its elements is in the public domain under applicable law, that status is in no way affected by the license.
*    Other Rights — In no way are any of the following rights affected by the license:
*        Your fair dealing or fair use rights, or other applicable copyright exceptions and limitations;
*        The author's moral rights;
*        Rights other persons may have either in the work itself or in how the work is used, such as publicity or privacy rights.
*    Notice — For any reuse or distribution, you must make clear to others the license terms of this work. The best way to do this is with a link to this web page.
*
* For details and the full license text, see http://creativecommons.org/licenses/by-nc-sa/3.0/
*/
#include <iostream>
#include <sodium.h>
#include <algorithm>
#include <memory>
#include <map>
#include <unistd.h>
#include <string>
#include "fmt/format.h"
#include "rapidjson/document.h"

namespace rap = rapidjson;

// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch) {
        return !std::isspace(ch) && ch != '\0';
    }).base(), s.end());
}

std::string keypairTemplate = R"(
{{
  "name": "{}",
  "publicKey":"{}",
  "privateKey":"{}"
}}
)";


namespace salty {
  // print debug stuff, otherwise only print the final output
  bool loud = false;

  void print(std::string stuff){
    if (loud){
      fmt::print("{}\n", stuff);
    }
  }
  static const char b58digits_ordered[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";


  /*
   * Copyright 2012-2014 Luke Dashjr
   * MIT license.  See COPYING for more details.
   * The Base58 stuff is from Luke, good guy.
   * https://github.com/luke-jr/libbase58/blob/master/base58.c
   */
  bool bin2base58(char *b58, size_t *b58sz, const void *data, size_t binsz){
    const uint8_t *bin = (uint8_t*)data;
    int carry;
    ssize_t i, j, high, zcount = 0;
    size_t size;
    
    while (zcount < binsz && !bin[zcount])
      ++zcount;
    
    size = (binsz - zcount) * 138 / 100 + 1;
    uint8_t buf[size];
    memset(buf, 0, size);
    
    for (i = zcount, high = size - 1; i < binsz; ++i, high = j)
    {
      for (carry = bin[i], j = size - 1; (j > high) || carry; --j)
      {
        carry += 256 * buf[j];
        buf[j] = carry % 58;
        carry /= 58;
      }
    }
    
    for (j = 0; j < size && !buf[j]; ++j);
    
    if (*b58sz <= zcount + size - j)
    {
      *b58sz = zcount + size - j + 1;
      return false;
    }
    
    if (zcount)
      memset(b58, '1', zcount);
    for (i = zcount; j < size; ++i, ++j)
      b58[i] = b58digits_ordered[buf[j]];
    b58[i] = '\0';
    *b58sz = i + 1;
    
    return true;
  }

  static const int8_t b58digits_map[] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1,
  };

  bool base582bin(void *bin, size_t *binszp, const char *b58, size_t b58sz)
  {
    size_t binsz = *binszp;
    const unsigned char *b58u = (const unsigned char*)b58;
    unsigned char *binu = (unsigned char*)bin;
    size_t outisz = (binsz + 3) / 4;
    uint32_t outi[outisz];
    uint64_t t;
    uint32_t c;
    size_t i, j;
    uint8_t bytesleft = binsz % 4;
    uint32_t zeromask = bytesleft ? (0xffffffff << (bytesleft * 8)) : 0;
    unsigned zerocount = 0;
    
    if (!b58sz)
      b58sz = strlen(b58);
    
    memset(outi, 0, outisz * sizeof(*outi));
    
    // Leading zeros, just count
    for (i = 0; i < b58sz && b58u[i] == '1'; ++i)
      ++zerocount;
    
    for ( ; i < b58sz; ++i)
    {
      if (b58u[i] & 0x80)
        // High-bit set on invalid digit
        return false;
      if (b58digits_map[b58u[i]] == -1)
        // Invalid base58 digit
        return false;
      c = (unsigned)b58digits_map[b58u[i]];
      for (j = outisz; j--; )
      {
        t = ((uint64_t)outi[j]) * 58 + c;
        c = (t & 0x3f00000000) >> 32;
        outi[j] = t & 0xffffffff;
      }
      if (c)
        // Output number too big (carry to the next int32)
        return false;
      if (outi[0] & zeromask)
        // Output number too big (last int32 filled too far)
        return false;
    }
    
    j = 0;
    switch (bytesleft) {
      case 3:
        *(binu++) = (outi[0] &   0xff0000) >> 16;
      case 2:
        *(binu++) = (outi[0] &     0xff00) >>  8;
      case 1:
        *(binu++) = (outi[0] &       0xff);
        ++j;
      default:
        break;
    }
    
    for (; j < outisz; ++j)
    {
      *(binu++) = (outi[j] >> 0x18) & 0xff;
      *(binu++) = (outi[j] >> 0x10) & 0xff;
      *(binu++) = (outi[j] >>    8) & 0xff;
      *(binu++) = (outi[j] >>    0) & 0xff;
    }
    
    // Count canonical base58 byte count
    binu = (unsigned char*)bin;
    for (i = 0; i < binsz; ++i)
    {
      if (binu[i])
        break;
      --*binszp;
    }
    *binszp += zerocount;
    
    return true;
  }

  uint8_t publicKey[crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES+100] = {0};
  size_t publicKeyLength = 0;
  uint8_t secretKey[crypto_sign_SECRETKEYBYTES +crypto_box_SECRETKEYBYTES+crypto_box_PUBLICKEYBYTES+100] = {0};
  size_t secretKeyLength = 0;

  uint8_t* publicKeyString = nullptr;
  uint8_t* secretKeyString = nullptr;

  bool DataToBase64(std::string_view data, std::string& data64){
    data64.resize(sodium_base64_encoded_len(data.length(), sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');

    if (sodium_bin2base64(data64.data(), data64.length(),
                     (const unsigned char*)data.data(), data.length(),
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING) == NULL){
      return false;
    }
    return true;
  }

  uint64_t DataFromBase64(std::string_view data64, uint8_t*& data){
    uint64_t dataLength = data64.length();
    data = (uint8_t*)calloc(dataLength, sizeof(uint8_t));

    int err = sodium_base642bin((unsigned char*)data, dataLength,
                          data64.data(), data64.length(),
                          NULL, &dataLength,
                          NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (!err){
      data = (uint8_t*)realloc(data, dataLength);
    }
    else{
      free(data);
      data = nullptr;
      return 0;
    }

    return dataLength;
  }

  int GetPrivateKeyFromBase64(std::string_view privateKey64, uint8_t*& privateKey){
    uint64_t privateKeyBytesLength = crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES+100;
    privateKey = (uint8_t*)calloc(privateKeyBytesLength, sizeof(uint8_t));

    int err = sodium_base642bin((unsigned char*)privateKey, privateKeyBytesLength,
                          privateKey64.data(), privateKey64.length(),
                          NULL, &privateKeyBytesLength,
                          NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (!err){
      privateKey = (uint8_t*)realloc(privateKey, privateKeyBytesLength);
    }
    else{
      free(privateKey);
      privateKey = nullptr;
      return 0;
    }

    return privateKeyBytesLength;
  }

  int GetPublicKeyFromBase64(std::string_view publicKey64, uint8_t*& publicKey){
    uint64_t publicKeyBytesLength = crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES+100;
    publicKey = (uint8_t*)calloc(publicKeyBytesLength, sizeof(uint8_t));
    //publicKey.resize(publicKeyBytesLength, '\0');

    int err = sodium_base642bin((unsigned char*)publicKey, publicKeyBytesLength,
                          publicKey64.data(), publicKey64.length(),
                          NULL, &publicKeyBytesLength,
                          NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    if (!err){
      publicKey = (uint8_t*)realloc(publicKey, publicKeyBytesLength);
    }
    else{
      free(publicKey);
      publicKey = nullptr;
      return 0;
    }
    return publicKeyBytesLength;
  }

  // strings are ok because of base64. 
  struct PublicKey {
    std::string signature = "";
    std::string verifyingKey = "";
    std::string encryptingKey = "";
    std::string name = "";
  };

  PublicKey* PublicKeyComponentsToBase64(std::string_view& publicKeyBytes){
    PublicKey* pks = new PublicKey();
    pks->signature.resize(sodium_base64_encoded_len(crypto_sign_BYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    pks->verifyingKey.resize(sodium_base64_encoded_len(crypto_sign_PUBLICKEYBYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    pks->encryptingKey.resize(sodium_base64_encoded_len(crypto_box_PUBLICKEYBYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    pks->name.resize(publicKeyBytes.length()-(crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES+1), '\0');

    memcpy(pks->name.data(), publicKeyBytes.data()+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES+1, pks->name.length());
    pks->name.resize(strlen(pks->name.c_str()));
    //print(fmt::format("\nNAME LENGTH: {}, {} \n", pks->name.length(), strlen(pks->name.c_str())));
    sodium_bin2base64(pks->signature.data(), pks->signature.length(),
                     (const unsigned char*)publicKeyBytes.data(), crypto_sign_BYTES,
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    sodium_bin2base64(pks->verifyingKey.data(), pks->verifyingKey.length(),
                     (const unsigned char*)publicKeyBytes.data()+crypto_sign_BYTES, crypto_sign_PUBLICKEYBYTES,
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    sodium_bin2base64(pks->encryptingKey.data(), pks->encryptingKey.length(),
                     (const unsigned char*)publicKeyBytes.data() + crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES,
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return pks;
  }

  // strings are ok because it's base64
  struct PrivateKey{
    std::string signingKey = "";
    std::string decryptingKey = "";
    std::string encryptingKey = "";
    std::string name = "";
  };

  void PrintPublicKey(std::unique_ptr<PublicKey> pk){
    fmt::print("\nPublic Key--\n");
    fmt::print("Name: {}\nSignature: {}\nVerifying Key: {}\nEncrypting Key: {}\n",
                            pk->name, pk->signature, pk->verifyingKey, pk->encryptingKey);
  }

  void PrintPrivateKey(std::unique_ptr<PrivateKey> pk){
    fmt::print("\nPrivate Key--\n");
    fmt::print("Name: {}\nSigning Key: {}\nDecrypting Key: {}\nEncrypting Key: {}\n",
                            pk->name, pk->signingKey, pk->decryptingKey, pk->encryptingKey);
  }

  bool IsPublicKey(std::string_view key){
    // 1 = public key, 0 private key
    uint8_t value = key[crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES+crypto_box_PUBLICKEYBYTES];
    print(fmt::format("pub value: {}\n", value));
    return value;
  }

  PrivateKey* PrivateKeyComponentsToBase64(std::string_view privateKeyBytes){
    PrivateKey* pks = new PrivateKey();
    pks->signingKey.resize(sodium_base64_encoded_len(crypto_sign_SECRETKEYBYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    pks->decryptingKey.resize(sodium_base64_encoded_len(crypto_box_SECRETKEYBYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    pks->encryptingKey.resize(sodium_base64_encoded_len(crypto_box_PUBLICKEYBYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');

    pks->name.resize(privateKeyBytes.length()-(crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES+1), '\0');
    memcpy(pks->name.data(), privateKeyBytes.data()+crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES+crypto_box_PUBLICKEYBYTES+1, pks->name.length());
    pks->name.resize(strlen(pks->name.c_str()));

    sodium_bin2base64(pks->signingKey.data(), pks->signingKey.length(),
                     (const unsigned char*)privateKeyBytes.data(), crypto_sign_SECRETKEYBYTES,
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    sodium_bin2base64(pks->decryptingKey.data(), pks->decryptingKey.length(),
                     (const unsigned char*)privateKeyBytes.data()+crypto_sign_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES,
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    sodium_bin2base64(pks->encryptingKey.data(), pks->encryptingKey.length(),
                     (const unsigned char*)privateKeyBytes.data()+crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES, crypto_box_SECRETKEYBYTES,
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    return pks;
  }

  std::pair<std::string,std::string> CreateKeyPair(std::string_view name){
    unsigned long long paddedNameLength = std::min((size_t)name.length(), (size_t)100);
    unsigned char paddedName[100] = {'\0'};
    //print(fmt::format("Name: {}\n", name.data()));
    memcpy(paddedName, name.data(), paddedNameLength);

    unsigned char pk[crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES
                    + crypto_box_PUBLICKEYBYTES + 1 + paddedNameLength] = {0};
    unsigned char sk[crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES+crypto_box_PUBLICKEYBYTES
                    + 1 + paddedNameLength] = {0};
    uint8_t pub = '\1';
    memcpy(pk+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES, &pub, 1);
    memcpy(pk+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES+1, paddedName, paddedNameLength);
    memcpy(sk+crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES+crypto_box_PUBLICKEYBYTES+1, paddedName, paddedNameLength);

    //fmt::print ("pub check: s {}, p {} \n", IsPublicKey((const char*)sk), IsPublicKey((const char*)pk));
    crypto_sign_keypair(pk+crypto_sign_BYTES, sk);
    crypto_box_keypair(pk+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES, sk+crypto_sign_SECRETKEYBYTES);
    memcpy(sk+crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES, pk+crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
    unsigned long long signed_message_len;

    crypto_sign(pk, &signed_message_len, pk+crypto_sign_BYTES, 
                crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES+1+paddedNameLength, sk);
    std::string publicKey64(sodium_base64_encoded_len(signed_message_len, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    std::string privateKey64(sodium_base64_encoded_len(crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES+crypto_box_PUBLICKEYBYTES+1+paddedNameLength, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    sodium_bin2base64(publicKey64.data(), publicKey64.length(),
                     pk, crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES+1+paddedNameLength,
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    sodium_bin2base64(privateKey64.data(), privateKey64.length(),
                     sk, crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES+crypto_box_PUBLICKEYBYTES+1+paddedNameLength,
                     sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    return {publicKey64, privateKey64};
  }

  bool GetFingerprint(std::string& fingerprint58, std::string_view keyOrKeyPair){
    rap::Document doc;
    rap::ParseResult ok = doc.Parse(keyOrKeyPair.data());
    // Check for keypair.  Need to check validity
  
    uint8_t* publicKey = nullptr;
    uint64_t publicKeyLength = 0;
    if (!ok.IsError() && doc.IsObject()){
      print(fmt::format("inspecting keypair\n"));

      // Both should exist otherwise fail out.
      if (!doc.HasMember("publicKey") || !doc.HasMember("privateKey")){
        print(fmt::format("The keypair could not be validated.\n"));
        exit(1);
      }

      // Get the Public Key
      publicKey = nullptr;
      publicKeyLength = GetPublicKeyFromBase64(doc["publicKey"].GetString(), publicKey);
      if (!publicKeyLength){
        print(fmt::format("Could not parse the keypair's Public Key\n"));
        exit(1);
      }
    }

    // It's a single key, set it
    if (!publicKeyLength){
      publicKeyLength = keyOrKeyPair.size();
      publicKey = (uint8_t*)calloc(publicKeyLength, sizeof(uint8_t));

      int err = sodium_base642bin(publicKey, publicKeyLength,
                            keyOrKeyPair.data(), keyOrKeyPair.length(),
                            NULL, &publicKeyLength,
                            NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
      if(err){
        print(fmt::format("could not convert publicKey base64 to binary -  Error: {}\n", err));
        free(publicKey);
        publicKey = nullptr;
        return false;
      }
      publicKey = (uint8_t*)realloc(publicKey, publicKeyLength);
    }


    unsigned char hash[crypto_generichash_BYTES];
    crypto_generichash(hash,  crypto_generichash_BYTES,
                   publicKey, publicKeyLength,
                   NULL, 0);

    size_t fingerprint58Length = 145;
    size_t length = fingerprint58.length();
    fingerprint58.resize(length+50);

    bool success = bin2base58(fingerprint58.data()+length, &fingerprint58Length, hash, crypto_generichash_BYTES);

    fingerprint58.resize(length+fingerprint58Length);
    rtrim(fingerprint58);
    return success;
  }

  void Inspect(std::string_view keyOrKeyPair){
    rap::Document doc;
    rap::ParseResult ok = doc.Parse(keyOrKeyPair.data());
    // Check for keypair.  Need to check validity even if keypair was specified
  
    if (!ok.IsError() && doc.IsObject()){
      print(fmt::format("inspecting keypair\n"));
      // Needs both otherwise fail out.
      if (!doc.HasMember("publicKey") || !doc.HasMember("privateKey")){
        print(fmt::format("The keypair could not be validated.\n"));
        exit(1);
      }

      // Get the Public Key
      uint8_t* publicKey = nullptr;
      uint64_t publicKeyLength = GetPublicKeyFromBase64(doc["publicKey"].GetString(), publicKey);
      if (!publicKeyLength){
        print(fmt::format("Could not parse the keypair's Public Key\n"));
        exit(1);
      }
      std::string_view publicKeyStringView((const char*)publicKey, publicKeyLength);

      // Get the Private Key
      uint8_t* privateKey = nullptr;
      uint64_t privateKeyLength = GetPrivateKeyFromBase64(doc["privateKey"].GetString(), privateKey);
      if(!privateKeyLength){
        print(fmt::format("Could not parse the keypair's Private Key\n"));
        exit(1);
      }
      std::string_view privateKeyStringView((const char*)privateKey, privateKeyLength);

      // Get the components then print
      std::unique_ptr<PublicKey> publicKeyComponents(PublicKeyComponentsToBase64(publicKeyStringView));
      PrintPublicKey(std::move(publicKeyComponents));
      std::unique_ptr<PrivateKey> privateKeyComponents(PrivateKeyComponentsToBase64(privateKeyStringView));
      PrintPrivateKey(std::move(privateKeyComponents));
      return;
    }
    print(fmt::format("pub {}, priv {}", crypto_sign_BYTES+crypto_sign_PUBLICKEYBYTES+crypto_box_PUBLICKEYBYTES, 
      crypto_sign_SECRETKEYBYTES+crypto_box_SECRETKEYBYTES+crypto_box_PUBLICKEYBYTES));
    // It's not an object, dealing with a single key,
    uint8_t* unknownKey = nullptr;
    uint64_t keyLength = DataFromBase64(keyOrKeyPair, unknownKey);
    if (!keyLength){
      print(fmt::format("Could not parse the key\n"));
      exit(1);
    }
    std::string_view keyStringView((const char*)unknownKey, keyLength);

    // Get the components and print
    if (IsPublicKey(keyStringView)){
      std::unique_ptr<PublicKey> publicKeyComponents(PublicKeyComponentsToBase64(keyStringView));
      PrintPublicKey(std::move(publicKeyComponents));
    }
    else{
      std::unique_ptr<PrivateKey> privateKeyComponents(PrivateKeyComponentsToBase64(keyStringView));
      PrintPrivateKey(std::move(privateKeyComponents));
    }
    free((uint8_t*)keyStringView.data());
  }

  bool VerifyCombined(std::string_view signedMessage, unsigned char* unsignedMessage, std::string_view inPublicKey, bool is64){
    unsigned char* publicKey = nullptr;
    unsigned long long messageLength;

    if(is64){
      //INFO("is 64");
      //publicKey = (unsigned char*)malloc(crypto_sign_PUBLICKEYBYTES);
      publicKey = (unsigned char*)malloc(inPublicKey.length());
      unsigned char* publicKeyEnd = nullptr;
      int err = sodium_base642bin(publicKey, inPublicKey.length(),
                          inPublicKey.data(), inPublicKey.length(),
                          NULL, NULL,
                          NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
      if (err){
        print(fmt::format("could not convert the public key to binary from base64, Error: {}",  err));
        free(publicKey);
        return false;
      }
      uint8_t* signedMessageBinary = (uint8_t*)calloc(signedMessage.length()+1, sizeof(uint8_t));
      size_t signedMessageBinaryLength;
      err = sodium_base642bin((unsigned char *)signedMessageBinary, signedMessage.length(),
                          signedMessage.data(), signedMessage.length(),
                          NULL, &signedMessageBinaryLength,
                          NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
      if (err){
        print(fmt::format("could not convert the message to binary from base64, Error: {}",  err));
        free(publicKey);
        return false;
      }
      //signedMessageBinary.resize(strlen(signedMessageBinary.c_str()));

      print(fmt::format("converted publicKey64 to binary\n"));
      print(fmt::format("crypto_sign_BYTES length: {}\n", crypto_sign_BYTES));
      //print(fmt::format("signed binary message length: {}\n", signedMessageBinary.length()-crypto_sign_BYTES));
      print(fmt::format("signedMessageBinaryLength: {}\n", signedMessageBinaryLength));
      //print(fmt::format("signed binary message length whole: {}\n", signedMessageBinary.length()));
      //print(fmt::format("signed binary message c_str: {}\n", strlen(signedMessageBinary.c_str())));
      print(fmt::format("signed message length: {}\n", signedMessage.length()));
      unsigned char* pk = publicKey+crypto_sign_BYTES;
      if (crypto_sign_open(unsignedMessage, &messageLength,
                          (const unsigned char*)signedMessageBinary, signedMessageBinaryLength, pk) != 0) {
        /* Incorrect signature! */
        print(fmt::format("incorrect signature! signedMessage:\n{}\npublicKey:\n{}\n\n", signedMessage,  inPublicKey));
        free(publicKey);
        return false;
      }
      free(publicKey);
    }
    else{
      publicKey = (unsigned char*)(inPublicKey.data());
      unsigned char* pk = publicKey+crypto_sign_BYTES;
      if (crypto_sign_open(unsignedMessage, &messageLength,
                          (const unsigned char*)signedMessage.data(), signedMessage.length(), pk) != 0) {
        /* Incorrect signature! */
        /*char publicKey64[1024] = {0};
        size_t publicKey64Length = 0;
        sodium_bin2base64(publicKey64, 1024,
                               publicKey, publicKey64Length,
                               sodium_base64_VARIANT_URLSAFE_NO_PADDING);
      //DEBUG("publicKey64: {}", publicKey64);*/
        //print(fmt::format(fmt::format("incorrect signature! signedMessage:\n{}\npublicKey:\n{}\n", signedMessage,  publicKey64)));
        //ERROR("incorrect signature!");
        return false;
      }
    }
    //INFO("Verified the message");
    return true;
  }

  bool VerifyDetached(std::string_view publicKeyStringView, std::string_view signatureStringView, std::string_view messageStringView){
    unsigned char publicKey[1024] = {0};
    size_t publicKeyLength = 0;
    int err = sodium_base642bin(publicKey, 1024,
                        publicKeyStringView.data(), publicKeyStringView.length(),
                        NULL, &publicKeyLength,
                        NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (err){
      print(fmt::format("publicKey64 failed\n"));
      return false;
    }
    unsigned char* pk = publicKey+crypto_sign_BYTES;

    unsigned char signature[crypto_sign_BYTES] = {0};
    err = sodium_base642bin(signature, crypto_sign_BYTES,
                        signatureStringView.data(), signatureStringView.length(),
                        NULL, NULL,
                        NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (err){
      print(fmt::format("signature64 failed: {}\n", signatureStringView));
      return false;
    }
    //print(fmt::format("\ntrying to verify: {}\n", messageStringView));
    err = crypto_sign_verify_detached(signature,
                                (const unsigned char *)messageStringView.data(),
                                messageStringView.length(),
                                (const unsigned char*)pk);
    if (err){
      print(fmt::format("verified detached failed, err: {}\n", err));
      // print(fmt::format("pksv: {}, sig: {}, msg:{}\n", publicKeyStringView, signatureStringView, messageStringView));
      return false;
    }

    return true;
  }

  /*
    Sigils are essentially security tokens/permission blobs or rather that's what someone notable said.
    But came up with a cool name for them which I personally think fits better so...yeah.
    https://en.wikipedia.org/wiki/Sigil,
    https://old.reddit.com/r/heraldry/comments/84qmtf/please_explain_the_difference_between_sigils/

    They are Organizaed in memory like so:
      Signature, crypto_sign_BYTES
      Voucher Byte Length 8 bytes
      Voucher
      Vouchee Byte Length 8 bytes
      Vouchee
      Permission Name 16 bytes utf8 encoded
      Permission Expiration Date 8 bytes little endian
      Permission Name...
      Permission Expiration Date...
      ... 256 max permissions
  */
  bool ReadSigil(std::string_view sigil64, std::string& signature, std::string& voucher, std::string& vouchee, std::unordered_map<std::string, uint64_t>& permissions){

    unsigned char sigil[10240];
    size_t sigilLength = 0;
    int err = sodium_base642bin(sigil, 10240,
                          sigil64.data(), sigil64.length(),
                          NULL, &sigilLength,
                          NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    sigil[sigilLength] = '\0';

    if (err){
      print(fmt::format("could not convert sigil64, Error: {}",  err));
      return false;
    }
    //DEBUG("sigilLength: {}\nsigil: {}\n", sigilLength, sigil64);
    //INFO("after sigil binning");
    uint64_t pos = 0;
    uint64_t *voucherLength = (uint64_t*)(sigil+crypto_sign_BYTES);
    //INFO("before memcpy");
    //memcpy((void*)&voucherLength, sigil+crypto_sign_BYTES, sizeof(uint64_t));
    //DEBUG("uint64_t size: {} after memcpy voucherLength, {}", sizeof(uint64_t), *voucherLength);

    if(*voucherLength >= sigilLength){
      print(fmt::format("voucher length is logger than sigil length\n"));
      return false;
    }
    pos = crypto_sign_BYTES+sizeof(uint64_t);
    std::string_view publicKey((const char*)(sigil+pos), *voucherLength);
    

    voucher.resize(sodium_base64_ENCODED_LEN(*voucherLength, sodium_base64_VARIANT_URLSAFE_NO_PADDING));

    sodium_bin2base64(voucher.data(), voucher.length(),
                           (const unsigned char*)publicKey.data(), *voucherLength,
                           sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    //DEBUG("voucher: {}", voucher);

    //unsigned char unsigned_message[sigilLength-pos] = {0};
    unsigned char** unsigned_message = new unsigned char*[sigilLength-pos]();  // heap
    unsigned long long unsigned_message_len;
    bool verified = salty::VerifyCombined(std::string_view((const char*)sigil, sigilLength),
                          *unsigned_message,
                          publicKey,
                          false);
    delete[] unsigned_message; // heap
    if (!verified){
      print(fmt::format(fmt::format("Could not verify sigil, sigi: {}, voucher:{}", sigil64,  voucher)));
      return false;
    }
    signature.resize(sodium_base64_ENCODED_LEN(crypto_sign_BYTES,
      sodium_base64_VARIANT_URLSAFE_NO_PADDING));
    sodium_bin2base64(signature.data(), signature.length(),
                           (const unsigned char*)sigil, crypto_sign_BYTES,
                           sodium_base64_VARIANT_URLSAFE_NO_PADDING);

    pos += *voucherLength;
    uint64_t* voucheeLength = (uint64_t*)(sigil+pos);
    //memcpy((void*)&voucheeLength, sigil+pos, sizeof(uint64_t));
    if (pos + *voucheeLength >= sigilLength){
      return false;
    }
    pos += sizeof(uint64_t);

    vouchee.resize(sodium_base64_ENCODED_LEN(*voucheeLength,
      sodium_base64_VARIANT_URLSAFE_NO_PADDING));
    sodium_bin2base64(vouchee.data(), vouchee.length(),
                           (const unsigned char*)sigil+pos, *voucheeLength,
                           sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    pos += *voucheeLength;
    
    // Permissions Gathering now
    uint16_t permissionsLength = sigilLength - pos;
    if(permissionsLength % 24 || permissionsLength > 768){
      print(fmt::format(fmt::format("permissions length is not correct, length: {}",  permissionsLength)));
      return false;
    }
    uint8_t permissionsCount = permissionsLength / 24;


    for (uint8_t i=0;i<permissionsCount;++i){
      std::string permission((const char*)(sigil+pos),(size_t)16);
      rtrim(permission);
      permissions.emplace(std::make_pair(permission, *((uint64_t*)(sigil+pos+16))));
      pos += 24;
    }
    rtrim(voucher);
    rtrim(vouchee);
    rtrim(signature);
    return true;
  }

  bool Encrypt(std::string_view publicKeyStringView, std::string_view inputData, uint8_t*& encryptedData){
    unsigned char publicKey[1024] = {0};
    size_t publicKeyLength = 0;
    int err = sodium_base642bin(publicKey, 1024,
                        publicKeyStringView.data(), publicKeyStringView.length(),
                        NULL, &publicKeyLength,
                        NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (err){
      print(fmt::format("publicKey64 failed\n"));
      return false;
    }
    unsigned char* recipient_pk =  publicKey + crypto_sign_BYTES + crypto_sign_PUBLICKEYBYTES;

    encryptedData = (uint8_t*)calloc(crypto_box_SEALBYTES + inputData.length(), sizeof(uint8_t));
    if(crypto_box_seal((unsigned char*)encryptedData, (const unsigned char*)inputData.data(), inputData.length(), recipient_pk) != 0){
      print(fmt::format("Could not encrypt data"));
      return false;
    }
    return true;
  }

  bool Decrypt(std::string_view inputData, uint8_t*& decryptedData){
    decryptedData = (uint8_t*)calloc(inputData.length() - crypto_box_SEALBYTES, sizeof(uint8_t));
    unsigned char* decryptionKey = (unsigned char*)secretKeyString + crypto_sign_SECRETKEYBYTES;
    unsigned char* encryptionKey = (unsigned char*)secretKeyString + crypto_sign_SECRETKEYBYTES + crypto_box_SECRETKEYBYTES;
    print(fmt::format("inputData: {}\n", inputData));
    if(crypto_box_seal_open((unsigned char*)decryptedData, (const unsigned char*)inputData.data(), inputData.length(), encryptionKey, decryptionKey) != 0){
      print(fmt::format("Could not decrypt the data\n"));
      return false;
    }
    return true;
  }

  bool Sign(std::string& signedString64, std::string_view inputString){
    unsigned char* signedMessage = (unsigned char*)malloc(crypto_sign_BYTES+inputString.length());
    long long unsigned int signedMessageLength;
    crypto_sign(signedMessage, &signedMessageLength, (const unsigned char*)inputString.data(), inputString.length(), (const unsigned char*)secretKeyString);


    signedString64.resize(sodium_base64_encoded_len(signedMessageLength, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    char* err = sodium_bin2base64((char*)signedString64.data(), signedString64.length(),
                      (const unsigned char*)signedMessage, signedMessageLength,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    signedString64.resize(strlen(signedString64.c_str()), '\0');
    free(signedMessage);
    if (!err){
      print(fmt::format(fmt::format("could not get could not create signature: Error {}",  err)));
      return false;
    }
    return true;
  }

  bool SignDetached(std::string& signature64, std::string_view inputString){
    unsigned char signature[crypto_sign_BYTES];
    crypto_sign_detached(signature, NULL, (const unsigned char*)inputString.data(), inputString.length(), (const unsigned char*)secretKeyString);


    signature64.resize(sodium_base64_encoded_len(crypto_sign_BYTES, sodium_base64_VARIANT_URLSAFE_NO_PADDING), '\0');
    char* err = sodium_bin2base64(signature64.data(), signature64.length(),
                      signature, crypto_sign_BYTES,
                      sodium_base64_VARIANT_URLSAFE_NO_PADDING);
    if (!err){
      print(fmt::format(fmt::format("could not get could not create signature: Error {}\n",  err)));
      return false;
    }
    //signature64.resize(strlen(signature64.c_str()));
    return true;
  }
}

bool CanDoStuffWithFile(std::string_view fileName, int actions){
  return !access(fileName.data(), actions);
}

void ReadFile(std::string_view fileName, uint8_t* container, std::string_view& inputText){
  FILE* f = fopen(fileName.data(), "r");
  // Determine file size
  fseek(f, 0, SEEK_END);
  size_t size = ftell(f);
  container = (uint8_t*)calloc(size, sizeof(uint8_t));
  rewind(f);
  size_t bytesRead = fread(container, 1, size, f);
  fclose(f);
  inputText = std::string_view((const char*)container, bytesRead);
}

void WriteFile(std::string_view fileName, std::string_view outputText){
  FILE* f = fopen(fileName.data(), "wb+");
  fwrite(outputText.data(), sizeof(unsigned char), outputText.length(), f);
  fclose(f);
}

int main(int argc, char* argv[]){
  bool creating = false;
  bool signing = false;
  bool verifying = false;
  bool decrypting = false;
  bool encrypting = false;
  bool viewing = false;
  bool inspecting = false;
  bool fingerprinting = false;
  bool detached = false;
  bool unexpectedEnd = false;
  bool canReadFile = false;
  bool canWriteFile = false;
  bool canOverwriteFile = false;

  std::string_view inputKey;
  std::string_view inputKey2;
  std::string_view inputSignature;
  std::string_view inputFileName;
  std::string_view inputText;
  uint8_t* inputBinary = nullptr;
  uint8_t* outputText = nullptr;
  std::string_view outputFileName;

  int majorOptionSet = 0;

  for (int i=0;i<argc;++i){
    salty::print(fmt::format(argv[i]));
    //salty::print(fmt::format("looping"));
    if (strcmp(argv[i], "--help") == 0){
      unexpectedEnd = true;
      break;
    }
    if(strcmp(argv[i], "--create") == 0){
      if (i+1 >= argc) {
        unexpectedEnd = true;
        salty::print(fmt::format("c requires some kind of input but none was provided\n"));
        break;
      }
      salty::print(fmt::format("Create key pair with name: {}\n", argv[++i]));
      std::string_view name = argv[i];
      std::pair<std::string, std::string> keyPair = salty::CreateKeyPair(name);

      fmt::print(keypairTemplate, name, keyPair.first, keyPair.second);
      return 0;
    }
    else if(strcmp(argv[i], "--inspect") == 0){
      majorOptionSet++;
      inspecting = true;
    }
    else if(strcmp(argv[i], "--fingerprint") == 0){
      majorOptionSet++;
      fingerprinting = true;
    }
    else if(strcmp(argv[i], "--detached") == 0){

      detached = true;
    }
    else if(strcmp(argv[i], "--sign") == 0){
      majorOptionSet++;
      if (i+1 >= argc) {
        unexpectedEnd = true;
        salty::print(fmt::format("Verify requires some kind of input but none was provided\n"));
        break;
      }
      signing = true;
      if (argv[i+1][0] == '-'){continue;}
      salty::print(fmt::format("Sign: {}\n", argv[++i]));
      inputText = argv[i];
    }
    else if(strcmp(argv[i], "--verify") == 0){
      majorOptionSet++;
      if (i+1 >= argc) {
        unexpectedEnd = true;
        salty::print(fmt::format("Verify requires some kind of input but none was provided\n"));
        break;
      }
      verifying = true;
      if (argv[i+1][0] == '-'){continue;}
      salty::print(fmt::format("Verify: {}\n", argv[++i]));
      inputText = argv[i];
    }
    else if(strcmp(argv[i], "--encrypt") == 0){
      majorOptionSet++;
      encrypting = true;
      salty::print(fmt::format("Encrypting\n"));
      int valueIndex = i+1;
      if (valueIndex < argc && argv[valueIndex][0] && argv[valueIndex][0] != '-'){
        inputText = argv[valueIndex];
        ++i;
      }
    }
    else if(strcmp(argv[i], "--decrypt") == 0){
      majorOptionSet++;
      decrypting = true;
      salty::print(fmt::format("decrypting\n"));
      int valueIndex = i+1;
      if (valueIndex < argc && argv[valueIndex][0] && argv[valueIndex][0] != '-'){
        inputText = argv[valueIndex];
        ++i;
      }
    }
    else if(strcmp(argv[i], "--signature") == 0){
      if (++i >= argc || !argv[i][0] || argv[i][0] == '-') {
        unexpectedEnd = true;
        salty::print(fmt::format("signature specified but no signature was provided.\n"));
        break;
      }
      salty::print(fmt::format("Signature: {}\n", argv[i]));
      inputSignature = argv[i];
    }
    else if(strcmp(argv[i], "--file") == 0){
      if (++i >= argc || !argv[i][0] || argv[i][0] == '-') {
        unexpectedEnd = true;
        salty::print(fmt::format("file specified but no file was provided.\n"));
        break;
      }
      salty::print(fmt::format("Input File Name: {}\n", argv[i]));
      inputFileName = argv[i];
      if(CanDoStuffWithFile(inputFileName, F_OK|R_OK)){
        canReadFile = true;
      }
      else{
        salty::print(fmt::format("Can't do stuff with the input file.  Check for it's existence or your permissions.\n"));
        unexpectedEnd = true;
      }
    }
    else if(strcmp(argv[i], "--output") == 0){
      if (++i >= argc || !argv[i][0] || argv[i][0] == '-') {
        unexpectedEnd = true;
        salty::print(fmt::format("output specified but no filename was provided.\n"));
        break;
      }
      outputFileName = argv[i];
      if(CanDoStuffWithFile(inputFileName, W_OK)){
        canWriteFile = true;
      }
      else{
        salty::print(fmt::format("Can't do stuff with the output file.  Check your permissions?\n"));
        unexpectedEnd = true;
      }
    }
    else if(strcmp(argv[i], "--force") == 0){
      canOverwriteFile = true;
    }
    else if(strcmp(argv[i], "--key") == 0){
      if (++i >= argc || !argv[i][0] || argv[i][0] == '-') {
        unexpectedEnd = true;
        salty::print(fmt::format("Key specified but no key was provided.\n"));
        break;
      }
      inputKey = std::string_view(argv[i]);
    }
    else if(strcmp(argv[i], "--loud") == 0 || strcmp(argv[i], "--debug") == 0){
      salty::loud = true;
    }
  }

  // Early invalid input.  Get out and educate.
  if(majorOptionSet == 0 || majorOptionSet > 1 || unexpectedEnd){
    fmt::print(R"(
Agginym Key Utility, manage agginym key actions.  Create, sign, verify, encrypt, decrypt, inspect.

Configs are json files {{"name":"Jeff", "publicKey":"", "privateKey":""}}
input is a string or file, output is a string or file depending on the selected options.
All inputs are expected to be url-safe base64 encoded with no padding.  All outputs are url-safe base64 encoded with no padding.
Only one action is allowed at a time so just call it again with your output if you need to do more complicated stuff
)");
    fmt::print(R"(
Usage: 

      --help        - You'll get this message.

      --create      - Creates a new json key pair.  The string directly after create is treated as the new name. No other commands will run if this is defined.
                      --create [name]

      --inspect     - This is used to inspect any key or keypair specified.  No other commands will run if this is defined.
                      Either --file or --key is required but only one at a time.   **NOTE** ONLY THE PUBLIC KEY SHOULD EVER BE SHARED.  Seriously, don't share the whole thing. Just copy and paste the thing publicKey.
                      --inspect --file [keypair.json], or --inspect --key [private or publickey string]

      --fingerprint - This prints the fingerprint of the key.  Requires either --key or --keypair.  It's a basse58 representation.  Only works with a public key
                      Hex is too long even though it survives capitalization. Base64 can be somewhat confusing sometimes.  
                      --fingerprint --key [publicKeyString]

      --decrypt     - Decrypt a string of text. Requires --key or --keypair.  The string immediately after --decrypt is taken as the input.
                      If --file is used then the file is used as input. If there is nothing afterwards or just another option specified then it takes piped or whatever input.
                      --decrypt [base64 string] --key [privateKeyString] --file 

      --encrypt     - Encrypt a string of text.  Requires --key.  The string immediately after --encrypt is taken as the input.  Requires quotes for items with spaces.
                      If --file is used then the file is used as input.  If there is nothing afterwards or just another option specified then it takes piped or whatever input.
                      --encrypt [raw string]  --key [publicKeyString]

      --sign        - Outputs a signed text or file for the provided input.  Base64 encoding with no padding. if --detached is defined then it only outputs the signature
                      --sign [string] --key [privateKey string] (--detached), or --sign --file [somefile.jpg/txt/whatever] --key [privateKey string] (--detached)

      --verify      - Verifies a detached signature and file/text or a combined signed file. Requires --signature and --key
                      --verify [string] --key [publicKey string] (--signature), or --verify --file [somecoolfile.png/pdf/whatever] --key [publicKey string] (--signature)

      --detached    - States whether a signature is detached or not while signing or verifying.  Only has any effect with --sign

      --signature   - The signature you need to provide when you specify --detached and --verify

      --key         - This is the public key when used with --verify or --encrypt. This is the private key when --sign or --decrypt.

      --file        - This is the input file when doing anything with --verify, --encrypt --decrypt, --inspect, or --fingerprint

      --signature   - This is the signature for use with --decrypt when --verify and --detached are used together

      --output      - This is the output file when doing anything with --encrypt or --decrypt.  If it's not specified then output is to stdout

      --debug,loud  - This prints a bunch of information that may be helpful in finding bugs.

      --force       - If the file exists this will truncate and write to the output file if --output is specified.
                      If --force is not specified and the file exists it will print to console.

      Input streams are not supported right now.  Bug reports are welcome.  I hope you're having a good day.
)");
    exit(1);
  }

  if (inspecting){
    if (canReadFile){
      salty::print(fmt::format("can read file\n"));
      ReadFile(inputFileName, inputBinary, inputText);
      salty::print(fmt::format("inputText: {}\n", inputText));
    }
    else{
      inputText = inputKey;
    }
    if (inputText.length() > 0){
      salty::print(fmt::format("has length\n"));
      salty::Inspect(inputText);
    }
    exit(0);
  }
  else if(fingerprinting){
    if (canReadFile){
      ReadFile(inputFileName, inputBinary, inputText);
    }
    else{
      inputText = inputKey;
    }
    if (inputText.size()){
      std::string fingerprint;
      salty::GetFingerprint(fingerprint, inputText);
      fmt::print("Fingerprint: {}\n", fingerprint);
    }
    exit(0);
  }
  else if (signing){
    // global
    salty::secretKeyLength = salty::GetPrivateKeyFromBase64(inputKey, salty::secretKeyString);
    if (!salty::secretKeyLength){
      salty::print(fmt::format("Couldn't parse the private key\n"));
      exit(1);
    }
    if (canReadFile){
      ReadFile(inputFileName, inputBinary, inputText);
    }

    if(detached || canReadFile){ // this is always output to console
      std::string signature64;
      salty::SignDetached(signature64, inputText);
      fmt::print("Signature: {}\n", signature64);
    }
    else{
      if(canWriteFile && (!CanDoStuffWithFile(outputFileName, F_OK) || canOverwriteFile)) { // either the file doesn't exist or we can overwrite it.
        std::string signature64;
        salty::SignDetached(signature64, inputText);
        fmt::print("Signature: {}\n", signature64);
      }
      else{ // otherwise output to console, lolol console flood if you don't have the right permissions.  better know what you're doing.
        std::string signedMessage64;
        salty::Sign(signedMessage64, inputText);
        fmt::print("Signed Message: {}\n", signedMessage64);
      }
    }
  }
  else if (verifying){
    if (!inputKey.size()){
      salty::print(fmt::format("A publicKey is required to verify anything. Provide it with --key\n"));
      exit(1);
    }
    if (canReadFile){ 
      if (!inputSignature.size()){ // if we're reading a file then we're assuming that it's a detached signature.
        salty::print(fmt::format("Verifying a file requires a detached signature.  Include one with --signature"));
        exit(1);
      }
      salty::print("verifying a file");
      ReadFile(inputFileName, inputBinary, inputText);
    }

    bool verified = false;
    salty::print(fmt::format("can readfile: {}\nfilecontent: {}", canReadFile, inputText));
    if (inputSignature.size()){ // detached
      salty::print(fmt::format("Signature provided, trying to verify as detached\n"));
      verified = salty::VerifyDetached(inputKey, inputSignature, inputText);
      if (verified){
        fmt::print("Verified: True\n");
      }
    }
    else{ // combined, the input should always be base64 encoded
      salty::print(fmt::format("input: {}, inputKey: {}\n", inputText, inputKey));
      outputText = (uint8_t*)calloc(inputText.size(), sizeof(uint8_t));
      verified = salty::VerifyCombined(inputText, outputText, inputKey, true);
      if (verified){
        //fmt::print("Verified: True\n");
        fmt::print("{}", outputText);
        exit(0);
      }
      else{
        //fmt::print("Verified: False\n");
        exit(1);
      }
    }
  }
  else if(encrypting){
    if(canReadFile){
      ReadFile(inputFileName, inputBinary, inputText);
    }
    if (!inputKey.size()){
      salty::print(fmt::format("A public key is required to encrypt anything.  Provide it with --key\n"));
      exit(1);
    }
    salty::print(fmt::format("before encrypt\n"));
    // lets get that key

    salty::Encrypt(inputKey, inputText, outputText);

    std::string_view outputStringView((const char*)outputText, crypto_box_SEALBYTES+inputText.length());
    if(canWriteFile && (!CanDoStuffWithFile(outputFileName, F_OK) || canOverwriteFile)) { // either the file doesn't exist or we can overwrite it.
      salty::print(fmt::format("Outputting to file, raw: {}", outputFileName));
      WriteFile(outputFileName, outputStringView);
    }
    else{ // otherwise output to console with base64.
      salty::print("Either you didn't specify a file or the file can't be written.  Check out --force and --output if that's what you wanted to do.");
      std::string output64;
      salty::DataToBase64(outputStringView, output64);
      fmt::print("Encrypted Output base64 encoded: {}\n", output64);
    }
  }
  else if(decrypting){
    if(canReadFile){
      ReadFile(inputFileName, inputBinary, inputText);
    }
    if (!inputKey.size()){
      salty::print(fmt::format("A private key is required to decrypt anything.  Provide it with --key\n"));
      exit(1);
    }
    salty::secretKeyLength = salty::GetPrivateKeyFromBase64(inputKey, salty::secretKeyString);
    //uint8_t* pubkey = nullptr;
    //uint64_t pubkeyLength = salty::DataFromBase64(inputKey2, pubkey);

    if (!salty::secretKeyLength){
      salty::print(fmt::format("Couldn't parse the private key\n"));
      exit(1);
    }
    std::string_view outputStringView;

    if (canReadFile){
      salty::Decrypt(inputText, outputText);
      outputStringView = std::string_view((const char*)outputText, inputText.length() - crypto_box_SEALBYTES);

    }
    else{
      uint8_t* inputRaw = nullptr;
      uint64_t inputRawLength = 0;
      inputRawLength = salty::DataFromBase64(inputText, inputRaw);
      if (!inputRawLength){
        salty::print(fmt::format("Could not parse the value for decryption\n"));
        exit(1);
      }
      std::string_view rawStringView((const char*)inputRaw, inputRawLength);
      salty::Decrypt(rawStringView, outputText);
      outputStringView = std::string_view((const char*)outputText, inputRawLength - crypto_box_SEALBYTES);
    }

    if(canWriteFile && (!CanDoStuffWithFile(outputFileName, F_OK) || canOverwriteFile)) { // either the file doesn't exist or we can overwrite it.
      salty::print(fmt::format("Outputting to file, raw: {}\n", outputFileName));
      WriteFile(outputFileName, outputStringView);
    }
    else{ // otherwise output to console, raw
      salty::print("Either you didn't specify a file or the file can't be written.  Check out --force and --output if that's what you wanted to do.");
      //std::string output64;
      //salty::DataToBase64(outputStringView, output64);
      fmt::print("Decrypted Output, raw: {}\n", outputStringView);
    }
  }
}