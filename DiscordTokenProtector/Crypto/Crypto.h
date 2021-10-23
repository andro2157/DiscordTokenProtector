#pragma once
#include "../Includes.h"
#include <Wincrypt.h>

#include <cryptopp/cryptlib.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/eax.h>
#include <cryptopp/hex.h>

//https://stackoverflow.com/a/56888301/13544464
using secure_string = std::basic_string<char, std::char_traits<char>, CryptoPP::AllocatorWithCleanup<char>>;

namespace Crypto {
	CryptoPP::SecByteBlock derivateKey(const secure_string& key, const size_t size, uint32_t& iterations, double timeInSeconds = 0.0);

	secure_string encrypt(const secure_string& content, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv);
	secure_string decrypt(const secure_string& cipher, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv);

	secure_string encryptHWID(const secure_string& content);
	secure_string decryptHWID(const secure_string& content);

	void encryptSBB(CryptoPP::SecByteBlock& in);
	void decryptSBB(CryptoPP::SecByteBlock& in);
}