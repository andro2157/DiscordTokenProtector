#pragma once
#include "../Includes.h"
#include "Crypto.h"
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>

enum class EncryptionType {
	HWID,
	Password,
	HWIDAndPassword,
	Yubi,
	Unknown
};

struct KeyData {
	EncryptionType type;
	CryptoPP::SecByteBlock key;
	CryptoPP::SecByteBlock iv;

	void reset() {
		type = EncryptionType::Unknown;
		key.CleanNew(0);
		iv.CleanNew(0);
	}

	bool isEncrypted = false;
	
	/*
	Note: the size of key and iv won't be changed since they are should be multiples of CRYPTPROTECTMEMORY_BLOCK_SIZE (16)
	*/
	void encrypt() {
		if (isEncrypted) return;

		Crypto::encryptSBB(key);
		Crypto::encryptSBB(iv);

		isEncrypted = true;
	}

	void decrypt() {
		if (!isEncrypted) return;

		Crypto::decryptSBB(key);
		Crypto::decryptSBB(iv);

		isEncrypted = false;
	}
};

static KeyData HWID_kd({ EncryptionType::HWID, CryptoPP::SecByteBlock(16), CryptoPP::SecByteBlock(16) });

namespace CryptoUtils {
	constexpr auto ALPHANUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	constexpr auto ALPHANUM_LEN = 26 * 2 + 10;

	inline secure_string secureRandomString(size_t len, const char* charRange = ALPHANUM, size_t charRangeLen = ALPHANUM_LEN) {
		using namespace CryptoPP;

		secure_string output;
		output.reserve(len);

		AutoSeededRandomPool rng;

		for (size_t i = 0; i < len; i++) {
			output.push_back(ALPHANUM[rng.GenerateByte() % ALPHANUM_LEN]);
		}

		return output;
	}
	inline CryptoPP::SecByteBlock randomSBB(size_t len) {
		CryptoPP::SecByteBlock out(len);
		CryptoPP::AutoSeededRandomPool rng;
		rng.GenerateBlock(out.data(), len);

		return out;
	}
	inline std::string toHex(const std::string& in) {
		using namespace CryptoPP;

		std::string result;
		HexEncoder encoder(new StringSink(result));

		encoder.Put((byte*)in.data(), in.size());
		encoder.MessageEnd();

		return result;
	}
	inline std::string fromHex(const std::string& in) {
		using namespace CryptoPP;

		std::string result;
		HexDecoder decoder(new StringSink(result));

		decoder.Put((byte*)in.data(), in.size());
		decoder.MessageEnd();

		return result;
	}

	//Note: not secure
	inline std::string SimpleSHA256(const std::string& data) {
		using namespace CryptoPP;

		std::string digest;

		SHA256 hash;
		hash.Update((const byte*)data.data(), data.size());
		digest.resize(hash.DigestSize());
		hash.Final((byte*)&digest[0]);

		return toHex(digest);
	}
}