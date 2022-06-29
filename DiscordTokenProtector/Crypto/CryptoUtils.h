#pragma once
#include "../Includes.h"
#include "Crypto.h"
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/base64.h>

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
	Note: the size of key and iv won't be changed since they should be multiples of CRYPTPROTECTMEMORY_BLOCK_SIZE (16)
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

	constexpr auto PASSCHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!/:.;,?*$%-_()[]{}";
	constexpr auto PASSCHARS_LEN = 80;

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

	inline secure_string KD_encrypt(const secure_string& data, KeyData keydata) {
		if (keydata.type == EncryptionType::HWID)
			return Crypto::encryptHWID(data);
		else if (keydata.type == EncryptionType::Password || keydata.type == EncryptionType::Yubi)
			return Crypto::encrypt(data, keydata.key, keydata.iv);
		else if (keydata.type == EncryptionType::HWIDAndPassword)
			return Crypto::encrypt(Crypto::encryptHWID(data), keydata.key, keydata.iv);
		else
			throw std::runtime_error("unknown encryption type");
	}

	inline secure_string KD_decrypt(const secure_string& data, KeyData keydata) {
		if (keydata.type == EncryptionType::HWID)
			return Crypto::decryptHWID(data);
		else if (keydata.type == EncryptionType::Password || keydata.type == EncryptionType::Yubi)
			return Crypto::decrypt(data, keydata.key, keydata.iv);
		else if (keydata.type == EncryptionType::HWIDAndPassword)
			return Crypto::decryptHWID(Crypto::decrypt(data, keydata.key, keydata.iv));
		else
			throw std::runtime_error("unknown encryption type");
	}

	inline secure_string toBase64(const secure_string& in) {
		using namespace CryptoPP;
		secure_string out;

		Base64Encoder encoder;
		encoder.Put(reinterpret_cast<const byte*>(in.data()), in.size());
		encoder.MessageEnd();

		auto size = encoder.MaxRetrievable();
		out.resize(size);
		encoder.Get(reinterpret_cast<byte*>(out.data()), out.size());

		return out;
	}

	inline secure_string fromBase64(const secure_string& in) {
		using namespace CryptoPP;

		secure_string out;

		Base64Decoder decoder;
		decoder.Put(reinterpret_cast<const byte*>(in.data()), in.size());
		decoder.MessageEnd();

		auto size = decoder.MaxRetrievable();
		out.resize(size);
		decoder.Get(reinterpret_cast<byte*>(out.data()), out.size());

		return out;
	}

	inline void printSecByteBlock(const CryptoPP::SecByteBlock& data) {
		for (const auto& c : data) {
			std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<uint16_t>(c) << " ";
		}
		std::cout << std::dec << std::endl;
	}
}