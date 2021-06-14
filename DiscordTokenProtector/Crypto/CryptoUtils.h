#pragma once
#include "../Includes.h"
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>

enum class EncryptionType {
	HWID,
	Password,
	HWIDAndPassword,
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
};

static const KeyData HWID_kd({ EncryptionType::HWID, CryptoPP::SecByteBlock(), CryptoPP::SecByteBlock() });

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
}