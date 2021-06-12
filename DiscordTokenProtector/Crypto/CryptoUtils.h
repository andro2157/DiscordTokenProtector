#pragma once
#include "../Includes.h"
#include <cryptopp/hex.h>

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