#include "Crypto.h"
#include "CryptoUtils.h"

namespace Crypto {
	//Just some random bytes as salt
	//Changing this will make encrypted file not recoverable
	constexpr auto CONST_SALT_LEN = 32;
	constexpr CryptoPP::byte CONST_SALT[CONST_SALT_LEN] = {
		0x0f, 0xbe, 0x25, 0x67, 0xe7, 0xf2, 0x56, 0xc5, 0x9e, 0xb8, 0xbb, 0x16, 0x89, 0x09, 0xb5, 0x15,
		0x8e, 0x88, 0xa4, 0x2d, 0xdc, 0x33, 0x56, 0xdb, 0x63, 0xd4, 0xb3, 0x09, 0x21, 0x42, 0x76, 0x80
	};

	CryptoPP::SecByteBlock derivateKey(const secure_string& key, const size_t size, uint32_t& iterations, double timeInSeconds) {
		using namespace CryptoPP;

		CryptoPP::SecByteBlock derived(size);
		//HKDF<SHA256> hkdf;
		PKCS5_PBKDF2_HMAC<SHA256> pbkdf;

		/*hkdf.DeriveKey(
			derived.data(), derived.size(),
			reinterpret_cast<const byte*>(key.data()), key.size(),
			CONST_SALT, CONST_SALT_LEN,
			nullptr, 0
		);*/

		iterations = pbkdf.DeriveKey(
			derived.data(), derived.size(), 0,
			reinterpret_cast<const byte*>(key.data()), key.size(),
			CONST_SALT, CONST_SALT_LEN,
			iterations,
			timeInSeconds
		);

		return derived;
	}

	//AES-EAX
	//https://www.cryptopp.com/wiki/EAX_Mode
	secure_string encrypt(const secure_string& content, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv) {
		using namespace CryptoPP;

		if (key.size() != AES::MAX_KEYLENGTH) {
			throw std::runtime_error(sf() << "Unexpected key size : expected " << AES::MAX_KEYLENGTH << " got " << key.size());
		}
		if (iv.size() != AES::BLOCKSIZE * 16) {
			throw std::runtime_error(sf() << "Unexpected iv size : expected " << AES::BLOCKSIZE * 16 << " got " << iv.size());
		}

		EAX<AES>::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv, iv.size());

		secure_string cipher;

		StringSource ss(reinterpret_cast<const byte*>(content.data()), content.size(), true,
			new AuthenticatedEncryptionFilter(e,
				new StringSinkTemplate<secure_string>(cipher)
			)
		);

		return cipher;
	}

	secure_string decrypt(const secure_string& cipher, CryptoPP::SecByteBlock key, CryptoPP::SecByteBlock iv) {
		using namespace CryptoPP;

		if (key.size() != AES::MAX_KEYLENGTH) {
			throw std::runtime_error(sf() << "Unexpected key size : expected " << AES::MAX_KEYLENGTH << " got " << key.size());
		}
		if (iv.size() != AES::BLOCKSIZE * 16) {
			throw std::runtime_error(sf() << "Unexpected iv size : expected " << AES::BLOCKSIZE * 16 << " got " << iv.size());
		}

		EAX< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv, iv.size());

		secure_string content;

		StringSource as(reinterpret_cast<const byte*>(cipher.data()), cipher.size(), true,
			new AuthenticatedDecryptionFilter(d,
				new StringSinkTemplate<secure_string>(content)
			)
		);

		return content;
	}

	secure_string encryptHWID(const secure_string& content) {
		DATA_BLOB DataIn;
		DATA_BLOB DataOut;

		DataIn.pbData = (BYTE*)content.data();
		DataIn.cbData = content.size();

		if (!CryptProtectData(&DataIn, NULL,NULL, NULL, NULL, NULL, &DataOut)) {
			throw std::runtime_error(sf() << "CryptProtectData failed : " << GetLastError());
		}

		secure_string out(DataOut.cbData, '\000');
		memcpy_s(out.data(), out.size(), DataOut.pbData, DataOut.cbData);

		SecureZeroMemory(DataOut.pbData, DataOut.cbData);
		LocalFree(DataOut.pbData);

		return out;
	}

	secure_string decryptHWID(const secure_string& content) {
		DATA_BLOB DataIn;
		DATA_BLOB DataOut;

		DataIn.pbData = (BYTE*)content.data();
		DataIn.cbData = content.size();

		if (!CryptUnprotectData(&DataIn, NULL, NULL, NULL, NULL, NULL, &DataOut)) {
			throw std::runtime_error(sf() << "CryptUnprotectData failed : " << GetLastError());
		}

		secure_string out(DataOut.cbData, '\000');
		memcpy_s(out.data(), out.size(), DataOut.pbData, DataOut.cbData);

		SecureZeroMemory(DataOut.pbData, DataOut.cbData);
		LocalFree(DataOut.pbData);

		return out;
	}

	void encryptSBB(CryptoPP::SecByteBlock& in) {
		if (auto mod = in.size() % CRYPTPROTECTMEMORY_BLOCK_SIZE; mod != 0)
			in.CleanGrow(in.size() + (CRYPTPROTECTMEMORY_BLOCK_SIZE - mod));

		if (!CryptProtectMemory(in.data(), in.size(), CRYPTPROTECTMEMORY_SAME_PROCESS))
			throw std::runtime_error(sf() << "CryptProtectMemory failed : " << GetLastError());
	}

	void decryptSBB(CryptoPP::SecByteBlock& in) {
		if (!CryptUnprotectMemory(in.data(), in.size(), CRYPTPROTECTMEMORY_SAME_PROCESS))
			throw std::runtime_error(sf() << "CryptProtectMemory failed : " << GetLastError());
	}
}