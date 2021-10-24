#include "Crypto.h"
#include "CryptoUtils.h"
#include "../Storage/Config.h"

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

#ifdef YUBIKEYSUPPORT
	Yubi::Yubi() {
		throwOnError(ykpiv_init(&m_state, true), "ykpiv_init");
		throwOnError(ykpiv_connect(m_state, NULL), "ykpiv_connect");

		m_model = ykpiv_util_devicemodel(m_state);
		if (m_model == NULL)
			throw std::runtime_error(sf() << "Failed ykpiv_util_devicemodel : model was NULL");
		if (m_model == DEVTYPE_NEOr3)
			throw std::runtime_error(sf() << "NEO YubiKey are not supported");
	}

	Yubi::~Yubi() {
		if (m_state) {
			ykpiv_disconnect(m_state);
			ykpiv_done(m_state);
		}
	}

	int Yubi::getRetryCount() {
		int retries = 0;
		throwOnError(ykpiv_get_pin_retries(m_state, &retries), "ykpiv_get_pin_retries");
		return retries;
	}

	int Yubi::authentificate(const secure_string& pin) {
		int tries = 0;
		m_err = ykpiv_verify(m_state, pin.c_str(), &tries);
		if (m_err == YKPIV_OK || m_err == YKPIV_WRONG_PIN)
			return tries;
		throwOnError(m_err, "ykpiv_verify");
		return 0;//Should not hit this
	}

	secure_string Yubi::signData(const CryptoPP::SecByteBlock& in) {
		secure_string signature;
		signature.resize(1024);

		size_t siglen = signature.size();

		throwOnError(
			ykpiv_sign_data(
				m_state, in.data(), in.size(),
				reinterpret_cast<byte*>(signature.data()), &siglen, YKPIV_ALGO_RSA2048, YKPIV_KEY_CARDAUTH
			), "ykpiv_sign_data");

		signature.resize(siglen);
		return signature;
	}

	std::string Yubi::getModelName() const {
		switch (m_model){
			case DEVTYPE_NEO: return "YubiKey NEO";
			case DEVTYPE_YK: return "YubiKey";
			case DEVTYPE_NEOr3: return "YubiKey NEO R3";
			case DEVTYPE_YK4: return "YubiKey 4";
			case DEVTYPE_YK5: return "YubiKey 5";
		}
		return "Unknown";
	}

	CryptoPP::SecByteBlock Yubi::generateKeyFile() {
		CryptoPP::SecByteBlock keydata = CryptoUtils::randomSBB(YUBIKEY_DATA_LEN);
		std::ofstream file(Config::getConfigPath() + YUBIKEY_KEY_FILE, std::ios::binary);
		if (!file.is_open())
			throw std::runtime_error("generateKeyFile : Failed to open YubiKey data file");

		file.write(reinterpret_cast<const char*>(keydata.data()), keydata.size());
		return keydata;
	}

	CryptoPP::SecByteBlock Yubi::readKeyFile() {
		std::ifstream file(Config::getConfigPath() + YUBIKEY_KEY_FILE, std::ios::binary);
		if (!file.is_open())
			throw std::runtime_error("readKeyFile : Failed to open YubiKey data file");

		CryptoPP::SecByteBlock keydata(YUBIKEY_DATA_LEN);
		file.read(reinterpret_cast<char*>(keydata.data()), YUBIKEY_DATA_LEN);

		return keydata;
	}

	void Yubi::throwOnError(ykpiv_rc err, const std::string& action) {
		m_err = err;
		if (err == YKPIV_OK) return;

		std::string errorString = "UNKNOWN_ERROR";

#define ADDCASE(ERR)\
	case ERR: errorString = #ERR; break;

		switch (err) {
			ADDCASE(YKPIV_MEMORY_ERROR);
			ADDCASE(YKPIV_PCSC_ERROR);
			ADDCASE(YKPIV_SIZE_ERROR);
			ADDCASE(YKPIV_APPLET_ERROR);
			ADDCASE(YKPIV_AUTHENTICATION_ERROR);
			ADDCASE(YKPIV_RANDOMNESS_ERROR);
			ADDCASE(YKPIV_GENERIC_ERROR);
			ADDCASE(YKPIV_KEY_ERROR);
			ADDCASE(YKPIV_PARSE_ERROR);
			ADDCASE(YKPIV_WRONG_PIN);
			ADDCASE(YKPIV_INVALID_OBJECT);
			ADDCASE(YKPIV_ALGORITHM_ERROR);
			ADDCASE(YKPIV_PIN_LOCKED);
			ADDCASE(YKPIV_ARGUMENT_ERROR);
			ADDCASE(YKPIV_RANGE_ERROR);
			ADDCASE(YKPIV_NOT_SUPPORTED);
		}

#undef ADDCASE

		throw std::runtime_error(sf() << "Failed " << action << " : " << errorString);
	}
#endif
}