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

#ifdef YUBIKEYSUPPORT
#include <ykpiv/ykpiv.h>
#pragma comment(lib, "ykpiv_static.lib")
#pragma comment(lib, "Winscard.lib")
#endif

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

#ifdef YUBIKEYSUPPORT
	constexpr auto YUBIKEY_KEY_FILE = L"yk.dat";
	constexpr auto YUBIKEY_DATA_LEN = 256;

	class Yubi {
	public:
		Yubi();
		~Yubi();

		int getRetryCount();

		//Returns -1 if authentificated, else it returns the amount of retries
		int authentificate(const secure_string& pin);
		//in.size() == 256
		secure_string signData(const CryptoPP::SecByteBlock& in);

		ykpiv_rc getLastError() const { return m_err; }

		std::string getModelName() const;

		static CryptoPP::SecByteBlock generateKeyFile();
		static CryptoPP::SecByteBlock readKeyFile();

	private:
		void throwOnError(ykpiv_rc err, const std::string& action);

		ykpiv_state* m_state;
		ykpiv_rc m_err;
		ykpiv_devmodel m_model = NULL;
	};
#endif
}