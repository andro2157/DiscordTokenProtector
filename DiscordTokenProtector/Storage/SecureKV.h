#pragma once
#include "Config.h"
#include "../Crypto/Crypto.h"
#include "../Crypto/CryptoUtils.h"

constexpr auto SECUREKV_FILENAME = L"secure.dat";
constexpr auto SECUREKV_DELIM = ':';
constexpr auto SECUREKV_HEADER = "SKV";

class SecureKV {
public:
	SecureKV();
	~SecureKV();

	void write(const secure_string& key, const secure_string& value, KeyData& keydata);
	secure_string read(const secure_string& key, KeyData& keydata);

	//Unsafe in memory
	void write_int(const secure_string& key, const int value, KeyData& keydata) {
		write(key, secure_string(std::to_string(value)), keydata);
	}
	//Unsafe in memory
	int read_int(const secure_string& key, KeyData& keydata, const int defaultValue = 0) {
		secure_string value = read(key, keydata);
		if (value.empty()) {
			write_int(key, defaultValue, keydata);
			return defaultValue;
		}
		return std::stoi(std::string(value));
	}

	using KV = std::pair<secure_string, secure_string>;
	using KVs = std::vector<KV>;

	bool save(const KVs& content, KeyData& keydata);
	KVs load(KeyData& keydata);

	void reencrypt(KeyData& oldKeydata, KeyData& newKeydata);

	EncryptionType getEncryptionType();

	//NOT thread safe!
	void reopenFile(bool remove = false);
private:
	void openFile();

	std::fstream m_file;
	std::mutex m_high_mutex;
	std::mutex m_low_mutex;
};

inline std::unique_ptr<SecureKV> g_secureKV;

namespace DEFAULT_KV {
	constexpr auto integrity = TRUE;
	constexpr auto integrity_checkhash = TRUE;
	constexpr auto integrity_checkexecutable = TRUE;
	constexpr auto integrity_checkmodule = TRUE;
	constexpr auto integrity_checkresource = TRUE;
	constexpr auto integrity_checkscripts = TRUE;
	constexpr auto integrity_allowbetterdiscord = FALSE;
	constexpr auto integrity_redownloadhashes = FALSE;
	constexpr auto integrity_ignorenonexec = FALSE;
	constexpr auto protect_discord_process = TRUE;
}