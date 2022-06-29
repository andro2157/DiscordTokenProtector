#pragma once
#include "SecureKV.h"

constexpr auto TOKENMANAGER_SEP = '!';

class empty_securekv_data_exception : public std::runtime_error {
public:
	empty_securekv_data_exception(std::string key) : std::runtime_error(sf() << "Empty SecureKV data. Key : " << key) {}
};

//TODO : make all of this work in SecureKV natively..
class TokenManager {
public:
	TokenManager() {}

	//Call after g_context.kd is initialized
	void init();

	void firstSetup(secure_string token, DiscordUserInfo info);

	secure_string getCurrentToken() { return getToken(m_idx); }
	secure_string getToken(const size_t idx);

	void updateCurrentToken(const secure_string new_token);

	DiscordUserInfo getCurrentCachedInfo() { return getCachedInfo(m_idx); }
	DiscordUserInfo getCachedInfo(const size_t idx);
	void updateCurrentCachedInfo(DiscordUserInfo info) { updateCachedInfo(m_idx, info); }
	void updateCachedInfo(const size_t idx, DiscordUserInfo info);

	size_t getCurrentIndex() const { return m_idx; }
	void setIndex(const size_t idx);

	//Returns the index
	size_t addToken(const secure_string token, const DiscordUserInfo info);
	void removeToken(size_t idx);
	void removeToken(const secure_string token);

	size_t size() const { return m_encryptedTokens.size(); }

	bool migrateOldToken();

	void updateKD(KeyData& newKeyData, KeyData& oldKeyData);

	static std::string dumpUserDataToJson(const DiscordUserInfo info);
	static DiscordUserInfo loadUserDataFromJson(std::string data);

	static void serializeData(const secure_string token, DiscordUserInfo cached_info, secure_string& out);
	static void deserializeData(const secure_string data, secure_string& token, DiscordUserInfo& info);

private:
	void flush();
	void load();

	std::vector<secure_string> m_encryptedTokens;
	std::vector<DiscordUserInfo> m_cachedInfos;
	size_t m_idx = 0;
	std::mutex m_mutex;
};

extern TokenManager g_tokenManager;