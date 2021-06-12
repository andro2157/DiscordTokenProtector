#pragma once
#include "../Includes.h"
#include <future>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "Ws2_32.lib")

class NetworkManager {
public:
	NetworkManager();
	~NetworkManager();

	//Starts the server and accept 1 client (the payload)
	void Start(std::promise<USHORT>& port);
	void Stop();

	std::string Recv();
private:
	std::string xorStr(std::string message);

	WSADATA m_wsaData;
	SOCKET m_socket = INVALID_SOCKET;
	SOCKET m_client = INVALID_SOCKET;
	std::string m_xorKey;
};