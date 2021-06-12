#pragma once
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <thread>
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "Utils.h"

#pragma comment(lib, "Ws2_32.lib")

class Server {
public:
	Server() {}
	~Server() {
		closesocket(m_socket);
	}

	void Connect(USHORT port);
	void Send(std::string message);

private:
	std::string xorStr(std::string message);

	SOCKET m_socket = INVALID_SOCKET;
	std::string m_xorKey;
};

inline void Server::Connect(USHORT port) {
	while (true) {
		m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (m_socket == INVALID_SOCKET) {
			int error = WSAGetLastError();
			if (error == WSANOTINITIALISED) {//Wait until WSAStartup is called.
				std::this_thread::sleep_for(std::chrono::milliseconds(200));
				continue;
			}
			throw std::runtime_error(sf() << __FUNCSIG__ " : Failed to initialize socket : " << error);
		}
		break;
	}
	sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	local.sin_port = htons(port);

	if (connect(m_socket, reinterpret_cast<sockaddr*>(&local), sizeof(sockaddr_in)) == SOCKET_ERROR)
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed to connect : " << WSAGetLastError());

	std::string key = randomString(16);
	Send(key);
	m_xorKey = key;
}

inline void Server::Send(std::string message) {
	uint32_t packetSize = message.size();
	if (int sendBytes = send(m_socket, reinterpret_cast<char*>(&packetSize), sizeof(uint32_t), NULL);
		sendBytes == SOCKET_ERROR || sendBytes != sizeof(uint32_t)/*Let's hope that this last one never happens*/) {
		std::cout <<  __FUNCSIG__ " : Failed send : " << sendBytes << " " << WSAGetLastError() << std::endl;
		return;
	}

	std::cout << "Sending : " << message << std::endl;

	if (!m_xorKey.empty()) message = xorStr(message);

	if (int sendBytes = send(m_socket, message.data(), message.size(), NULL);//Repetitive
		sendBytes == SOCKET_ERROR || sendBytes != message.size()) {
		std::cout << __FUNCSIG__ " : Failed send : " << sendBytes << " " << WSAGetLastError() << std::endl;
		return;
	}
}

inline std::string Server::xorStr(std::string message) {
	for (size_t i = 0; i < message.size(); i++) message[i] ^= m_xorKey[i % m_xorKey.size()];
	return message;
}