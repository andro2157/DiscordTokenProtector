#include "NetworkManager.h"
#include <future>

NetworkManager::NetworkManager() {
	if (WSAStartup(MAKEWORD(2, 2), &m_wsaData)) {
		FATALERROR_STR(sf() << __FUNCSIG__ " : Failed WSAStartup : " << WSAGetLastError());
	}
}

NetworkManager::~NetworkManager() {
	WSACleanup();
}

void NetworkManager::Start(std::promise<USHORT>& port) {
	m_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_socket == INVALID_SOCKET)
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed to initialize socket : " << WSAGetLastError());


	sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	local.sin_port = 0;//Random port

	if (bind(m_socket, reinterpret_cast<sockaddr*>(&local), sizeof(local)))
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed bind : " << WSAGetLastError());

	sockaddr_in sin;
	int namelen = sizeof(sin);
	if (getsockname(m_socket, reinterpret_cast<sockaddr*>(&sin), &namelen) == SOCKET_ERROR || namelen != sizeof(sin))
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed getsockname : " << WSAGetLastError());

	port.set_value(ntohs(sin.sin_port));

	const char OPTION_VALUE = 1;
	if (setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, &OPTION_VALUE, sizeof(int)))
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed setsockopt SOL_SOCKET, SO_REUSEADDR : " << WSAGetLastError());

	if (setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY, &OPTION_VALUE, sizeof(int)))
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed setsockopt IPPROTO_TCP, TCP_NODELAY : " << WSAGetLastError());

	if (listen(m_socket, SOMAXCONN))
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed listen : " << WSAGetLastError());

	g_logger.info(sf() << "Accept!");

	//Accept 1 client
	SOCKADDR_IN client_info = { 0 };
	int addrsize = sizeof(client_info);
	m_client = accept(m_socket, reinterpret_cast<sockaddr*>(&client_info), &addrsize);
	if (m_client == INVALID_SOCKET)
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed accept : " << WSAGetLastError());
	g_logger.info(sf() << "Accepted : " << m_client);

	m_xorKey = Recv();//Simple XorKey, a real encryption isn't really needed. If a program targets DTP we have more trouble...
}

void NetworkManager::Stop() {
	closesocket(m_client);
	closesocket(m_socket);
	m_xorKey.clear();
}

std::string NetworkManager::Recv() {
	uint32_t packetSize;
	if (int recvBytes = recv(m_client, reinterpret_cast<char*>(&packetSize), sizeof(uint32_t), NULL);
		recvBytes == SOCKET_ERROR || recvBytes != sizeof(uint32_t)/*Let's hope that this last one never happens*/) {
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed recv : " << recvBytes << " " << WSAGetLastError());
	}
#ifndef _PROD
	g_logger.info(sf() << "Recv packet size : " << packetSize);
#endif
	std::string output;
	output.resize(packetSize, '\000');
	if (int recvBytes = recv(m_client, output.data(), packetSize, NULL);//Repetitive
		recvBytes == SOCKET_ERROR || recvBytes != packetSize) {
		throw std::runtime_error(sf() << __FUNCSIG__ " : Failed recv : " << recvBytes << " " << WSAGetLastError());
	}

	if (!m_xorKey.empty()) output = xorStr(output);

#ifndef _PROD
	g_logger.info(sf() << "Received : " << output);
#endif
	return output;
}

std::string NetworkManager::xorStr(std::string message) {
	for (size_t i = 0; i < message.size(); i++) message[i] ^= m_xorKey[i % m_xorKey.size()];
	return message;
}