#pragma once
#include "FolderRemover.h"
#include "../Utils/logger.h"

FolderRemover::~FolderRemover() {
	if (m_running) {
		m_running = false;
		m_thread.join();
	}
}

void FolderRemover::Start() {
	if (m_running) {
		g_logger.warning(__FUNCSIG__ " : Thread is already running!");
		return;
	}
	m_running = true;
	m_thread = std::thread(&FolderRemover::RemoverThread, this);
}

void FolderRemover::Stop() {
	if (!m_running) {
		g_logger.warning(__FUNCSIG__ " : Thread is not running!");
		return;
	}
	m_running = false;
	m_thread.join();
}

void FolderRemover::Remove() {
	if (std::filesystem::exists(m_path)) {
		try {
			std::filesystem::remove_all(m_path);
		}
		catch (...) {}//We can safely ignore it
	}
}

void FolderRemover::RemoverThread() {
	while (m_running) {
		Remove();
		std::this_thread::sleep_for(std::chrono::milliseconds(UPDATE_DELAY));
	}
}