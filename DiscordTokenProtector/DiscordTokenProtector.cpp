#include "Includes.h"
#include "Protection/ProcessProtection.h"
#include "Discord.h"
#include "Utils/Utils.h"
#include "Storage/Config.h"
#include "Menu/Menu.h"
#include "Context.h"

void mainInit() {
    try {
#ifdef _PROD
        g_logger.setOutFile(Config::getConfigPath() + L"logging.log");
#endif

        g_processprotection = std::make_unique<ProcessProtection>();
#ifdef _PROD
        //TODO Protect threads, threads are killable without admin permission
        g_processprotection->ProtectProcess();
#endif
        g_discord = std::make_unique<Discord>();

        g_config = std::make_unique<Config>();
        g_secureKV = std::make_unique<SecureKV>();
    }
    catch (std::exception& e) {
        FATALERROR(e.what());
    }
}

int main() {
#ifndef _PROD
    std::cout << "Discord Token Protector by Andro24" << std::endl;
#endif

#ifdef _PROD
    if (!std::filesystem::exists("ProtectionPayload.dll")) {
        FATALERROR("Missing ProtectionPayload.dll\nPlease redownload it and put it in the same directory as DiscordTokenProtector.exe");
    }
    {
        std::wstring modulePath(MAX_PATH, L'\000');
        GetModuleFileName(GetModuleHandle(NULL), modulePath.data(), MAX_PATH);
        if (modulePath.find(Config::getConfigPath() + L"DiscordTokenProtector.exe") == std::wstring::npos) {
            FATALERROR_STR(sf() << "Invalid module path!");
        }
    }
#endif

    mainInit();
    g_context.initTokenState();

    Menu::SetupWindow();

    ExitProcess(0);
    return 0;
}

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    PSTR lpCmdLine, INT nCmdShow) {
    return main();
}