# Discord Token Protector
#### Protect your Discord token from malicious grabbers!

## [For NTTS viewers here's my response to the video](NTTS.md)

##### ✔️ **Works with the latest version of Discord**

![Main Workflow](https://github.com/andro2157/DiscordTokenProtector/actions/workflows/msbuild.yml/badge.svg)

<p align="center">
  <img width="500" src="Assets/DiscordTokenProtectorUI.png">
</p>

This project is still under development! You might face some instability issues!\
This is in **NO** way a perfect solution against Discord token grabbers.
But this will protect you against most token grabbers:
- (Most common) LevelDB reading *(from the beginning)*
- (Less common) Script injection / Discord module tampering *(from dev-6)*
- (Rare) Memory reading *(from dev-8)*

**Any targeted attack against DiscordTokenProtector can bypass this protection!**

## [✔️Good practices when using DTP](goodpractice.md)

### ⚠️ Disclaimer
**DTP is not affiliated with Discord.**\
**DTP is in NO way responsible for what can happen on your Discord account.**\
**Chances of getting terminated using DTP are very low, but please keep in mind that using third-party software is against Discord's TOS.**


## Features

#### ✅ Protect your self from most token grabbers
#### ✅ Securely store your Discord token in an encrypted file (YubiKeys* are supported)
#### ✅ Switch easily between multiple accounts
#### ✅ Change your Discord password in one-click
#### ✅ Check the integrity of your Discord installation on launch (BetterDiscord is supported)
#### ✅ Check scripts for known malwares *(eg AnarchyGrabber3)*
#### ✅ Protect the Discord process from memory reading / code injection
#### ✅ Protect DTP from tampering attacks (protects the process/config from unauthorized users)

**Except from YubiKey NEO*

## Installation / Update

### Download the latest release **[HERE](https://github.com/andro2157/DiscordTokenProtector/releases)**

* Start DiscordTokenProtectorSetup.exe
* Select between Normal and NoStartup installation
* **[Set it up](Setup.md)**
* ([YubiKey Setup Guide](YubiSetup.md))
* Enjoy!

## What does it do?

Here's a little diagram of how it works:

<p align="center">
  <img width="800" src="Assets/how_does_it_work.jpg">
</p>

It removes the `Local Storage` and `Session Storage` directories from `%appdata%\Discord`.
These directories can store your Discord token (used to authenticate you).
Most of the grabbers look for your token there. Therefore, by removing these directories you can avoid getting grabbed.\
Your Discord token is stored in a secure container encrypted with AES-256.

## Some stuff to consider

* By removing these directories, Discord cannot store any local settings.
Meaning that all of your client-specific settings will be removed each time you start Discord. (eg. keybinds, default audio device, ...)\
**BUT**, all of the server-side settings are still saved. (users descriptions, language, dark mode, ...)

* Discord canary might not work properly. These builds don't support handoff login.

* Again, this is a project in development, and you might face some instabilities (crash, discord not launching, ...). Please report these issues on this repo.

* Some anti-virus flags DiscordTokenProtector because it can start with Windows and it can inject payload into Discord.
These activities are suspicious for AVs. I provided builds without the auto-startup, it reduces the amount of false-flag.

* DiscordTokenProtector doesn't seem to work well on Windows 7

* Integrity check hashes are uploaded manually, therefore you might get an error message saying that it's unable to get the hashes. Please open a ticket if it says so!

## Compilation

To compile, it's recommended to use [vcpkg](https://github.com/microsoft/vcpkg) for the libraries

### Step 1: Installing vcpkg
*You can skip this step if you already have it*
```
git clone https://github.com/microsoft/vcpkg
cd vcpkg
bootstrap-vcpkg.bat -disableMetrics
```
Start a new cmd as admin in the `vcpkg` folder and type:
```
vcpkg integrate install
```

### Step 2: Cloning DiscordTokenProtector
Copy and paste this (in the vcpkg directory if you don't have it in the PATH)
```
git clone https://github.com/andro2157/DiscordTokenProtector
```


### Step 3: Installing the libraries using manifest mode
```
cd DiscordTokenProtector
vcpkg install --triplet x86-windows-static
```
*This process might take some time as it's building these libraries (for the static link)*

### Step 4: Open the project in VS
Open `DiscordTokenProtector.sln`

### Step 5: Open the project settings
Set "Use Vcpkg Manifest" to Yes

Everything should be setup, you just need to compile it with the `PROD` or `PROD-NOSTARTUP` config in **x86**.

### (Optional) Step 6: Compile with YubiKey support
* Download the latest yubico-piv-tool source code here: https://developers.yubico.com/yubico-piv-tool/Releases/ \
**Don't clone from the repo, it won't compile on Windows!**
* Follow the instructions [here](https://github.com/Yubico/yubico-piv-tool#building-on-windows) to create the project.
* Open the generated .sln file in Visual Studio.
* Open the properties of the `ykpiv` project.
* Go to `C++` > `Code Generation`, and change the `Runtime Library` from `Multi-threaded DLL (/MD)` to `Multi-threaded (/MT)`
* Compile
* By default, the `PROD-YUBI(-NOSTARTUP)` config will look for the library and the headers in `C:\Program Files (x86)\Yubico\Yubico PIV Tool\` (default installation path of the PIV tool). You can move them here or change the path in the DTP project properties.

*Note : C++17 is required to compile.*

## Credit

* [Discord](https://discord.com/)
* Ocornut for [ImGui](https://github.com/ocornut/imgui)
* Nlohmann for the [JSON lib](https://github.com/nlohmann/json)
* [CryptoPP](https://www.cryptopp.com/)
* Stevemk14ebr for [Polyhook v2](https://github.com/stevemk14ebr/PolyHook_2_0)
* [CUrl](https://curl.se/)
* [Yubico](https://www.yubico.com/) for YubiKeys and [yubico-piv-tool](https://github.com/Yubico/yubico-piv-tool)

## Donation

If you would like to support this project by donating, you can do it through:
* [Brave Browser](https://brave.com/) tips
* Crypto (ETH / BSC) 0x6997878c19ab249AEbc523635f09B95b793AfA5D
