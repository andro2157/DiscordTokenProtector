# Some good practice when using DTP

## ✔️ If you use Discord on your browser, don't forget to disconnect from it after using it
Many grabbers also grab cookies / tokens from browsers on your computer. They sometimes only target the Discord token, therefore,
don't forget to **remove every cookies / data from discord.com**.\
If you want to log into Discord in your browser, please consider using the **incognito mode**.\
Furthermore, if you are logged into your browser, the Discord client will automatically connect to your account using handoff. This can be dangerous as some grabbers try to kill the DTP process to start the client without protection; with handoff you automatically leak your token.

## ✔️ Never log into you account manually on the client (except to resetup DTP yourself)
If you're using DTP, there's no reason to manually type your credentials / scan the QR code.\
If DTP doesn't automatically logs you in there are several reasons:
* It's a known bug that DTP is rarely unable to make you log into your account. Restarting your computer should fix the issue. (If it persists please open a ticket)
* Your Discord token has expired. You then just have to remove the token from DTP (in the account tab) and resetup it.
* **A malware killed the DTP process and is trying to get your token by making you relogin without the protection.**

## ✔️ Remember that DTP is not a perfect solution
Currently DTP can protect you from most of grabbers:
- (Most common) LevelDB reading *(from the beginning)*
- (Less common) Script injection / Discord module tampering *(from dev-6)*
- (Rare) Memory reading *(from dev-8)*

However, any very well targeted attacks against DTP can bypass the protection.\
**⚠️ Any process that has admin priviledges can disable this protection, and get your token ⚠️**\
**Please make sure to enable UAC (enabled by default) and do NOT give admin priviledges to any process!**

It is very recommended to start DTP with Windows and keep it running in the background (even when not using Discord), to avoid any tampering. If DTP is not running, it is very easy for a malware to replace/remove the DTP executable.