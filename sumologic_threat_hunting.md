### INITIAL ACCESS

1. External RDP Login (T1078)
```spl
index=security EventCode=4624 LogonType=10 | stats count by src_ip,user,host
```
Severity: Medium | Confidence: High | FP Notes: VPN or legit remote work

2. Brute Force Failures (T1110)
```spl
index=security EventCode=4625 | stats count by src_ip,user | where count>5
```
Severity: High | Confidence: Medium | FP Notes: NAT gateways possible

3. Phishing Email Link Clicks (T1566)
```spl
index=email EventType=click | stats count by user, sender, link
```
Severity: Medium | Confidence: Medium | FP Notes: Training exercises

4. Suspicious OAuth Consent (T1528)
```spl
oauth consent granted | where app not in [AUTHORIZED_APPS]
```
Severity: Medium | Confidence: Medium | FP Notes: New SaaS app

5. New Account Creation (T1136)
```spl
user created | where role matches /(admin|privileged)/
```
Severity: High | Confidence: High | FP Notes: Legit HR onboarding

6. Temporary Account Use (T1078)
```spl
login success | where user matches /temp/i
```
Severity: Medium | Confidence: Medium | FP Notes: Contractor accounts

7. Password Spray Attempt (T1110)
```spl
_failed login | stats count by src_ip,user | where count>10
```
Severity: High | Confidence: Medium | FP Notes: High rate of attempts

8. Login From New Geo Location (T1078)
```spl
login success | geoip src_ip as country | where country not in [AUTHORIZED_COUNTRIES]
```
Severity: Medium | Confidence: Medium | FP Notes: Travel or VPN

9. Impossible Travel (T1078)
```spl
login success | timeslice 1h | count_distinct country by user | where count>2
```
Severity: High | Confidence: Medium | FP Notes: Suspicious geo pattern

10. Disabled Account Login Attempt (T1078)
```spl
login attempt | where account_status='disabled'
```
Severity: High | Confidence: High | FP Notes: Rare event

---
### EXECUTION

11. Suspicious PowerShell (T1059)
```spl
index=windows powershell ScriptBlockText!=null | stats count by user,host
```
Severity: High | Confidence: Medium | FP Notes: Admin scripts

12. Encoded Command Execution (T1027)
```spl
powershell | where CommandLine matches /-enc/i
```
Severity: High | Confidence: High | FP Notes: Rare legit use

13. Office Macro Execution (T1204)
```spl
office macro executed | stats by user,host
```
Severity: Medium | Confidence: Medium | FP Notes: Legacy workflows

14. LOLBins Abuse (T1218)
```spl
process_name in (certutil.exe,mshta.exe,rundll32.exe)
```
Severity: High | Confidence: High | FP Notes: Minimal

15. Script From Temp Directory (T1059)
```spl
process_path matches /temp/
```
Severity: Medium | Confidence: Medium | FP Notes: Installers

---
### PERSISTENCE

16. Registry Run Key Added (T1547)
```spl
registry_key="Run" action=created
```
Severity: High | Confidence: High | FP Notes: Software installs

17. Scheduled Task Created (T1053)
```spl
task created | stats by user,task_name
```
Severity: Medium | Confidence: Medium | FP Notes: Patch jobs

18. New Service Installed (T1543)
```spl
service installed | stats by service_name
```
Severity: High | Confidence: High | FP Notes: Monitoring agents

19. Startup Folder Abuse (T1547)
```spl
file_path matches /Startup/
```
Severity: Medium | Confidence: Medium | FP Notes: Rare

20. WMI Event Subscription (T1546)
```spl
wmi event consumer created
```
Severity: High | Confidence: High | FP Notes: Very rare

---
### PRIVILEGE ESCALATION

21. Admin Group Membership Change (T1098)
```spl
group=Administrators action=added
```
Severity: High | Confidence: High | FP Notes: IT ops

22. UAC Bypass Indicators (T1548)
```spl
process integrity=high parent!=explorer.exe
```
Severity: High | Confidence: Medium | FP Notes: Installers

23. Token Impersonation (T1134)
```spl
token_type=delegation
```
Severity: High | Confidence: High | FP Notes: Rare

24. Exploit Tool Execution (T1068)
```spl
process_name matches /(mimikatz|winpeas)/i
```
Severity: Critical | Confidence: High | FP Notes: None

25. Sudo Abuse (T1548)
```spl
index=linux command=sudo | stats by user
```
Severity: Medium | Confidence: Medium | FP Notes: Admins

---
### DEFENSE EVASION

26. AV Disabled (T1562)
```spl
antivirus status=disabled
```
Severity: Critical | Confidence: High | FP Notes: Rare

27. Log Clearing (T1070)
```spl
event action=log_cleared
```
Severity: High | Confidence: High | FP Notes: Maintenance

28. File Masquerading (T1036)
```spl
file_name matches /(svchost|lsass)\.exe/
```
Severity: High | Confidence: Medium | FP Notes: False names

29. Process Injection (T1055)
```spl
process injected=true
```
Severity: Critical | Confidence: High | FP Notes: None

30. Signed Binary Proxy Execution (T1218)
```spl
parent_process!=expected
```
Severity: High | Confidence: Medium | FP Notes: Edge cases

---
### CREDENTIAL ACCESS

31. LSASS Access (T1003)
```spl
process accesses lsass.exe
```
Severity: Critical | Confidence: High | FP Notes: None

32. Credential Dump Tools (T1003)
```spl
process_name in (mimikatz.exe,procdump.exe)
```
Severity: Critical | Confidence: High | FP Notes: None

33. Browser Credential Access (T1555)
```spl
browser credential read
```
Severity: High | Confidence: Medium | FP Notes: Password managers

34. Keylogging Activity (T1056)
```spl
api_call=GetAsyncKeyState
```
Severity: Critical | Confidence: High | FP Notes: None

35. NTDS.dit Access (T1003)
```spl
file_access=ntds.dit
```
Severity: Critical | Confidence: High | FP Notes: None

---
### DISCOVERY

36. Account Enumeration (T1087)
```spl
net user /domain
```
Severity: Medium | Confidence: Medium | FP Notes: Admin tasks

37. Network Discovery (T1016)
```spl
arp -a OR ipconfig
```
Severity: Low | Confidence: Medium | FP Notes: Troubleshooting

38. Security Tool Discovery (T1518)
```spl
process lists antivirus
```
Severity: Medium | Confidence: Medium | FP Notes: Inventory scripts

39. Domain Trust Discovery (T1482)
```spl
trust enumeration
```
Severity: High | Confidence: Medium | FP Notes: Rare

40. File Share Discovery (T1135)
```spl
net view
```
Severity: Medium | Confidence: Medium | FP Notes: Admin use

---
### LATERAL MOVEMENT

41. SMB Lateral Movement (T1021)
```spl
logon_type=3 src!=dest
```
Severity: High | Confidence: Medium | FP Notes: Admin access

42. RDP Internal Spread (T1021)
```spl
internal rdp login
```
Severity: High | Confidence: Medium | FP Notes: IT ops

43. PsExec Usage (T1569)
```spl
process_name=psexec.exe
```
Severity: Critical | Confidence: High | FP Notes: None

44. WinRM Abuse (T1021)
```spl
winrm session started
```
Severity: High | Confidence: Medium | FP Notes: Automation

45. SSH Key Reuse (T1021)
```spl
ssh login reused key
```
Severity: Medium | Confidence: Medium | FP Notes: DevOps

---
### COMMAND AND CONTROL

46. Beaconing Traffic (T1071)
```spl
network pattern=periodic
```
Severity: High | Confidence: Medium | FP Notes: Monitoring tools

47. DNS Tunneling (T1071)
```spl
dns query length>50
```
Severity: Critical | Confidence: High | FP Notes: None

48. C2 Over HTTPS (T1071)
```spl
ssl dest not in allowlist
```
Severity: High | Confidence: Medium | FP Notes: SaaS apps

49. TOR Traffic (T1090)
```spl
dest_port=9001
```
Severity: Critical | Confidence: High | FP Notes: None

50. Dead Drop Resolver (T1105)
```spl
url matches pastebin
```
Severity: High | Confidence: Medium | FP Notes: Research

---
### EXFILTRATION

51. Large Data Transfer (T1041)
```spl
bytes_out>1GB
```
Severity: High | Confidence: Medium | FP Notes: Backups

52. Cloud Storage Upload (T1567)
```spl
dest in (dropbox,mega)
```
Severity: High | Confidence: Medium | FP Notes: Legit sharing

53. Email Exfiltration (T1048)
```spl
smtp attachments large
```
Severity: High | Confidence: Medium | FP Notes: Reports

54. Archive Before Exfil (T1560)
```spl
tar or zip executed
```
Severity: Medium | Confidence: Medium | FP Notes: Backups

55. Database Dump (T1005)
```spl
mysqldump OR pg_dump
```
Severity: Critical | Confidence: High | FP Notes: DB admins

---
### IMPACT

56. Ransomware Extension (T1486)
```spl
file extension matches /(lock|crypt)/
```
Severity: Critical | Confidence: High | FP Notes: None

57. Shadow Copy Deletion (T1490)
```spl
vssadmin delete shadows
```
Severity: Critical | Confidence: High | FP Notes: None

58. Service Stop (T1489)
```spl
service stopped unexpectedly
```
Severity: High | Confidence: Medium | FP Notes: Maintenance

59. Disk Wipe Attempt (T1485)
```spl
disk wipe command
```
Severity: Critical | Confidence: High | FP Notes: None

60. Defacement Indicators (T1491)
```spl
web file modified
```
Severity: High | Confidence: Medium | FP Notes: Web updates

---
### CLOUD & SAAS

61. Impossible Cloud Login (T1078)
```spl
cloud login geo anomaly
```
Severity: High | Confidence: Medium | FP Notes: VPN

62. Excessive API Calls (T1528)
```spl
api calls spike
```
Severity: Medium | Confidence: Medium | FP Notes: Automation

63. IAM Role Abuse (T1098)
```spl
iam role modified
```
Severity: High | Confidence: High | FP Notes: Cloud ops

64. Public Bucket Creation (T1530)
```spl
bucket public=true
```
Severity: High | Confidence: High | FP Notes: Misconfig

65. Token Reuse (T1528)
```spl
oauth token reused
```
Severity: Medium | Confidence: Medium | FP Notes: Legit apps

---
### CONTAINER / K8S

66. Pod Exec Abuse (T1609)
```spl
kubectl exec
```
Severity: High | Confidence: Medium | FP Notes: Debugging

67. Privileged Container (T1611)
```spl
container privileged=true
```
Severity: Critical | Confidence: High | FP Notes: Rare

68. K8s Secret Access (T1552)
```spl
secret accessed
```
Severity: High | Confidence: High | FP Notes: Deployments

69. Image Pull From Untrusted Registry (T1190)
```spl
image registry not allowed
```
Severity: High | Confidence: Medium | FP Notes: Testing

70. Node Shell Access (T1609)
```spl
node shell started
```
Severity: Critical | Confidence: High | FP Notes: None

---
### ADVANCED / ANOMALY

71. Living Off The Land Burst (T1218)
```spl
multiple lolbins executed
```
Severity: High | Confidence: Medium | FP Notes: Power users

72. Time-Based Evasion (T1497)
```spl
sleep command detected
```
Severity: Medium | Confidence: Medium | FP Notes: Scripts

73. Rare Parent-Child Process (T1059)
```spl
rare process chain
```
Severity: High | Confidence: Medium | FP Notes: Edge cases

74. User Behavior Deviation (UEBA)
```spl
user risk score spike
```
Severity: High | Confidence: Medium | FP Notes: Role change

75. Host Risk Accumulation
```spl
risk_score>90
```
Severity: Critical | Confidence: High | FP Notes: None

---
### THREAT ACTOR TRADECRAFT

76. Cobalt Strike Indicators (T1071)
```spl
c2 pattern=cobaltstrike
```
Severity: Critical | Confidence: High | FP Notes: None

77. Sliver Framework Use
```spl
process_name=sliver
```
Severity: Critical | Confidence: High | FP Notes: None

78. Brute Ratel Indicators
```spl
bruteratel beacon
```
Severity: Critical | Confidence: High | FP Notes: None

79. Custom Loader Execution
```spl
unsigned loader
```
Severity: High | Confidence: Medium | FP Notes: Rare

80. Memory-Only Payload
```spl
no file write detected
```
Severity: Critical | Confidence: High | FP Notes: None

---
### POST-COMPROMISE

81. Internal Recon Burst
```spl
multiple discovery cmds
```
Severity: High | Confidence: Medium | FP Notes: Admins

82. Lateral + Priv Esc Chain
```spl
correlated alerts
```
Severity: Critical | Confidence: High | FP Notes: None

83. Dormant Account Reactivation
```spl
account enabled after inactivity
```
Severity: High | Confidence: Medium | FP Notes: Contractors

84. Backup Deletion (T1490)
```spl
backup deleted
```
Severity: Critical | Confidence: High | FP Notes: None

85. Security Tool Tampering
```spl
edr service stopped
```
Severity: Critical | Confidence: High | FP Notes: None

---
### IMPACT / BUSINESS RISK

86. Data Integrity Violation
```spl
hash mismatch detected
```
Severity: High | Confidence: Medium | FP Notes: Updates

87. Availability Degradation
```spl
service uptime drop
```
Severity: High | Confidence: Medium | FP Notes: Outages

88. Financial System Access
```spl
finance app accessed anomalously
```
Severity: Critical | Confidence: High | FP Notes: None

89. Executive Account Access
```spl
exec user login anomaly
```
Severity: Critical | Confidence: High | FP Notes: Travel

90. Legal / Compliance Data Touched
```spl
pii or phi accessed
```
Severity: Critical | Confidence: High | FP Notes: Audits

---
### META / HUNT OPS

91. Alert Fatigue Indicator
```spl
alerts per analyst>threshold
```
Severity: Medium | Confidence: Medium | FP Notes: Staffing

92. Blind Spot Detection
```spl
data source silent
```
Severity: High | Confidence: Medium | FP Notes: Maintenance

93. Logging Disabled
```spl
logging status=off
```
Severity: Critical | Confidence: High | FP Notes: None

94. Sensor Coverage Gap
```spl
host missing edr
```
Severity: High | Confidence: Medium | FP Notes: New assets

95. Threat Intel Match
```spl
ioc matched
```
Severity: Critical | Confidence: High | FP Notes: None

---
### HUNT CONCLUSIONS

96. Multi-Stage Kill Chain Detected
```spl
killchain stage>=3
```
Severity: Critical | Confidence: High | FP Notes: None

97. Repeat Victim Host
```spl
host compromised again
```
Severity: High | Confidence: High | FP Notes: Legacy systems

98. Uncontained Threat
```spl
incident unresolved>24h
```
Severity: Critical | Confidence: High | FP Notes: None

99. Threat Actor Dwell Time Exceeded
```spl
dwell_time>30d
```
Severity: Critical | Confidence: High | FP Notes: None

100. Confirmed Breach
```spl
incident status=confirmed
```
Severity: Critical | Confidence: High | FP Notes: None

