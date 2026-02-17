# Admin-MorningBrief

**What if your first 15 minutes didn't involve checking 6 different consoles?**

Admin-MorningBrief is a PowerShell module that gives you a single, prioritised view of everything that needs attention in your Windows environment. One command, one dark-themed HTML dashboard: locked accounts, failing disks, stopped services, expiring certificates, security events, and more -- all ranked by severity so you know exactly where to start.

## Quick Start

```powershell
# Import the module
Import-Module .\Admin-MorningBrief.psd1

# Basic run -- checks AD accounts, security events, and local certificates
Invoke-MorningBrief

# Full run against every server in your Servers OU
Invoke-MorningBrief -ComputerName (Get-ADComputer -Filter * -SearchBase "OU=Servers,DC=corp,DC=com").Name

# Include Microsoft 365 / Entra ID risky sign-in checks
Invoke-MorningBrief -ComputerName DC01, SQL02, WEB01 -IncludeM365

# E-mail the report to the team
Invoke-MorningBrief -ComputerName DC01, SQL02 `
    -SendEmail -SmtpServer mail.corp.com `
    -EmailTo ops-team@corp.com -EmailFrom brief@corp.com
```

## What Gets Checked

| Category | Alert Type | Priority |
|---|---|---|
| **Accounts** | Locked-out accounts | Critical |
| | Passwords expiring in < 3 days | High |
| | Passwords expiring in < 14 days | Medium |
| | Expired accounts | High |
| | Recently disabled accounts (24h) | Low |
| | Newly created accounts (24h) | Low |
| **Infrastructure** | Disk usage > 95% | Critical |
| | Disk usage > 90% | High |
| | Critical services stopped (DNS, DHCP, NTDS, ...) | Critical |
| | Pending reboot | High |
| | Critical event log entries (24h) | High |
| | Error event log entries (24h) | Medium |
| | Uptime > 90 days (needs patching reboot) | Medium |
| | Server unreachable | Critical |
| **Security** | Failed logins above threshold | High |
| | Privileged group membership changes | Critical |
| | Admin logon from unusual source | High |
| | Entra risky sign-ins (with `-IncludeM365`) | Critical / High |
| | Entra risky users (with `-IncludeM365`) | High |
| **Expirations** | Certificates expiring in < 7 days | Critical |
| | Certificates expiring in < 14 days | High |
| | Certificates expiring in < 30 days | Medium |
| | Service account passwords expiring | High |
| | User accounts approaching expiration | Medium |
| | DHCP scope utilization > 90% | High |
| | Domain functional level (informational) | Low |

## The Dashboard

The HTML report uses a dark theme with a blue accent (`#58a6ff`) and is designed to be:

- **Scannable** -- critical items at the top in red, then high (orange), medium (yellow), low (gray).
- **Print-friendly** -- colours adapt for light backgrounds when printed.
- **Wall-display ready** -- pass `-AutoRefreshSeconds 300` and open it in a kiosk browser.

Summary cards at the top show counts per priority level at a glance. Each alert shows a severity badge, the source system, alert type, the affected object, detail text, and timestamp.

Open `Samples/sample-report.html` in a browser to see a realistic example.

## Using Individual Alert Functions

Each check is also available as a standalone command:

```powershell
# Just account health
Get-AccountAlerts -DaysPasswordExpiry 7

# Infrastructure across specific servers
Get-InfrastructureAlerts -ComputerName DC01, SQL02, WEB01 -DiskThresholdPercent 85

# Security events from the last 12 hours
Get-SecurityAlerts -HoursBack 12 -FailedLoginThreshold 5 -IncludeM365

# Expiring certificates and accounts
Get-ExpirationAlerts -DaysCertExpiry 14 -ComputerName WEB01, WEB02
```

All functions return uniform `PSCustomObject` arrays with these properties:

| Property | Description |
|---|---|
| `AlertType` | Canonical alert name (e.g. `LockedAccount`, `DiskSpaceCritical`) |
| `Priority` | `Critical`, `High`, `Medium`, or `Low` |
| `Source` | Originating system (`ActiveDirectory`, `Infrastructure`, `Security`, etc.) |
| `AffectedObject` | The user, server, or resource affected |
| `Detail` | Human-readable description |
| `Timestamp` | When the condition was detected or occurred |
| `Category` | Grouping category (`Account`, `Infrastructure`, `Security`, `Expiration`) |
| `ColorCode` | Hex colour for rendering |
| `SortOrder` | Numeric sort key (1 = Critical, 4 = Low) |

## Scheduled Task Setup

Generate the brief automatically before you arrive so it is ready on your desktop:

```powershell
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument @"
-NoProfile -ExecutionPolicy Bypass -Command "
    Import-Module C:\Tools\Admin-MorningBrief\Admin-MorningBrief.psd1;
    Invoke-MorningBrief -ComputerName DC01,DC02,SQL01,SQL02,WEB01,WEB02 `
        -OutputPath C:\Reports\MorningBrief `
        -SendEmail -SmtpServer mail.corp.com `
        -EmailTo admin@corp.com -EmailFrom brief@corp.com
"
"@

$trigger = New-ScheduledTaskTrigger -Daily -At '06:30AM'

$principal = New-ScheduledTaskPrincipal `
    -UserId 'CORP\svc-morningbrief' `
    -LogonType Password `
    -RunLevel Highest

Register-ScheduledTask -TaskName 'Admin-MorningBrief' `
    -Action $action -Trigger $trigger -Principal $principal `
    -Description 'Generate daily morning brief report'
```

> **Tip:** The service account needs read access to AD, remote CIM access to the servers, and (if using `-IncludeM365`) an app registration with `IdentityRiskyUser.Read.All` and `IdentityRiskySignIn.Read.All` permissions.

## Requirements

- **PowerShell 5.1** or later (runs on Windows PowerShell and PowerShell 7)
- **ActiveDirectory** module (RSAT) for account and security checks
- **Remote CIM** access to target servers for infrastructure checks
- **Microsoft.Graph** module (optional) for Entra ID / M365 checks
- **DhcpServer** module (optional) for DHCP scope utilisation checks

## Installation

Copy the module folder to a PSModulePath location:

```powershell
Copy-Item -Recurse .\Admin-MorningBrief\ "$HOME\Documents\PowerShell\Modules\Admin-MorningBrief"
```

Or import directly:

```powershell
Import-Module .\Admin-MorningBrief\Admin-MorningBrief.psd1
```

## Testing

```powershell
# Requires Pester v5
Invoke-Pester -Path .\Tests\Admin-MorningBrief.Tests.ps1 -Output Detailed
```

## License

MIT License -- see [LICENSE](LICENSE).
