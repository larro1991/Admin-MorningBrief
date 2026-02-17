#Requires -Modules Pester

<#
    Pester v5 tests for Admin-MorningBrief module.
    Run with:  Invoke-Pester -Path .\Tests\Admin-MorningBrief.Tests.ps1 -Output Detailed
#>

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..' 'Admin-MorningBrief.psd1'
    Import-Module $modulePath -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module Admin-MorningBrief -Force -ErrorAction SilentlyContinue
}

# ═══════════════════════════════════════════════════════════════════════
# Module-level tests
# ═══════════════════════════════════════════════════════════════════════
Describe 'Module: Admin-MorningBrief' {

    Context 'Module loading' {
        It 'Should import without errors' {
            { Import-Module $modulePath -Force } | Should -Not -Throw
        }

        It 'Should export exactly 5 public functions' {
            $mod = Get-Module Admin-MorningBrief
            $mod.ExportedFunctions.Count | Should -Be 5
        }

        It 'Should export Invoke-MorningBrief' {
            (Get-Command Invoke-MorningBrief -Module Admin-MorningBrief) | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-AccountAlerts' {
            (Get-Command Get-AccountAlerts -Module Admin-MorningBrief) | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-InfrastructureAlerts' {
            (Get-Command Get-InfrastructureAlerts -Module Admin-MorningBrief) | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-SecurityAlerts' {
            (Get-Command Get-SecurityAlerts -Module Admin-MorningBrief) | Should -Not -BeNullOrEmpty
        }

        It 'Should export Get-ExpirationAlerts' {
            (Get-Command Get-ExpirationAlerts -Module Admin-MorningBrief) | Should -Not -BeNullOrEmpty
        }

        It 'Should NOT export private function Get-AlertPriority' {
            { Get-Command Get-AlertPriority -Module Admin-MorningBrief -ErrorAction Stop } |
                Should -Throw
        }

        It 'Should NOT export private function New-HtmlDashboard' {
            { Get-Command New-HtmlDashboard -Module Admin-MorningBrief -ErrorAction Stop } |
                Should -Throw
        }
    }

    Context 'Manifest validation' {
        $manifest = Test-ModuleManifest -Path $modulePath -ErrorAction Stop

        It 'Should have a valid manifest' {
            $manifest | Should -Not -BeNullOrEmpty
        }

        It 'Should have GUID f6a7b8c9-3d24-4fa0-e1b2-7d8e9f0a1b23' {
            $manifest.GUID | Should -Be 'f6a7b8c9-3d24-4fa0-e1b2-7d8e9f0a1b23'
        }

        It 'Should require PowerShell 5.1' {
            $manifest.PowerShellVersion | Should -Be '5.1'
        }

        It 'Should have Author set to Larry Roberts' {
            $manifest.Author | Should -BeLike '*Larry Roberts*'
        }

        It 'Should have a description' {
            $manifest.Description | Should -Not -BeNullOrEmpty
        }

        It 'Should have a ProjectUri' {
            $manifest.PrivateData.PSData.ProjectUri | Should -Not -BeNullOrEmpty
        }

        It 'Should have tags' {
            $manifest.PrivateData.PSData.Tags | Should -Not -BeNullOrEmpty
            $manifest.PrivateData.PSData.Tags | Should -Contain 'Admin'
            $manifest.PrivateData.PSData.Tags | Should -Contain 'Dashboard'
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# Parameter validation tests
# ═══════════════════════════════════════════════════════════════════════
Describe 'Parameter validation' {

    Context 'Get-AccountAlerts parameters' {
        It 'Should accept -DaysPasswordExpiry' {
            (Get-Command Get-AccountAlerts).Parameters['DaysPasswordExpiry'] | Should -Not -BeNullOrEmpty
        }

        It 'Should accept -SearchBase' {
            (Get-Command Get-AccountAlerts).Parameters['SearchBase'] | Should -Not -BeNullOrEmpty
        }

        It 'Should default DaysPasswordExpiry to 14' {
            (Get-Command Get-AccountAlerts).Parameters['DaysPasswordExpiry'].Attributes |
                Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] } |
                ForEach-Object { $_.Mandatory } | Should -BeFalse
        }
    }

    Context 'Get-InfrastructureAlerts parameters' {
        It 'Should require -ComputerName' {
            $param = (Get-Command Get-InfrastructureAlerts).Parameters['ComputerName']
            $mandatory = $param.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] }
            $mandatory.Mandatory | Should -BeTrue
        }

        It 'Should accept -DiskThresholdPercent' {
            (Get-Command Get-InfrastructureAlerts).Parameters['DiskThresholdPercent'] | Should -Not -BeNullOrEmpty
        }

        It 'Should accept -UptimeThresholdDays' {
            (Get-Command Get-InfrastructureAlerts).Parameters['UptimeThresholdDays'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Get-SecurityAlerts parameters' {
        It 'Should accept -HoursBack' {
            (Get-Command Get-SecurityAlerts).Parameters['HoursBack'] | Should -Not -BeNullOrEmpty
        }

        It 'Should accept -FailedLoginThreshold' {
            (Get-Command Get-SecurityAlerts).Parameters['FailedLoginThreshold'] | Should -Not -BeNullOrEmpty
        }

        It 'Should accept -IncludeM365 switch' {
            $param = (Get-Command Get-SecurityAlerts).Parameters['IncludeM365']
            $param | Should -Not -BeNullOrEmpty
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }
    }

    Context 'Get-ExpirationAlerts parameters' {
        It 'Should accept -DaysCertExpiry' {
            (Get-Command Get-ExpirationAlerts).Parameters['DaysCertExpiry'] | Should -Not -BeNullOrEmpty
        }

        It 'Should accept -DaysPasswordExpiry' {
            (Get-Command Get-ExpirationAlerts).Parameters['DaysPasswordExpiry'] | Should -Not -BeNullOrEmpty
        }

        It 'Should accept -DaysAccountExpiry' {
            (Get-Command Get-ExpirationAlerts).Parameters['DaysAccountExpiry'] | Should -Not -BeNullOrEmpty
        }

        It 'Should accept -ComputerName' {
            (Get-Command Get-ExpirationAlerts).Parameters['ComputerName'] | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Invoke-MorningBrief parameters' {
        It 'Should accept -OutputPath' {
            (Get-Command Invoke-MorningBrief).Parameters['OutputPath'] | Should -Not -BeNullOrEmpty
        }

        It 'Should accept -SendEmail switch' {
            $param = (Get-Command Invoke-MorningBrief).Parameters['SendEmail']
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Should accept -SmtpServer' {
            (Get-Command Invoke-MorningBrief).Parameters['SmtpServer'] | Should -Not -BeNullOrEmpty
        }

        It 'Should accept -IncludeM365 switch' {
            $param = (Get-Command Invoke-MorningBrief).Parameters['IncludeM365']
            $param.ParameterType.Name | Should -Be 'SwitchParameter'
        }

        It 'Should accept -AutoRefreshSeconds' {
            (Get-Command Invoke-MorningBrief).Parameters['AutoRefreshSeconds'] | Should -Not -BeNullOrEmpty
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# Mock-based functional tests
# ═══════════════════════════════════════════════════════════════════════
Describe 'Get-AccountAlerts (mocked)' {

    BeforeAll {
        # Re-import so internal functions are available in the module scope
        Import-Module (Join-Path $PSScriptRoot '..' 'Admin-MorningBrief.psd1') -Force
    }

    It 'Should return LockedAccount alert when Search-ADAccount finds locked users' {
        # Mock inside the module scope
        InModuleScope Admin-MorningBrief {
            Mock Search-ADAccount {
                [PSCustomObject]@{
                    SamAccountName = 'jsmith'
                    DistinguishedName = 'CN=John Smith,OU=Users,DC=corp,DC=com'
                }
            }
            Mock Get-ADUser {
                [PSCustomObject]@{
                    SamAccountName = 'jsmith'
                    DisplayName    = 'John Smith'
                    LockedOut      = $true
                    lockoutTime    = ([datetime]'2026-02-16 07:15:00').ToFileTime()
                    Enabled        = $true
                }
            }
            Mock Get-ADDefaultDomainPasswordPolicy {
                [PSCustomObject]@{ MaxPasswordAge = New-TimeSpan -Days 90 }
            }

            $results = Get-AccountAlerts -DaysPasswordExpiry 14
            $locked  = @($results | Where-Object AlertType -eq 'LockedAccount')
            $locked.Count | Should -BeGreaterOrEqual 1
            $locked[0].Priority | Should -Be 'Critical'
            $locked[0].AffectedObject | Should -BeLike '*jsmith*'
        }
    }

    It 'Should return PasswordExpiring alert as HIGH when expiry is within 3 days' {
        InModuleScope Admin-MorningBrief {
            Mock Search-ADAccount { @() }
            Mock Get-ADDefaultDomainPasswordPolicy {
                [PSCustomObject]@{ MaxPasswordAge = New-TimeSpan -Days 90 }
            }
            Mock Get-ADUser {
                param($Filter, $Properties)
                # Only respond to the password-expiry query (Enabled filter)
                if ($Filter -and $Filter.ToString() -match 'Enabled') {
                    [PSCustomObject]@{
                        SamAccountName   = 'alee'
                        DisplayName      = 'Alice Lee'
                        PasswordLastSet  = (Get-Date).AddDays(-88)   # 2 days left
                        Enabled          = $true
                        PasswordNeverExpires = $false
                    }
                }
            }

            $results  = Get-AccountAlerts -DaysPasswordExpiry 14
            $pwAlerts = @($results | Where-Object AlertType -eq 'PasswordExpiring')
            $pwAlerts.Count | Should -BeGreaterOrEqual 1
            $pwAlerts[0].Priority | Should -Be 'High'
        }
    }
}

Describe 'Get-InfrastructureAlerts (mocked)' {

    It 'Should flag a critical disk when usage exceeds 95%' {
        InModuleScope Admin-MorningBrief {
            Mock New-CimSession { [PSCustomObject]@{ Id = 1 } }
            Mock Remove-CimSession {}
            Mock Get-CimInstance {
                param($CimSession, $ClassName, $Filter)
                if ($ClassName -eq 'Win32_LogicalDisk') {
                    [PSCustomObject]@{
                        DeviceID  = 'C:'
                        Size      = 100GB
                        FreeSpace = 3GB    # 97% used
                        DriveType = 3
                    }
                }
                elseif ($ClassName -eq 'Win32_Service') {
                    @()   # no stopped services
                }
                elseif ($ClassName -eq 'Win32_OperatingSystem') {
                    [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-10) }
                }
            }
            Mock Invoke-Command { $false }  # no pending reboot

            $results = Get-InfrastructureAlerts -ComputerName 'SQL02'
            $disk    = @($results | Where-Object AlertType -eq 'DiskSpaceCritical')
            $disk.Count | Should -Be 1
            $disk[0].Priority | Should -Be 'Critical'
            $disk[0].AffectedObject | Should -BeLike '*SQL02*C:*'
        }
    }

    It 'Should flag a stopped critical service' {
        InModuleScope Admin-MorningBrief {
            Mock New-CimSession { [PSCustomObject]@{ Id = 1 } }
            Mock Remove-CimSession {}
            Mock Get-CimInstance {
                param($CimSession, $ClassName, $Filter)
                if ($ClassName -eq 'Win32_LogicalDisk') { @() }
                elseif ($ClassName -eq 'Win32_Service') {
                    [PSCustomObject]@{
                        Name        = 'DNS'
                        DisplayName = 'DNS Server'
                        State       = 'Stopped'
                        StartMode   = 'Auto'
                    }
                }
                elseif ($ClassName -eq 'Win32_OperatingSystem') {
                    [PSCustomObject]@{ LastBootUpTime = (Get-Date).AddDays(-5) }
                }
            }
            Mock Invoke-Command { $false }

            $results = Get-InfrastructureAlerts -ComputerName 'DC03'
            $svcAlert = @($results | Where-Object AlertType -eq 'ServiceStopped')
            $svcAlert.Count | Should -Be 1
            $svcAlert[0].Priority | Should -Be 'Critical'
            $svcAlert[0].Detail | Should -BeLike '*DNS*Stopped*'
        }
    }

    It 'Should produce ServerUnreachable alert when CIM session fails' {
        InModuleScope Admin-MorningBrief {
            Mock New-CimSession { throw 'Connection refused' }

            $results = Get-InfrastructureAlerts -ComputerName 'OFFLINE01'
            $unreachable = @($results | Where-Object AlertType -eq 'ServerUnreachable')
            $unreachable.Count | Should -Be 1
            $unreachable[0].Priority | Should -Be 'Critical'
        }
    }
}

Describe 'Get-SecurityAlerts (mocked)' {

    It 'Should flag users exceeding failed login threshold' {
        InModuleScope Admin-MorningBrief {
            # Build 15 fake 4625 events for user "badactor"
            $fakeEvents = 1..15 | ForEach-Object {
                $props = @(
                    [PSCustomObject]@{ Value = '' },  # 0 - SubjectUserSid
                    [PSCustomObject]@{ Value = '' },  # 1 - SubjectUserName
                    [PSCustomObject]@{ Value = '' },  # 2 - SubjectDomainName
                    [PSCustomObject]@{ Value = '' },  # 3 - SubjectLogonId
                    [PSCustomObject]@{ Value = '' },  # 4 - TargetUserSid
                    [PSCustomObject]@{ Value = 'badactor' },  # 5 - TargetUserName
                    [PSCustomObject]@{ Value = 'CORP' },       # 6 - TargetDomainName
                    [PSCustomObject]@{ Value = '' },  # 7
                    [PSCustomObject]@{ Value = '' },  # 8
                    [PSCustomObject]@{ Value = '' },  # 9
                    [PSCustomObject]@{ Value = '' },  # 10
                    [PSCustomObject]@{ Value = '' },  # 11
                    [PSCustomObject]@{ Value = '' },  # 12
                    [PSCustomObject]@{ Value = '' },  # 13
                    [PSCustomObject]@{ Value = '' },  # 14
                    [PSCustomObject]@{ Value = '' },  # 15
                    [PSCustomObject]@{ Value = '' },  # 16
                    [PSCustomObject]@{ Value = '' },  # 17
                    [PSCustomObject]@{ Value = '' },  # 18
                    [PSCustomObject]@{ Value = '10.0.0.99' }   # 19 - IpAddress
                )
                [PSCustomObject]@{
                    Id          = 4625
                    TimeCreated = (Get-Date).AddMinutes(-$_)
                    Properties  = $props
                }
            }

            Mock Get-WinEvent { $fakeEvents }
            Mock Get-ADGroupMember { @() }  # skip admin checks

            $results = Get-SecurityAlerts -FailedLoginThreshold 10
            $failed  = @($results | Where-Object AlertType -eq 'FailedLoginsExceeded')
            $failed.Count | Should -Be 1
            $failed[0].Priority | Should -Be 'High'
            $failed[0].AffectedObject | Should -Be 'badactor'
            $failed[0].Detail | Should -BeLike '*15*failed*'
        }
    }
}

Describe 'Get-ExpirationAlerts (mocked)' {

    It 'Should flag a certificate expiring within 7 days as Critical' {
        InModuleScope Admin-MorningBrief {
            Mock Get-ChildItem {
                [PSCustomObject]@{
                    Subject      = 'CN=webapp.corp.com'
                    FriendlyName = 'WebApp SSL'
                    Thumbprint   = 'AABBCCDD11223344'
                    NotAfter     = (Get-Date).AddDays(5)
                    DnsNameList  = @('webapp.corp.com')
                }
            }
            Mock Get-ADDefaultDomainPasswordPolicy {
                [PSCustomObject]@{ MaxPasswordAge = New-TimeSpan -Days 90 }
            }
            Mock Get-ADUser { @() }
            Mock Get-ADDomain {
                [PSCustomObject]@{ DomainMode = 'Windows2016Domain'; DNSRoot = 'corp.com' }
            }
            Mock Get-ADForest {
                [PSCustomObject]@{ ForestMode = 'Windows2016Forest' }
            }

            $results  = Get-ExpirationAlerts -DaysCertExpiry 30
            $certAlert = @($results | Where-Object AlertType -eq 'CertificateExpiring')
            $certAlert.Count | Should -Be 1
            $certAlert[0].Priority | Should -Be 'Critical'
            $certAlert[0].Detail | Should -BeLike '*5 day*'
        }
    }

    It 'Should flag a certificate expiring within 14 days as High' {
        InModuleScope Admin-MorningBrief {
            Mock Get-ChildItem {
                [PSCustomObject]@{
                    Subject      = 'CN=mail.corp.com'
                    FriendlyName = 'Mail Cert'
                    Thumbprint   = 'EEFF00112233AABB'
                    NotAfter     = (Get-Date).AddDays(12)
                    DnsNameList  = @('mail.corp.com')
                }
            }
            Mock Get-ADDefaultDomainPasswordPolicy {
                [PSCustomObject]@{ MaxPasswordAge = New-TimeSpan -Days 90 }
            }
            Mock Get-ADUser { @() }
            Mock Get-ADDomain {
                [PSCustomObject]@{ DomainMode = 'Windows2016Domain'; DNSRoot = 'corp.com' }
            }
            Mock Get-ADForest {
                [PSCustomObject]@{ ForestMode = 'Windows2016Forest' }
            }

            $results  = Get-ExpirationAlerts -DaysCertExpiry 30
            $certAlert = @($results | Where-Object AlertType -eq 'CertificateExpiring')
            $certAlert.Count | Should -Be 1
            $certAlert[0].Priority | Should -Be 'High'
        }
    }
}

Describe 'Invoke-MorningBrief (mocked)' {

    It 'Should throw when -SendEmail is used without -SmtpServer' {
        { Invoke-MorningBrief -SendEmail -EmailTo 'a@b.com' -EmailFrom 'c@d.com' } |
            Should -Throw '*SmtpServer*'
    }

    It 'Should produce a summary object and HTML report' {
        InModuleScope Admin-MorningBrief {
            # Stub all alert functions to return controlled data
            Mock Get-AccountAlerts {
                @(
                    [PSCustomObject]@{
                        AlertType = 'LockedAccount'; Priority = 'Critical'; Source = 'ActiveDirectory'
                        AffectedObject = 'jsmith'; Detail = 'Locked out'; Timestamp = (Get-Date)
                        Category = 'Account'; ColorCode = '#f85149'; SortOrder = 1
                    }
                )
            }
            Mock Get-InfrastructureAlerts {
                @(
                    [PSCustomObject]@{
                        AlertType = 'DiskSpaceCritical'; Priority = 'Critical'; Source = 'Infrastructure'
                        AffectedObject = 'SQL02 (C:)'; Detail = '97% full'; Timestamp = (Get-Date)
                        Category = 'Infrastructure'; ColorCode = '#f85149'; SortOrder = 1
                    }
                )
            }
            Mock Get-SecurityAlerts { @() }
            Mock Get-ExpirationAlerts {
                @(
                    [PSCustomObject]@{
                        AlertType = 'CertificateExpiring'; Priority = 'High'; Source = 'Certificates'
                        AffectedObject = 'WEB01 - SSL'; Detail = 'Expires in 10 days'; Timestamp = (Get-Date)
                        Category = 'Expiration'; ColorCode = '#d29922'; SortOrder = 2
                    }
                )
            }

            $outputDir = Join-Path $TestDrive 'Reports'
            $result    = Invoke-MorningBrief -ComputerName 'SQL02' -OutputPath $outputDir

            $result.CriticalCount | Should -Be 2
            $result.HighCount     | Should -Be 1
            $result.TotalCount    | Should -Be 3
            $result.ReportPath    | Should -Not -BeNullOrEmpty
            Test-Path $result.ReportPath | Should -BeTrue

            # Verify HTML contains key elements
            $html = Get-Content $result.ReportPath -Raw
            $html | Should -BeLike '*Morning Brief*'
            $html | Should -BeLike '*jsmith*'
            $html | Should -BeLike '*SQL02*'
        }
    }
}

Describe 'Get-AlertPriority (private, tested via InModuleScope)' {

    It 'Should return Critical for LockedAccount' {
        InModuleScope Admin-MorningBrief {
            $p = Get-AlertPriority -AlertType 'LockedAccount'
            $p.Priority  | Should -Be 'Critical'
            $p.SortOrder | Should -Be 1
        }
    }

    It 'Should return High for PasswordExpiring with 2 days left' {
        InModuleScope Admin-MorningBrief {
            $p = Get-AlertPriority -AlertType 'PasswordExpiring' -Detail @{ DaysUntilExpiry = 2 }
            $p.Priority | Should -Be 'High'
        }
    }

    It 'Should return Medium for PasswordExpiring with 10 days left' {
        InModuleScope Admin-MorningBrief {
            $p = Get-AlertPriority -AlertType 'PasswordExpiring' -Detail @{ DaysUntilExpiry = 10 }
            $p.Priority | Should -Be 'Medium'
        }
    }

    It 'Should return Critical for CertificateExpiring with 5 days left' {
        InModuleScope Admin-MorningBrief {
            $p = Get-AlertPriority -AlertType 'CertificateExpiring' -Detail @{ DaysUntilExpiry = 5 }
            $p.Priority | Should -Be 'Critical'
        }
    }

    It 'Should return Medium for unknown alert types' {
        InModuleScope Admin-MorningBrief {
            $p = Get-AlertPriority -AlertType 'SomethingNew'
            $p.Priority | Should -Be 'Medium'
        }
    }
}
