@{
    RootModule        = 'Admin-MorningBrief.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'f6a7b8c9-3d24-4fa0-e1b2-7d8e9f0a1b23'
    Author            = 'Larry Roberts, Independent Consultant'
    CompanyName       = 'Independent'
    Copyright         = '(c) 2026 Larry Roberts. All rights reserved.'
    Description       = 'Daily admin morning briefing. One command to see locked accounts, disk alerts, security events, and expiring certificates across your environment.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-MorningBrief',
        'Get-AccountAlerts',
        'Get-InfrastructureAlerts',
        'Get-SecurityAlerts',
        'Get-ExpirationAlerts'
    )
    CmdletsToExport   = @()
    VariablesToExport  = @()
    AliasesToExport    = @()
    PrivateData        = @{
        PSData = @{
            Tags         = @('Admin', 'Morning', 'Brief', 'Dashboard', 'Alerts', 'Monitoring', 'Security', 'Infrastructure')
            LicenseUri   = 'https://github.com/larro1991/Admin-MorningBrief/blob/master/LICENSE'
            ProjectUri   = 'https://github.com/larro1991/Admin-MorningBrief'
            ReleaseNotes = 'Initial release - Morning Command Center for Windows administrators.'
        }
    }
}
