#Create role Capabilities   
$JEAGrantRightsRoleCapability = @{
    CompanyName = 'Scomnewbie LAB'
    Description = 'Toolbox dedicated to local admins account administration'
    ModulesToImport = 'C:\Custom_Modules\GrantLocalADmins.psm1'
    VisibleFunctions = 'TabExpansion2','Get-UserInfo','Set-ADUserJitAdmin'
    VisibleCmdlets     = 'Select-Object'
    #To avoid the 'does not belong to the set message'
    AliasDefinitions   = @{ Name = 'Select-Object' ; Value = 'Microsoft.PowerShell.Utility\Select-Object' }
    FunctionDefinition = @{
        Name = 'Get-UserInfo'
        Scriptblock = {
            $PSSenderInfo
        }
    }
}


#Session to access the roles and will define the endpoint
$SessionConfig = @{
    CompanyName = 'Scomnewbie LAB'
    SessionType = 'RestrictedRemoteServer'
    GroupManagedServiceAccount = 'Scomnewbie\JEAGrantRights'
    RoleDefinitions = @{
        'Scomnewbie\JEAUsers-GrantRights' = @{RoleCapabilities = 'JEAGrantRights'}
        #'Scomnewbie\NetworkAdmins' = @{RoleCapabilities = 'Network'}
    }
    TranscriptDirectory = 'C:\TranscriptsDirectory'
}

#Variables for the modules
$ModPAth = "$env:programFiles\WindowsPowershell\Modules" 
$ModName = "JEAGrantRights"

# Create then empty module to hold capability files
New-Item -Path "$ModPath\$ModName" -ItemType Directory
New-ModuleManifest -Path "$ModPath\$ModName\$ModName.psd1"

# Create the roles capability files
New-Item -Path "$ModPath\$ModName\RoleCapabilities" -ItemType Directory
#New-PSRoleCapabilityFile -Path "$ModPath\$ModName\RoleCapabilities\GnstoolsMSOLLicAdmin.psrc" @GnstoolsMSOLLicAdminRoleCapability
New-PSRoleCapabilityFile -Path "$ModPath\$ModName\RoleCapabilities\JEAGrantRights.psrc" @JEAGrantRightsRoleCapability
# View the role files
psedit "$ModPath\$ModName\RoleCapabilities" | Foreach-Object{psedit $_.Fullname}

# Create and view the session configuration with these roles
New-PSSessionConfigurationFile -Path ".\$ModName.pssc" @SessionConfig
psedit ".\$ModName.pssc"

# Create the transcript folder
New-Item -Path C:\TranscriptDirectory -ItemType Directory -Force -ea Silentlycontinue

# Register the session configuration with these roles
Register-PSSessionConfiguration -Name $ModName -Path ".\$ModName.pssc"
Restart-Service WinRM
Get-childItem C:\Windows\system32\WindowsPowershell\v1.0\SessionConfig

# Check it out, note the auto-generated SDDL from role groups
Get-PSSessionConfiguration -Name $ModName | fl *
# View the SDDL translation using the cmdlets
(Get-PSSessionConfiguration -Name $ModName).SecurityDescriptorSddl
ConvertFrom-SddlString -Sddl (Get-PSSessionConfiguration -Name $ModName).SecurityDescriptorSddl