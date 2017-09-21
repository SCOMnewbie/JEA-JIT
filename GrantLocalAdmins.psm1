function Initialize-EventLog {
    param(
        [string]$LogName,
        [string]$SourceName
    )
	
    New-EventLog -LogName $LogName -Source $SourceName
    Write-EventLog -LogName $LogName -Source $SourceName -EntryType Information -EventId 0 -Message "Log initialized"
}

function Test-EventLog {
    param(
        [string]$LogName,
        [string]$SourceName
    )
	
    Try {
        if ((Get-EventLog -LogName $LogName -Source $SourceName).count -ne 0) {
            Get-EventLog -LogName $LogName -Source $SourceName -Newest 1 | Out-Null
        }
        else {
            Write-EventLog -LogName $LogName -Source $SourceName -EntryType Information -EventId 0 -Message "Log initialized"
        }
        Write-Verbose "EventLog Initialized"
    }
    Catch {
        Initialize-EventLog -LogName $LogName -Source $SourceName
    }
}

function Test-DBConnection {
    param(
        $Database,
        $ServerInstance
    )

    #Requires -version 5
    #Requires -modules sqlserver
		
    $TestConnDate = Invoke-sqlcmd -Query "SELECT GETDATE()" -Database $Database -ServerInstance $ServerInstance  -querytimeout 200 -AbortOnError
    [int]$CheckValue = (New-TimeSpan $(Get-Date) $TestConnDate.Column1).days
    $CheckValue
}

Function Set-ADUserJitAdmin {

    ##########################################################################################################
    <#
    .SYNOPSIS
        Grant temporary privilege access to a team or an application based on Authorization depending of a
        good AD structure.
     
    .DESCRIPTION
        Grant temporary privilege access to a team or an application depending of the good AD structure.
        Team and Application can be added/removed for the param.
        0.25 TTLHours means 15 minutes
        $UserToGrantAccess parameter verify the UPN. Make sure you change it.
        Reasons is mandatory because each time you need admin access, you should have a change related to it.
        We can of course disable the mandatory part 

    .EXAMPLE
        Set-ADUserJitAdmin -TeamName PokemonTeam
                           -Application Skype 
                           -TtlHours 0.25
                           -UserToGrantAccess "robert@scomnewbie.local","raoul@scomnewbie.local"
                           -Reasons "Ticket number REQ25698"
                        
        Will add robert and raoul local admin of the Skype server application only if they are Authorized.
        To allow them, make sure that the account are put into the Authorized<Application>Admins group.

    .EXAMPLE
        Set-ADUserJitAdmin -TeamName PokemonTeam
                           -TtlHours 0.25
                           -UserToGrantAccess "robert@scomnewbie.local","raoul@scomnewbie.local"
                           -Reasons "Ticket number REQ25698"
                        
        Will add robert and raoul local admins of all team servers only if they are Authorized. To allow them,
        make sure that the account are put into the Authorized<Team>Admins group. 

    .NOTES
        THIS CODE-SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
        OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
        FITNESS FOR A PARTICULAR PURPOSE. 

        This script is an idea based on this script: https://gallery.technet.microsoft.com/scriptcenter/Set-ADUserJitAdmin-b8bb1f47
    #>
    ##########################################################################################################

    #Requires -version 5
    #Requires -modules ActiveDirectory

    #Authors: Scomnewbie
    #Version: 1.0

    #Define and validate parameters
    [CmdletBinding()]
    Param(
        #TeamName
        [parameter(Mandatory, Position = 1)]
        [ValidateSet("PokemonTeam", "DBZTeam", "NarutoTeam")]
        [String]$TeamName,

        #Application
        [parameter(Mandatory = $false, Position = 2)]
        [ValidateSet("Exchange", "Skype")]
        [String]$Application,

        #The amount of time, in hours, that the user is granted privileged access 0.25 means 15 min
        [parameter(Mandatory, Position = 3)]
        [ValidateSet("0.25", "0.5", "0.75", "1", "1.5", "2", "2.5", "3")]
        [string]$TtlHours,

        #Who
        [parameter(Mandatory, Position = 4)]
        [ValidatePattern('.+@(scomnewbie.local|Myotherdomain.local)\b')]
        [array]$UserToGrantAccess,

        #Why
        [parameter(Mandatory, Position = 5)]
        [string]$Reasons

    )

    ################################
    ###         Variables        ###
    ################################

    ##########################################
    #### Place to change with your values ####

    #Logging Variables
    [string]$LogName = "GrantLocalAdmin"
    [string]$SourceName = "TeamAndApplication"
    
		
    #Database Variables
    $Database = "JEA-GrantLocalAdmin"
    $ServerInstance = "JEA\SQLEXPRESS"
    $GrantLocalAdminHistory = "[dbo].[GrantLocalAdminHistory]"

    #### END of Place to change with your values ####
    #################################################
 
    #Create datetime variables for dynamic groups and SQL
    $SmallDate = "{0:yyyyMMddHHmmss}" -f (get-date)
    $SQLFormatDate = Get-Date -format 'yyyy-MM-dd hh:m:s.fff'

    #Create the temporary dynamic group name for the dedicated application servers
    if ($Application) {
        $DynamicGroupName = "DG-$TeamName-$Application-$SmallDate"
    }
    #Request access for all team servers
    else {
        $DynamicGroupName = "DG-$TeamName-$SmallDate" 
    }

    #Get the domain distingusihed name (Simple case where we only have one forest/Domain)
    $DomainDn = (Get-ADDomain).DistinguishedName

    #Construct an distinguished name to store the Dynamic Groups
    if ($Application) {
        $ContainerDn = "OU=Dynamic_Groups,OU=Delegation,OU=$Application,OU=$TeamName,$DomainDn"
    }
    else {
        $ContainerDn = "OU=Dynamic_Groups,OU=Delegation,OU=$TeamName,$DomainDn"
    }

    #Get a System.DirectoryServices.DirectoryEntry object representing the container
    $Container = [ADSI]("LDAP://$ContainerDn")

    ################################
    ###           Main           ###
    ################################

    #region PreReqSQL	
    #Test DB Connection
    $DBTest = Test-DBConnection -Database $Database -ServerInstance $ServerInstance -SourceName $SourceName -LogName $LogName
	
    #Depending of the hour of the day, the result can be 0 or 1
    if (! (($DBTest -eq 0) -or ($DBTest -eq 1))) {
        Write-EventLog -LogName $LogName -Source $SourceName -EntryType Error -EventId 102 -Message "Unable to contact the database $Database\$ServerInstance"
        Write-Output "Unable to contact the database $Database\$ServerInstance"
        exit
    }	
    #EndRegion

    #Now we know that the DB seems to be up and running

    #Use the container object to create the temporary dynamic group
    $DynamicGroup = $Container.Create("group", "CN=$DynamicGroupName") 
        
    #Check that we have created the dynamic group
    if (!$DynamicGroup) {
        #Write error
        Write-Error -Message "Unable to create dynamic group!" -ErrorAction Stop
    }   #end of if ($DynamicGroup)

    $DynamicGroup.PutEx(2, "objectClass", @("dynamicObject", "group"))  | out-null
    $DynamicGroup.Put("msDS-Entry-Time-To-Die", [datetime]::UtcNow.AddHours($TtlHours)) | out-null
    $DynamicGroup.Put("sAMAccountName", $DynamicGroupName)  | out-null
    $DynamicGroup.Put("displayName", $DynamicGroupName)  | out-null
    $DynamicGroup.Put("description", "Temporary group to grant local admin on machines from the team $TeamName")  | out-null
    $DynamicGroup.SetInfo() | out-null

    #Check that the additional information has been set on the dynamic group
    if ($?) {

        #Write to console
        Write-Output "$(Get-Date -f T) - `'CN=$DynamicGroupName,$ContainerDn `' created and set to expire in $TtlHours hours"

    }   #end of if ($?)
    else {

        #Write error
        Write-Output -Message "Unable to configure dynamic group settings!" -ErrorAction Stop

    }   #end of else ($?)

    #Here the dynamic group should be created time to populate it with users.

    $ADObjectUsers = @()
    Foreach ($user in $UserToGrantAccess) {

        $ADUser = Get-ADUser -Filter {userprincipalName -eq $user} -Properties memberof -ErrorAction SilentlyContinue
        #We only keep the valid UPN
        if ($ADUser -ne $null) {
            #Here we know that the UPN is valid
            #Now we double check that those account can effectively become local admin on the machines. To confirm this, we just have to check that the account belongs either to the whole team delegation group or the application group only.
            $Authorized = $false
            Foreach ($SG in $ADUser.MemberOf) {
                if (($SG -eq "CN=Authorized$TeamName`Admins,OU=Delegation,OU=$TeamName,$DomainDn") -OR ($SG -eq "CN=Authorized$Application`Admins,OU=Delegation,OU=$Application,OU=$TeamName,$DomainDn")) {
                    #If the user belongs to one of the authorized SG, we will keep it for later use
                    $ADObjectUsers += $ADUser
                    $Authorized = $true     
                }
            }
            if ($Authorized) {
                Write-Host "User: $user has been Authorized" -ForegroundColor Green
            }
            else {
                Write-Host "User: $user has not been Authorized" -ForegroundColor Red
            }#End of test Authorized   
        }
        else {
            Write-host "ERROR: UPN $user doesn't exist" -ForegroundColor Red
        }#End of test UPN    
    }

    #Now that we have a valid list of Authorized users, let's add them 
    if ($ADObjectUsers.count -gt 0) {

        Add-ADGroupMember -Members $ADObjectUsers -Identity $($DynamicGroup.sAMAccountName.ToString())

        if ($?) {
            #Write to console
            Write-Output "Information: Users added correctly to the group $DynamicGroupName"
        }   #end of if ($?)
        else {

            #Write error
            Write-Output -Message "Error: Unable to add authorized users to the group $DynamicGroupName" -ErrorAction Stop

        }   #end of else ($?)
    }
    else {
        Write-Output "Warning: No one in the list seems to be authorized"
        break
    }

    #Now that the group is populated correctly we will simply add it under the good delegation (Application)
    #Add the admin inside the application admins
    if ($Application) {
        Add-ADGroupMember -Identity "CN=$Application`Admins,OU=Delegation,OU=$Application,OU=$TeamName,$DomainDn" -Members $($DynamicGroup.sAMAccountName.ToString())
        if (! $?) {
            Write-EventLog -LogName $LogName -Source $SourceName -EntryType Error -EventId 102 -Message "Unable to members inside CN=$Application`Admins,OU=Delegation,OU=$Application,OU=$TeamName,$DomainDn"
            Write-Output "Error: Unable to members inside CN=$Application`Admins,OU=Delegation,OU=$Application,OU=$TeamName,$DomainDn"
            exit
        }

        #This command will "come" with JEA 
        $Context = (Get-UserInfo | Select-Object -ExpandProperty RunAsUser)
        #$Context = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name

        [string]$UsersString = ""
        Foreach ($user in $ADObjectUsers) {
            #Create a string with all Authorized accounts
            $UsersString += $user.UserPrincipalName + ","
        }
        #remove the last ,
        $UsersString = $UsersString.Substring(0, $UsersString.Length - 1)   

        Invoke-sqlcmd -Query "INSERT INTO $GrantLocalAdminHistory ([Who],[What],[HowLong],[When],[Why]) VALUES (`'$Context`',`'Has requested access to the application: $Application from the team $TeamName for users: $UsersString`',`'$TtlHours`',`'$SQLFormatDate`',`'$Reasons`')" -Database $Database -ServerInstance $ServerInstance  -querytimeout 200 -AbortOnError
    }
    #If the application is empty, it means that the requestor want to be a team admin (not an application one)
    else {
        Add-ADGroupMember -Identity "CN=$TeamName`Admins,OU=Delegation,OU=$TeamName,$DomainDn" -Members $($DynamicGroup.sAMAccountName.ToString())

        if (! $?) {
            Write-EventLog -LogName $LogName -Source $SourceName -EntryType Error -EventId 102 -Message "Unable to members inside CN=$TeamName`Admins,OU=Delegation,OU=$TeamName,$DomainDn"
            Write-Output "Error: Unable to members inside CN=$TeamName`Admins,OU=Delegation,OU=$TeamName,$DomainDn"
            exit
        }

        #This command "comes" with JEA
        $Context = (Get-UserInfo | Select-Object -ExpandProperty RunAsUser)
        #$Context = ([Security.Principal.WindowsIdentity]::GetCurrent()).Name

        [string]$UsersString = ""
        Foreach ($user in $ADObjectUsers) {
            #Create a string with all Authorized accounts
            $UsersString += $user.UserPrincipalName + ","
        }
        #remove the last ,
        $UsersString = $UsersString.Substring(0, $UsersString.Length - 1)

        Invoke-sqlcmd -Query "INSERT INTO $GrantLocalAdminHistory ([Who],[What],[HowLong],[When],[Why]) VALUES (`'$Context`',`'Has requested access on all $TeamName servers for users: $UsersString`',`'$TtlHours`',`'$SQLFormatDate`',`'$Reasons`')" -Database $Database -ServerInstance $ServerInstance  -querytimeout 200 -AbortOnError
    }
}
