
#You have to modify these two lines first:
#OUPath is where we will apply the delegation
#$ServiceAccount is the SamAccountName.
#This script will grant add/remove user account management to all security groups and Security Group creation under $OUPath

#Authors: Scomnewbie
#Version: 1.0

######### VARIABLE TO MODIFY TO FIT YOUR NEEDS #########
$OUPath = "OU=PokemonTeam,DC=ScomNewbie,DC=local"
$ServiceAccount = Get-ADServiceAccount JEAGrantRights
######### END OF VARIABLE TO MODIFY TO FIT YOUR NEEDS #########


#Bring up an Active Directory command prompt so we can use this later on in the script
cd ad:
#Get a reference to the RootDSE of the current domain
$rootdse = Get-ADRootDSE
#Get a reference to the current domain
$domain = Get-ADDomain

#Create a hashtable to store the GUID value of each schema class and attribute
$guidmap = @{}
Get-ADObject -SearchBase ($rootdse.SchemaNamingContext) -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName,schemaIDGUID | % {$guidmap[$_.lDAPDisplayName]=[System.GUID]$_.schemaIDGUID}

$schemaIDGUID = @{}
### NEED TO RECONCILE THE CONFLICTS ###
$ErrorActionPreference = 'SilentlyContinue'
Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID | ForEach-Object {$schemaIDGUID.add($_.name,[System.GUID]$_.schemaIDGUID)}
Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID | ForEach-Object {$schemaIDGUID.add($_.name,[System.GUID]$_.rightsGUID)}
$ErrorActionPreference = 'Stop'

#Get a reference to the OU we want to delegate
$ou = Get-ADOrganizationalUnit -Identity $OUPath

#Get the SID values of each group we wish to delegate access to
#ServiceAccount
$identity = [System.Security.Principal.IdentityReference] $ServiceAccount.SID
$adRights = [System.DirectoryServices.ActiveDirectoryRights] "ReadProperty","Writeproperty"
$type = [System.Security.AccessControl.AccessControlType] "Allow"
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
$objectguid = new-object Guid $guidmap["member"]
$inheritedobjectguid = new-object Guid  $schemaIDGUID["Group"]

#Get a copy of the current DACL on the OU
$acl = Get-ACL -Path ($ou.DistinguishedName)
#Create an Access Control Entry for new permission
#Allow the Service Desk group to also reset passwords on all descendent user objects
$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objectguid,$inheritanceType,$inheritedobjectguid
$acl.AddAccessRule($ace)

$ErrorActionPreference = "silentlycontinue"
#Get the SID values of each group we wish to delegate access to
#ServiceAccount
$identity = [System.Security.Principal.IdentityReference] $ServiceAccount.SID
$adRights = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild"
$type = [System.Security.AccessControl.AccessControlType] "Allow"
$inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
$objectguid = new-object Guid $guidmap["group"]
$inheritedobjectguid = new-object Guid  "00000000-0000-0000-0000-000000000000"

$ace = new-object System.DirectoryServices.ActiveDirectoryAccessRule $identity,$adRights,$type,$objectguid,$inheritanceType,$inheritedobjectguid
$acl.AddAccessRule($ace)

#Re-apply the modified DACL to the OU
Set-ACL -ACLObject $acl -Path ("AD:\"+($ou.DistinguishedName))