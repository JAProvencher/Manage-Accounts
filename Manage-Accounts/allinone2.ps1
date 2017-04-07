<#
.SYNOPSIS
  Automated account management and reporting

.DESCRIPTION
	This script will collect objects for each user account in Active Directory.
	
	These objects will be evaluated for:
	1.  Inactivity.  Criteria and actions listed below:
		-	Account has not logged on for 23 days:  Identified as potentially dormant.  A warning email is sent to the user.
		-	Account has not logged on for 30+ days:  Account is disabled.  An email is sent to the user.
		-	Account has not logged on for 45+ days and is already disabled.  Account will be flagged for deletion.
		-	Accounts that have never logged on will use the more recent of the account creation date+30 days and the current date
			as their "True LastLogon".  This will essentially give new users a total of 60 days to logon before their account is
			flagged as dormant and disabled.
		-	Exception groups are in place for specific accounts/conditions.
		-	Accounts protected by AdminSDHolder cannot be acted on by the script.  Notification is sent to the Account Management Team.
	2.  Smartcard Requirement
		-	Users who do not require a smartcard to logon
		-	Users who have a temporary or permanent exception to this requirement.
		-	Users whose account is protected by AdminSDHolder and do not require smartcard logon.  Identifies accounts
			whose password age is near or beyond the threshold.
	
	The emails sent by the script are sent to an address that is on another network where the accounts are not evaluated by this script.


  
.PARAMETER
	None

.INPUTS
  None

.OUTPUTS
  Log file stored in the script folder\scriptname_Logs\Script_[datestring].log
  CSV file for processing by helpdesk

.NOTES
  Version:        1.0
  Author:         John Provencher
  Creation Date:  
  Purpose/Change: 
  
#>

#region VariableAssignments
$today=get-date -format dd-MMM-yy # Date used when annotating the user's description
$date=get-date -format d
$datestring=get-date -format yyyyMMdd # Date used in output file names
$graceperiod=(get-date).adddays(-30)
$setdesc="Dormant account disabled $today" # Text appended to user's description
$srcdomain=$env:userdomain #What domain is this running in?
$emptyemail=@()
$Helpdesk='NUWC_NPT_Helpdesk@navy.mil' # Email address for the Helpdesk group
$AcctMgmt='AccountManagement<NWPT.NUWC_NPT_10411_Account_Mgmt@navy.mil>'
$checks=@('Disabled:','%%Delete%%','X:')
$version='1.0'
if(test-path ".\sentmail.xml")
{
    $sentmail=import-clixml sentmail.xml
}
else
{
    $sentmail=@()
}

$start=get-date
$srcdomain=$env:userdomain #What domain is this running in?
$NoSmartcard=@()
#endregion
$stopwatch=[System.Diagnostics.StopWatch]::StartNew()

trap
[Exception] { 
sendl "error: $($_.Exception.GetType().Name) - $($_.Exception.Message)" 
}
#region FunctionLoad

#*******************************************************************************************************
# Check for/create log file
#
function LogFileCheck
{
[cmdletbinding()]
param()

	if (!(Test-Path $LogDir -erroraction 'SilentlyContinue')) # Check if log file directory exists - if not, create and then create log file for this script.
	{
		mkdir $LogDir
		New-Item "$LogPath" -type file
	}
	if (((Get-ChildItem $LogPath).length/1MB) -gt $MaxLogFileSizeMB) # Check size of log file - to stop unweildy size, archive existing file if over limit and create fresh. 
	{
		$NewLogFile = $LogName.replace('.log', " ARCHIVED $(Get-Date -Format dd-MM-yyy-hh-mm-ss).log")
		Rename-Item $Logpath $LogDir\$NewLogFile
	}
}
#*******************************************************************************************************
# Send an entry to the log file
#
function sendl ([string]$message) # Send to log file 
{
[cmdletbinding()]
	$toOutput = "$(get-date) > $message " | Out-File $logpath -append -NoClobber
}

#*******************************************************************************************************
# Updated function to get the "True" lastlogon.  If never logged on, returns whenCreated+30 days.
# Used for calculating Disable and Delete dates.

function get-lastlogon
{
[cmdletbinding()]
	param($user)
	$dcs=get-addomaincontroller -filter *|Select-Object -expandproperty hostname|Where-Object {test-connection -computername $_ -count 1 -ea 0}
	$llo=0
	$tmptime=0
	$wc=$user.whencreated.tofiletime()
	foreach($dc in $dcs)
	{
		$tmptime=(get-aduser $user -property lastlogon -server $dc).lastlogon
		$llo=$llo,$tmptime|Sort-Object -descending|Select-Object -first 1
	}
	$llo=$llo,$user.lastlogontimestamp,$wc,$user."msDS-LastSuccessfulInteractiveLogonTime"|Sort-Object -descending|Select-Object -first 1
	$llo=[datetime]::fromfiletime($llo)
	if(!$user.lastlogontimestamp){$llo=$llo.adddays(30)}
	return $llo
}

#*******************************************************************************************************
# Get account action based on True LastLogon.  Checks if account is already disabled, marked for deletion, etc.
#
function Get-UserAction
{
	[cmdletbinding()]
	param($user,$tll)
    $delex=(get-adgroup exc.deleteexempt).distinguishedname
    $logonex=(get-adgroup exc.logon).distinguishedname
	$now=get-date
	$warndate=(get-date).adddays(7)
	$disableon=$tll.adddays(30)
	$deleteon=$tll.adddays(45)
	$disablein=($disableon - $now).days
	$deletein=($deleteon - $now).days
	$warnrange=(1..7)
	$maxpwdage=(get-addefaultdomainpasswordpolicy).maxpasswordage.days
	$Xes=($user.carlicense -match 'X:').count
	if($user.passwordlastset)
	{
		$pwdage=if($user.passwordlastset -and ($user.smartcardlogonrequired -eq $false)){((get-date)-$user.passwordlastset).days}else{'NA'}
	}
	$action=@()
	

		if($warnrange -contains $deletein)
		{
			[array]$action='Warn Delete'
		}
		elseif($warnrange -contains $disablein)
		{
			[array]$action='Warn Disable'
		}
		elseif($user.carlicense -contains '%%Delete%%' -and $xes -lt 3)
		{
			[array]$action='Marked for Deletion'
		}
		elseif($deletein -le 0 -and $user.carlicense -notcontains '%%Delete%%' -and $user.memberof -notcontains $delex -and $user.memberof -notcontains $logonex `
                -and -not [bool]($user.memberof -match "guests"))
		{
			[array]$action='Mark for Deletion'
		}
		elseif($disablein -le 0 -and $user.enabled)
		{
			[array]$action='Disable User'
		}
		elseif($user.enabled -eq $false -and $deletein -gt 7)
		{
			[array]$action='Disabled'
		}
		elseif($xes -eq 3 -and $user.memberof -notcontains $delex)
		{
			[array]$action='Delete user'
		}
		elseif($xes -gt 3)
		{
			[array]$action='Ticket for delete submitted'
		}
	
	
	if(!$action)
	{
		$action='Okay'
	}
	return($action)
}
#*******************************************************************************************************
# Send mail to user
#
Function Send-Mail
{
[cmdletbinding()]
	Param($mail,$body,$subject, $cc)
	
	$Notify=@{
	SMTPServer='SMTP'
	From='AccountManagement<NWPT.NUWC_NPT_10411_Account_Mgmt@navy.mil>'
	Body=$body
	Subject=$subject
	To=$mail
    CC=$cc
	}
	Send-mailmessage @Notify -verbose
    $notify.remove("CC")
}

#*******************************************************************************************************
# Mark user for deletion after not having logged on in 45+ days
#
Function Mark-User
{
[cmdletbinding()]
Param($user)
$date=$((get-date).toshortdatestring())
try
{
    set-aduser -identity $user.samaccountname -add @{carlicense='%%Delete%%',"X:$date"}
}
catch
{
Write-host "Submit ticket to add '%%Delete%%' and 'X:$date' to users carlicence property"
}
    $user.action='marked for deletion'
    $user.xes=1
notify-user $user 'delete'
}

#*******************************************************************************************************
# Generate email to AccountManagement to delete the inactive account
#

Function Delete-User
{
[cmdletbinding()]
    Param($user)
    $when='{0}, {1}, and {2}' -f $user.delnotifydate.split(',')
	$body=@"
Please delete account $($user.logonname).  The user has not logged on to the network in $($user.dayssince) days and has been
notified by email three times: $($when).
"@
	$subject="Delete user $($user.logonname)"
# send-mailmessage -from $acctmgmt -to $helpdesk -Subject "Delete $($user.logonname)" -body $body -cc $user.mail -smtpserver smtp -verbose
Send-Mail $helpdesk $body $subject $user.mail
set-aduser $user.samaccountname -add @{carlicense="X:$((get-date).toshortdatestring())"} -verbose
}

#*******************************************************************************************************
# Disable inactive account
#
Function Disable-User
{
[cmdletbinding()]
	Param($user)
	$date=get-date -f d
	if(!$user.protected)
	{
		Disable-ADAccount $user.samaccountname
		$user.action = 'disabled'
		if($user.disablecount -eq 0)
		{
			disable-adaccount $user.samaccountname
			set-aduser $user.samaccountname -add @{carlicense='DisableCount:1',"Disabled:$($date)"}
			$newdesc=$user.description+" - $setdesc"
			set-aduser $user.samaccountname -description $newdesc
			Notify-User $user 'disable'
		}
		else
		{
			$cnt=[int]($user.carlicense -match 'disablecount').split(':')[1]+1
			disable-adaccount $user.samaccountname
			set-aduser $user -replace @{carlicense="DisableCount:$cnt","Disabled:$($date)"}
			set-aduser $user.samaccountname -description $newdesc
			Notify-User $user 'disable'
		}
	}
	elseif($user.protected -and $user.xes -lt 4)
	{
		'Write code to have protected user disabled and not have multiple tickets generated'
	}
}

#*******************************************************************************************************
# Notify user of action taken
#
Function Notify-User
{
[cmdletbinding()]
    Param($user,$act)
    $date=$((get-date).toshortdatestring())
    $msg=if($user.("$($act)in") -gt 0){"will be $($user.action) in $($user.("$($act)in")) day(s)"}else{"has been $($user.action)"}
    $domain=$env:userdomain
    $logonname="$domain\$($user.samaccountname)"
    $salutation="$($user.givenname)"
    $closing=@"
    `n`t`tThank you,`n
    `n`tNUWCDIVNPT Account Management Team
"@

    if($user.action -match 'Marked for deletion' -and $user.xes -gt 0)
    {
	    $notification='This is your '+$(switch ($user.xes)
	    {
	    '1' {'first'}
	    '2' {'second'}
	    '3' {'third and final'}
	    })+' notification.'
    }

    $body=@"
$salutation,`n

    Your account, $($logonname), $($msg) due to not having logged on in $($user.dayssince) days.`n

    $notification

    Users are required to log on at least once every 30 days.  Accounts are automatically disabled after 30
    days of inactivity and are marked to be deleted after 45 days.`n
    If this account is required, but seldom logged on to, request a "Delete Exemption" through your IAO.`n
    $closing
"@

    $subject="Account $($logonname) $($user.action)"

    send-mail $user.mail $body $subject
    if($user.action -eq 'Marked for deletion' -and $user.xes -ge 1)
    {
        set-aduser -identity $user.samaccountname -add @{carlicense="X:$date"}
    }

}

#*******************************************************************************************************
# Generate helpdesk ticket
#
Function SendTo-HelpDesk
{
[cmdletbinding()]
    Param($subject,$message,$CopyTo)
    $Notify=@{
    From="AcctMgmt_Process@NPTRDTE.nuwc.navy.mil"
    To=$helpdesk
    CC=$CopyTo
    Subject=$subject
    Body=$message
    SMTPServer="SMTP"
    }
    # Send-Mailmessage @Notify
    $sentmail+=$notify
    remove-variable subject,message,copyto,notify
}

#*******************************************************************************************************
# Notify users who do not required smartcard logon as appropriate
#
Function SmartCard-Notification
{
[cmdletbinding()]
    Param($user)
    $logonname="$($env:userdomain)\$($user.samaccountname)"
    $cc='AccountManagement<NWPT.NUWC_NPT_10411_Account_Mgmt@navy.mil>'
    $msg=&{if($user.cloexception -notin @($True,'Temp'))
	    {
		    "Account: $($logonname) - Smartcard not required and no exception filed"
	    }
	    if($user.passwordneverexpires)
	    {
		    "Account: $($logonname) - Smartcard not required and PasswordNeverExpires"
	    }
	    if($user.passwordage -ge 60)
	    {
		    "Account: $($logonname) - Password is expired"
	    }
	    
        if((1..7) -contains ($user.passwordlastset.adddays(60) - (get-date)).days)
	    {
		    $days=($user.passwordlastset.adddays(60) - (get-date)).days
		    "Account: $($logonname) - Password expires soon: $($days) day(s) remain"
	    }
	    else{$msg = $null}
	    }
    if($msg){
    $body=@"
    This email is to notify you that:`n
    $($msg)
    `n
    Please take the appropriate action.
    `n
    Thank you,`n
    NUWCDIVNPT Account Management Team
"@
    $subject="$($logonname) smartcard/password status"
    send-mail $user.mail $body $subject $cc
    }
}


#endregion

#*******************************************************************************************************
#Main body of script - actual work happens below
#*******************************************************************************************************


LogfileCheck
sendl "$('*'*80)"
sendl "Beginning $scriptname version $version"
Sendl "Start time: $start"
sendl "$('*'*80)"
if((get-module activedirectory) -or (import-module activedirectory -passthru)){SendL 'Active directory module loaded'}

# Get big list of all users to process

sendl "$('*'*80)"
$users=get-aduser -filter * -properties *|Sort-Object samaccountname
sendl "$($users.count) users loaded"
sendl 'Processing...'
$toproc=@()
foreach ($user in $users)
{
	$tll=get-lastlogon $user
	$table=@{
	GivenName=$user.givenname
	DisplayName=$user.displayname
	SamAccountName=$user.samaccountname
	LogonName="$($srcdomain)\$($user.samaccountname)"
	Description=$user.description
	UPN=$user.userprincipalname
	Mail=$user.mail
	Dept=$user.department
	Office=$user.office
	Phone=$user.telephonenumber
	Created=$user.whencreated
	Changed=$user.whenchanged
	PasswordLastSet=$user.passwordlastset
	PasswordAge=if($user.passwordlastset -ne $null){((get-date)-$user.passwordlastset).days}else{0}
	TrueLastLogon=$tll
	DaysSince=((get-date) - $tll).days
	DisableOn=$tll.adddays(30).toshortdatestring()
	DisableIn=($tll.adddays(30) - (Get-Date)).days
	DeleteOn=if([int]$user.sid.value.split('-')[-1] -lt 1000){"Exempt"}else{$tll.adddays(45).toshortdatestring()}
	DeleteIn=if([int]$user.sid.value.split('-')[-1] -lt 1000){"Exempt"}else{($tll.adddays(45) - (Get-Date)).days}
	Disabled=!$user.enabled
	Locked=$user.lockedout
	NeverLoggedOn=$user.lastlogontimestamp -eq $null
	SCRequired=$user.smartcardlogonrequired
	DN=$user.distinguishedname
	Action=(Get-UserAction $user $tll) -join ';'
	Protected=[bool]($user.admincount -eq 1)
	Groups=($user.memberof|get-adgroup).name
	CLOException=if($user.memberof -match 'exc.cac'){'Temp'}else{[bool]($user.memberof -match 'exc.accounts' -or [int]$user.sid.value.split('-')[-1] -lt 1000)}
	LogonException=[bool]($user.memberof -match 'exc.logon' -or [int]$user.sid.value.split('-')[-1] -lt 1000)
	New=[bool]($user.whencreated -ge $graceperiod)
	DeleteExemption=[bool]($user.memberof -match 'exc.deleteexempt' -or [int]$user.sid.value.split('-')[-1] -lt 1000)
	PasswordNeverExpires=$user.passwordneverexpires
	DisableCount=if($user.carlicense -match 'disablecount'){($user.carlicense -match 'disablecount').split(':')[1]}else{'0'}
	DisabledDate=if($user.carlicense -match 'disabled:'){($user.carlicense -match 'Disabled:').split(':')[1]}else{'NotDisabled'}
	Xes=($user.carlicense -match 'X:').count
	DelNotifyDate=if([int]$user.sid.value.split('-')[-1] -lt 1000){"Exempt"}else{(($user.carlicense -match 'X:') -split ':' -notmatch 'X'|Sort-Object {[datetime] $_}) -join ','}
	DeleteOverdue=if([int]$user.sid.value.split('-')[-1] -lt 1000){"Exempt"}else{((get-date)-($tll.adddays(45))).days}
    LockedOut=$user.lockedout
    Special=([int]$user.sid.value.split('-')[-1] -lt 1000)
	}
	$tmpobj=new-object psobject -property $table
	"$($tmpobj.samaccountname) -> $($tmpobj.action)"
    $toproc+=$tmpobj
}

# Was user previously disabled and/or marked for deletion but is now enabled?
foreach($check in $checks)
	{
		$clritem=$user.carlicense -match $check
		if($clritem -and $user.enabled)
		{
            try
            {
                set-aduser $user -remove @{carlicense=$clritem} -verbose
                "$($clritem) removed from $user.samaccountname"
                $user=get-aduser $user -properties *
            }
            catch
            {
                Write-Host "Could not remove $clritem from user properties"
            }
		}
	}
	
    # Is user's description reflecting the account was disabled, but it is enabled.
	if($user.description -like '*dormant*' -and $user.enabled -eq $true)
	{
		$newdesc=$user.description.substring(0,$user.description.indexof('Dormant')-3)
        try
        {
            set-aduser $user -description $newdesc -verbose
        }
        catch
        {
            #if($sentmail.cc -notcontains $user.mail
            send-mailmessage -to $Helpdesk -Subject "Elevated account modification" -Body "Remove 'Dormant account' string from description for NPTRDTE\$($user.name)" -smtpserver "SMTP" -From "AcctMgmt_Process@NPTRDTE.nuwc.navy.mil"
        }
		Write-host "Description fixed for $($user.name)" -ForegroundColor yellow
	}
	
foreach($obj in $toproc)
{
    if(!$obj.SCRequired)
    {
        Smartcard-Notification $obj
    }
}
	
	
	
	if($tmpobj.DeleteExemption -and $tmpobj.disabledondelete -ne 'Exempt')
	{
		set-aduser $tmpobj.dn -Replace @{carlicense='Exempt'} -whatif
		Write-host "$($tmpobj.samaccountname) marked 'EXEMPT' from deletion" -foregroundcolor red
		SendL "$($tmpobj.samaccountname) marked 'EXEMPT' from deletion"
	}
	elseif(!$tmpobj.DeleteExemption -and $tmpobj.disabledondelete -eq 'Exempt')
	{
		set-aduser $tmpobj.dn -Clear carlicense -whatif
		Write-host "Delete exemption flag removed from $($tmpobj.samaccountname)" -foregroundcolor red
		SendL "Delete exemption flag removed from $($tmpobj.samaccountname)"
	}
	if($tmpobj.status -eq 'Delete' -and $tmpobj.disabledondelete -ne 'delete' -and (!$tmpobj.logonexception -or !$tmpobj.deleteexemption))
	{
			set-aduser $tmpobj.dn -Replace @{carlicense='Delete'} -whatif
			Write-Host "$($tmpobj.samaccountname) marked for deletion" -foregroundcolor red
			SendL "$($tmpobj.samaccountname) marked for deletion"
			$marked+=$tmpobj
			$todelete+=$tmpobj
	}
