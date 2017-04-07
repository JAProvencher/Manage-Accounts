foreach($obj in $toproc)
{
	switch ($obj.action)
	{
		"Mark for deletion" {"Mark-User $obj"}
		"Marked for deletion" {if(((Get-Date)-[datetime]($user.delnotifydate -split ","|sort -descending|select -first 1)).days -ge 3){$obj.xes+=1;notify-user $obj "delete"}}
		"Warn Delete" {$obj.action="marked for deletion";notify-user $obj "delete"}
		"Warn Disable" {$obj.action="disabled";notify-user $obj "disable"}
		"Disable User" {try{Disable-User $obj}catch{}}
		"Delete User"	{Delete-User $obj}
	}
}
