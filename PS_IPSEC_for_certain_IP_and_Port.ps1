# Auf Server


$SERVER_CLIENT = Read-Host "Is this (S)erver oder (C)lient of your connection ? S or C)" 
if ($SERVER_CLIENT -eq "S")  {
	$SERVER = $true } 
elseif($SERVER_CLIENT -eq "C" ) 
{ $CLIENT= $true 
}
else {
	"Wrong Answer!"
	exit
	
}



$REMOTE_IP = Read-Host "Enter remote IP: " 

$REMOTE_PORT = Read-Host "Enter remote PORT: " 

$MYPSK = Read-Host "Enter PSK: " 



if($SERVER) {
New-NetFirewallRule -DisplayName 'RDP 2323 IN' -Profile @('Domain', 'Private') -Direction inbound -Action Allow -Protocol TCP -LocalAddress $REMOTE_IP -RemotePort $REMOTE_PORT -Authentication Required -Encryption Required

}



# Auf Client


if($CLIENT) {
$name='RDP ' + $REMOTE_PORT + ' OUT'

New-NetFirewallRule -DisplayName $name -Profile @('Domain', 'Private') -Direction outbound -Action Allow -Protocol TCP -RemoteAddress $REMOTE_IP -RemotePort $REMOTE_PORT -Authentication Required -Encryption Required

}


# Auf Beiden:




" IPSEC Connection Security Rule erstellen"

New-NetIPsecRule -DisplayName RDP_PSK -InboundSecurity Require -OutboundSecurity Require -RemoteAddress $REMOTE_IP -RemotePort $REMOTE_PORT -Protocol TCP




" Authset PSK erstellen"

$PSK = New-NetIPsecAuthProposal -PreSharedKey $MYPSK -Machine

$AUTH = New-NetIPsecPhase1AuthSet -DisplayName PSK_P1_Set -Proposal $PSK

"PSK auf Rule anwenden:"

Set-NetIPsecRule -DisplayName RDP_PSK -Phase1AuthSet $AUTH.Name