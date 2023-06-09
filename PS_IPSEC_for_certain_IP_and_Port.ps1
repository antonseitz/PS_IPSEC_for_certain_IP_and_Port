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
$NAME = Read-Host "Enter RULE NAME: (i.e. RDP )" 

$NAME = $NAME + ' TCP ' + $REMOTE_PORT 
if($SERVER) {
	$NAME=$NAME + ' IN IPSEC PSK'
New-NetFirewallRule -DisplayName $NAME  -Profile @('Any') -Direction inbound -Action Allow -Protocol TCP -LocalAddress $REMOTE_IP -LocalPort $REMOTE_PORT -Authentication Required -Encryption Required

}



# Auf Client


if($CLIENT) {
$NAME=$NAME + ' OUT IPSEC PSK'

New-NetFirewallRule -DisplayName $NAME -Profile @('Domain', 'Private') -Direction outbound -Action Allow -Protocol TCP -RemoteAddress $REMOTE_IP -RemotePort $REMOTE_PORT -Authentication Required -Encryption Required

}


# Auf Beiden:




" IPSEC Connection Security Rule erstellen"

New-NetIPsecRule -DisplayName $NAME -InboundSecurity Require -OutboundSecurity Require -RemoteAddress $REMOTE_IP -RemotePort $REMOTE_PORT -Protocol TCP




" Authset PSK erstellen"

$PSK = New-NetIPsecAuthProposal -PreSharedKey $MYPSK -Machine

$AUTH = New-NetIPsecPhase1AuthSet -DisplayName PSK_P1_Set -Proposal $PSK

"PSK auf Rule anwenden:"

Set-NetIPsecRule -DisplayName $NAME -Phase1AuthSet $AUTH.Name