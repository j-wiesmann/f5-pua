#!/bin/bash
# Filename: build_pua.sh
#
# Builds out a reference PUA deployment on a BIG-IP running TMOS 13.1.0.2
#
# Bill Church - bill@f5.com
#
clear

shopt -s nocasematch

WORKINGDIR=/tmp/pua

SHASUMSURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/shasums.txt
SHASUMSFNAME=shasums.txt
STARTUPURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/startup_script_webssh_commands.sh
STARTUPFNAME=startup_script_webssh_commands.sh
WEBSSHURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-ILX-WebSSH2-current.tgz
WEBSSHFNAME=BIG-IP-ILX-WebSSH2-current.tgz
WEBSSHILXNAME=WebSSH2-0.2.0-test
WEBSSHILXPLUGIN=WebSSH_plugin-test
EPHEMERALURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-ILX-ephemeral_auth-current.tgz
EPHEMERALFNAME=BIG-IP-ILX-ephemeral_auth-current.tgz
EPHEMERALILXNAME=ephemeral_auth-0.2.8-test
EPHEMERALILXPLUGIN=ephemeral_auth_plugin
ILXARCHIVEDIR=/var/ilx/workspaces/Common/archive

# dont try to figure it out, just ask bill@f5.com

checkoutput() {
  if [ $RESULT -eq 0 ]; then
    echo "[OK]"
    return
  else
    #failure
    echo "[FAILED]"
    echo;echo;echo "Previous command failed: $CMD"
    echo;echo;echo $OUTPUT
    exit
  fi
}

getvip() {
  YESNO="n"
  while [ "$YESNO" == "n" ]
    do
    echo
    echo -n "Type the IP address of your $SERVICENAME service virtual server and press ENTER: "
    read SERVICENAME_VIP
    echo
    echo -n "You typed $SERVICENAME_VIP, is that correct (y/n)? "
    echo
    read -n1 YESNO
    if [ "$SERVICENAME_VIP" == "$WEBSSH2VIP" ]; then
      $SERVICENAME VIP can not equal WEBSSH Service VIP
      YESNO="n"
    fi
  done
  return
}

echo;echo
echo -n "Preparing environment... "
mkdir -p $WORKINGDIR
RESULT="$?" 2>&1
  CMD="!-1" 2>&1
checkoutput

echo "Adding directory ILX archive directory"
mkdir -p $ILXARCHIVEDIR
RESULT="$?" 2>&1
  CMD="!-1" 2>&1
checkoutput

echo -n "Changing to $WORKINGDIR... "
cd $WORKINGDIR
RESULT="$?" 2>&1
  CMD="!-1" 2>&1
checkoutput

echo -n "Downloading $SHASUMSFNAME... "
OUTPUT=$(curl --progress-bar $SHASUMSURL > $SHASUMSFNAME 2>&1)
RESULT="$?" 2>&1
  CMD="!-1" 2>&1
checkoutput

echo "Checking for $STARTUPFNAME..."
if [ ! -f $STARTUPFNAME ]; then
  echo -n "Downloading $STARTUPFNAME... "
  OUTPUT=$(curl --progress-bar $STARTUPURL > $STARTUPFNAME)
  RESULT="$?" 2>&1
  CMD="!-1" 2>&1
  checkoutput
fi

echo "Checking for $WEBSSHFNAME..."
if [ ! -f $WEBSSHFNAME ]; then
  echo -n "Downloading $WEBSSHFNAME... "
  OUTPUT=$(curl --progress-bar $WEBSSHURL > $WEBSSHFNAME)
  RESULT="$?" 2>&1
  CMD="!-1" 2>&1
  checkoutput
fi

echo "Checking for $EPHEMERALFNAME"
if [ ! -f $EPHEMERALFNAME ]; then
  echo -n "Downloading $EPHEMERALFNAME... "
  OUTPUT=$(curl --progress-bar $EPHEMERALURL > $EPHEMERALFNAME)
  RESULT="$?" 2>&1
  CMD="!-1" 2>&1
  checkoutput
fi

echo "Checking SHA256 signatures of downloaded files"
sha256sum -c $SHASUMSFNAME
if [ $? -gt 0 ]; then
  echo "SHA256 checksum failed. Halting."
  exit
fi

echo -n "Placing $STARTUPFNAME in /config... "
OUTPUT=$(mv $STARTUPFNAME /config)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Placing $WEBSSHFNAME in $ILXARCHIVEDIR... "
OUTPUT=$(mv $WORKINGDIR/$WEBSSHFNAME $ILXARCHIVEDIR/$WEBSSHFNAME)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Placing $EPHEMERALFNAME in $ILXARCHIVEDIR... "
OUTPUT=$(mv $WORKINGDIR/$EPHEMERALFNAME $ILXARCHIVEDIR/$EPHEMERALFNAME)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Importing WebSSH2 Workspace... "
# create ilx workspace new from-uri https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-ILX-WebSSH2-current.tgz
OUTPUT=$(tmsh create ilx workspace $WEBSSHILXNAME from-archive $WEBSSHFNAME)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Importing Ephemeral Authentication Workspace... "
OUTPUT=$(tmsh create ilx workspace $EPHEMERALILXNAME from-archive $EPHEMERALFNAME)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

SERVICENAME=WebSSH2
getvip
WEBSSH2VIP="$SERVICENAME_VIP"

SERVICENAME=RADIUS
getvip
RADIUSVIP="$SERVICENAME_VIP"

SERVICENAME=LDAP
getvip
LDAPVIP="$SERVICENAME_VIP"

SERVICENAME=LDAPS
getvip
LDAPSVIP="$SERVICENAME_VIP"

SERVICENAME=Webtop
getvip
WEBTOPVIP="$SERVICENAME_VIP"


echo -n "Creating WEBSSH Proxy Service Virtual Server... "
OUTPUT=$(tmsh create ltm virtual webssh_proxy { destination $WEBSSH2VIP:2222 ip-protocol tcp mask 255.255.255.255 profiles add { clientssl-insecure-compatible { context clientside } tcp { } } source 0.0.0.0/0 })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating tmm route for Plugin... "
OUTPUT=$(tmsh create net route webssh_tmm_route gw 127.1.1.254 network $WEBSSH2VIP/32)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Installing webssh tmm vip startup script... "
OUTPUT=$(bash /config/$STARTUPFNAME $WEBSSH2VIP)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating WebSSH2 Plugin... "
# create ilx workspace new from-uri https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-ILX-WebSSH2-current.tgz
OUTPUT=$(tmsh create ilx plugin $WEBSSHILXPLUGIN from-workspace $WEBSSHILXNAME)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating Ephemeral Authentication Plugin... "
# create ilx workspace new from-uri https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-ILX-WebSSH2-current.tgz
OUTPUT=$(tmsh create ilx plugin $EPHEMERALILXPLUGIN from-workspace $EPHEMERALILXNAME)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating ephemeral_config data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_config { records add { BINDDN { data CN=Administrator,CN=Users,DC=mydomain,DC=local } BINDPWD { data Password123 } BINDURL { data ldaps://192.168.20.230:636 } DEBUG { data 2 } DEBUG_PASSWORD { data 1 } RADIUS_SECRET { data radius_secret } RADIUS_TESTMODE { data 1 } RADIUS_TESTUSER { data f5testuser } ROTATE { data 0 } pwrulesLen { data 8 } pwrulesLwrCaseMin { data 1 } pwrulesNumbersMin { data 1 } pwrulesPunctuationMin { data 1 } pwrulesUpCaseMin { data 1 } } type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating ephemeral_LDAP_Bypass data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_LDAP_Bypass { records add { "cn=f5 service account,cn=users,dc=mydomain,dc=local" { } cn=administrator,cn=users,dc=mydomain,dc=local { } cn=proxyuser,cn=users,dc=mydomain,dc=local { } } type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating ephemeral_RADIUS_Bypass data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_RADIUS_Bypass { records add { jlpicard { } } type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating ephemeral_radprox_host_groups data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_radprox_host_groups { records add { 192.168.99.80 { data "CN=RouterEnable,CN=Users,DC=mydomain,DC=local:15;CN=RouterView,CN=Users,DC=mydomain,DC=local:1" } 192.168.99.81 { data "CN=RouterEnable,CN=Users,DC=mydomain,DC=local:15;CN=RouterView,CN=Users,DC=mydomain,DC=local:1" } 192.168.99.82 { data "CN=RouterEnable,CN=Users,DC=mydomain,DC=local:15;CN=RouterView,CN=Users,DC=mydomain,DC=local:1" } 192.168.99.83 { data "CN=RouterEnable,CN=Users,DC=mydomain,DC=local:15;CN=RouterView,CN=Users,DC=mydomain,DC=local:1" } 192.168.99.85 { data "CN=RouterEnable,CN=Users,DC=mydomain,DC=local:15;CN=RouterView,CN=Users,DC=mydomain,DC=local:1" } } type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating ephemeral_radprox_radius_attributes data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_radprox_radius_attributes { records add { BLUECOAT { data "[['Service-Type', <<<VALUE>>>]]" } CISCO { data "[['Vendor-Specific', 9, [['Cisco-AVPair', 'shell:priv-lvl=<<<VALUE>>>']]]]" } DEFAULT { data "[['Vendor-Specific', 9, [['Cisco-AVPair', 'shell:priv-lvl=<<<VALUE>>>']]]]" } F5 { data "[['Vendor-Specific', 3375, [['F5-LTM-User-Role, <<<VALUE>>>]]]]" } PALOALTO { data "[['Vendor-Specific', 25461, [['PaloAlto-Admin-Role', <<<VALUE>>>]]]]" } } type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating ephemeral_radprox_radius_client data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_radprox_radius_client { records add { 192.168.99.80 { data DEFAULT } 192.168.99.81 { data DEFAULT } 192.168.99.82 { data CISCO } 192.168.99.83 { data CISCO } 192.168.99.85 { data PALOALTO } } type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating RADIUS Proxy Service Virtual Server... "
OUTPUT=$(tmsh create ltm virtual radius_proxy { destination $RADIUSVIP:1812 ip-protocol udp mask 255.255.255.255 profiles add { udp { } } source-address-translation { type automap } source 0.0.0.0/0 rules { $EPHEMERALILXPLUGIN/radius_proxy }})
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating LDAP Proxy Service Virtual Server... "
OUTPUT=$(tmsh create ltm virtual ldap_proxy { destination $LDAPVIP:389 ip-protocol tcp mask 255.255.255.255 profiles add { tcp { } } source-address-translation { type automap } source 0.0.0.0/0 rules { $EPHEMERALILXPLUGIN/ldap_proxy }})
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating LDAPS (ssl) Proxy Service Virtual Server... "
OUTPUT=$(tmsh create ltm virtual ldaps_proxy { destination $LDAPSVIP:636 ip-protocol tcp mask 255.255.255.255 profiles add { tcp { } clientssl { context clientside } serverssl-insecure-compatible { context serverside } } source-address-translation { type automap } source 0.0.0.0/0 rules { $EPHEMERALILXPLUGIN/ldap_proxy_ssl }})
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

# WEBTOP VIPS

echo -n "Creating Webtop Virtual Server... "
OUTPUT=$(tmsh create ltm virtual pua_webtop { destination $WEBTOPVIP:443 ip-protocol tcp mask 255.255.255.255 profiles add { tcp { } clientssl { context clientside } serverssl-insecure-compatible { context serverside } } source-address-translation { type automap } source 0.0.0.0/0 rules { $EPHEMERALILXPLUGIN/APM_ephemeral_auth }})
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput


# SERVICNAME=Ephemeral Authentication
# getvip
# EPHEMERALVIP="$SERVICENAME_VIP"

