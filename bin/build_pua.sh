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

#SHASUMSURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/shasums.txt
#SHASUMSFNAME=shasums.txt
STARTUPURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/startup_script_webssh_commands.sh
STARTUPFNAME=startup_script_webssh_commands.sh
WEBSSHURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-13.1.0.2-ILX-WebSSH2-current.tgz
WEBSSHFNAME=BIG-IP-13.1.0.2-ILX-WebSSH2-current.tgz
WEBSSHILXNAME=WebSSH2-0.2.0-test
WEBSSHILXPLUGIN=WebSSH_plugin-test
EPHEMERALURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-ILX-ephemeral_auth-current.tgz
EPHEMERALFNAME=BIG-IP-ILX-ephemeral_auth-current.tgz
EPHEMERALILXNAME=ephemeral_auth-0.2.8-test
EPHEMERALILXPLUGIN=ephemeral_auth_plugin
ILXARCHIVEDIR=/var/ilx/workspaces/Common/archive

# dont try to figure it out, just ask bill@f5.com
DEFAULTIP=
MGMTIP=$(ifconfig mgmt | awk '/inet addr/{print substr($2,6)}')
checkoutput() {
  if [ $RESULT -eq 0 ]; then
    echo "[OK]"
    return
  else
    #failure
    tput bel;tput bel;tput bel;tput bel
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
    if [ "$DEFAULTIP" == "" ]; then
      echo -n "Type the IP address of your $SERVICENAME service virtual server and press ENTER: "
    else
      echo -n "Type the IP address of your $SERVICENAME service virtual server and press ENTER [$DEFAULTIP]: "
    fi
    read SERVICENAME_VIP
    if [[ ("$SERVICENAME_VIP" == "") && ("$DEFAULTIP" != "") ]]; then
      SERVICENAME_VIP=$DEFAULTIP
    fi
    echo
    echo -n "You typed $SERVICENAME_VIP, is that correct (Y/n)? "
    read -n1 YESNO
    if [ "$SERVICENAME_VIP" == "$WEBSSH2VIP" ]; then
      echo $SERVICENAME VIP must not equal WEBSSH Service VIP
      YESNO="n"
    fi
  done
  return
}

downloadAndCheck() {
  echo "Checking for $FNAME..."
  if [ ! -f $FNAME ]; then
    echo -n "Downloading $FNAME... "
    OUTPUT=$(curl --progress-bar $URL > $FNAME)
    RESULT="$?" 2>&1
    CMD="!-1" 2>&1
    checkoutput
    echo -n "Downloading $FNAME.sha256... "
    OUTPUT=$(curl --progress-bar $URL.sha256 > $FNAME.sha256)
    RESULT="$?" 2>&1
    CMD="!-1" 2>&1
    checkoutput
  fi
  echo "Checking $FNAME hash..."
  sha256sum -c $FNAME.sha256
  if [ $? -gt 0 ]; then
    echo "SHA256 checksum failed. Halting."
    exit
  fi
}

echo;echo
echo -n "Preparing environment... "
mkdir -p $WORKINGDIR
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo "Adding directory ILX archive directory"
mkdir -p $ILXARCHIVEDIR
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Changing to $WORKINGDIR... "
cd $WORKINGDIR
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

FNAME=$STARTUPFNAME
URL=$STARTUPURL
downloadAndCheck

FNAME=$WEBSSHFNAME
URL=$WEBSSHURL
downloadAndCheck

FNAME=$EPHEMERALFNAME
URL=$EPHEMERALURL
downloadAndCheck

echo
echo -n "Placing $STARTUPFNAME in /config... "
OUTPUT=$(mv $STARTUPFNAME /config)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Placing $WEBSSHFNAME in $ILXARCHIVEDIR... "
OUTPUT=$(mv $WORKINGDIR/$WEBSSHFNAME $ILXARCHIVEDIR/$WEBSSHFNAME)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Placing $EPHEMERALFNAME in $ILXARCHIVEDIR... "
OUTPUT=$(mv $WORKINGDIR/$EPHEMERALFNAME $ILXARCHIVEDIR/$EPHEMERALFNAME)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating ephemeral_config data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_config { records add { DEBUG { data 2 } DEBUG_PASSWORD { data 1 } RADIUS_SECRET { data radius_secret } RADIUS_TESTMODE { data 1 } RADIUS_TESTUSER { data testuser } ROTATE { data 0 } pwrulesLen { data 8 } pwrulesLwrCaseMin { data 1 } pwrulesNumbersMin { data 1 } pwrulesPunctuationMin { data 1 } pwrulesUpCaseMin { data 1 } } type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating ephemeral_LDAP_Bypass data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_LDAP_Bypass { records add { "cn=f5 service account,cn=users,dc=mydomain,dc=local" { } cn=administrator,cn=users,dc=mydomain,dc=local { } cn=proxyuser,cn=users,dc=mydomain,dc=local { } } type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating ephemeral_RADIUS_Bypass data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_RADIUS_Bypass { type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating ephemeral_radprox_host_groups data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_radprox_host_groups { type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating ephemeral_radprox_radius_attributes data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_radprox_radius_attributes { records add { BLUECOAT { data "[['Service-Type', <<<VALUE>>>]]" } CISCO { data "[['Vendor-Specific', 9, [['Cisco-AVPair', 'shell:priv-lvl=<<<VALUE>>>']]]]" } DEFAULT { data "[['Vendor-Specific', 9, [['Cisco-AVPair', 'shell:priv-lvl=<<<VALUE>>>']]]]" } F5 { data "[['Vendor-Specific', 3375, [['F5-LTM-User-Role, <<<VALUE>>>]]]]" } PALOALTO { data "[['Vendor-Specific', 25461, [['PaloAlto-Admin-Role', <<<VALUE>>>]]]]" } } type string })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating ephemeral_radprox_radius_client data group... "
OUTPUT=$(tmsh create ltm data-group internal ephemeral_radprox_radius_client { type string })
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

echo
echo -n "Modifying Ephemeral Authentication Workspace... "
OUTPUT=$(tmsh modify ilx workspace $EPHEMERALILXNAME node-version 6.9.1)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

tput bel;tput bel
SERVICENAME=WebSSH2
getvip
WEBSSH2VIP="$SERVICENAME_VIP"

SERVICENAME=RADIUS
getvip
RADIUSVIP="$SERVICENAME_VIP"
DEFAULTIP=$SERVICENAME_VIP

SERVICENAME=LDAP
getvip
LDAPVIP="$SERVICENAME_VIP"
DEFAULTIP=$SERVICENAME_VIP

SERVICENAME=LDAPS
getvip
LDAPSVIP="$SERVICENAME_VIP"
DEFAULTIP=$SERVICENAME_VIP

SERVICENAME=Webtop
getvip
WEBTOPVIP="$SERVICENAME_VIP"
DEFAULTIP=$SERVICENAME_VIP

echo;echo
echo -n "Creating WEBSSH Proxy Service Virtual Server... "
OUTPUT=$(tmsh create ltm virtual webssh_proxy { destination $WEBSSH2VIP:2222 ip-protocol tcp mask 255.255.255.255 profiles add { clientssl-insecure-compatible { context clientside } tcp { } } source 0.0.0.0/0 translate-address disabled translate-port disabled })
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

#echo -n "Modifying WebSSH2 Workspace config.json... "
#OUTPUT=$(jq '.listen.ip = "0.0.0.0"' $ILXARCHIVEDIR/../$WEBSSHILXNAME/extensions/WebSSH2/config.json > $ILXARCHIVEDIR/../$WEBSSHILXNAME/extensions/WebSSH2/config.json)
#RESULT="$?" 2>&1
#CMD="!-1" 2>&1
#checkoutput

echo
echo -n "Creating WebSSH2 Plugin... "
OUTPUT=$(tmsh create ilx plugin $WEBSSHILXPLUGIN from-workspace $WEBSSHILXNAME extensions { webssh2 { concurrency-mode single ilx-logging enabled  } })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating Ephemeral Authentication Plugin... "
OUTPUT=$(tmsh create ilx plugin $EPHEMERALILXPLUGIN from-workspace $EPHEMERALILXNAME extensions { ephemeral_auth { ilx-logging enabled } })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating RADIUS Proxy Service Virtual Server... "
OUTPUT=$(tmsh create ltm virtual radius_proxy { destination $RADIUSVIP:1812 ip-protocol udp mask 255.255.255.255 profiles add { udp { } } source-address-translation { type automap } source 0.0.0.0/0 rules { $EPHEMERALILXPLUGIN/radius_proxy }})
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating LDAP Proxy Service Virtual Server... "
OUTPUT=$(tmsh create ltm virtual ldap_proxy { destination $LDAPVIP:389 ip-protocol tcp mask 255.255.255.255 profiles add { tcp { } } source-address-translation { type automap } source 0.0.0.0/0 rules { $EPHEMERALILXPLUGIN/ldap_proxy }})
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Creating LDAPS (ssl) Proxy Service Virtual Server... "
OUTPUT=$(tmsh create ltm virtual ldaps_proxy { destination $LDAPSVIP:636 ip-protocol tcp mask 255.255.255.255 profiles add { tcp { } clientssl { context clientside } serverssl-insecure-compatible { context serverside } } source-address-translation { type automap } source 0.0.0.0/0 rules { $EPHEMERALILXPLUGIN/ldap_proxy_ssl }})
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

# WEBTOP VIPS

echo
echo -n "Creating pua APM Policy..."
echo 'proc script::run {} {' > $WORKINGDIR/policy.tcl
echo '  tmsh::begin_transaction' >> $WORKINGDIR/policy.tcl
echo '  tmsh::create /apm policy agent ending-allow /Common/pua_end_allow_ag { }' >> $WORKINGDIR/policy.tcl
echo '  tmsh::create /apm policy agent ending-deny /Common/pua_end_deny_ag { }' >> $WORKINGDIR/policy.tcl
echo '  tmsh::create /apm policy agent ending-deny /Common/pua_end_deny2_ag { }' >> $WORKINGDIR/policy.tcl
echo '  tmsh::create /apm policy policy-item /Common/pua_end_allow { agents add { /Common/pua_end_allow_ag { type ending-allow } } caption Allow color 1 item-type ending }' >> $WORKINGDIR/policy.tcl
echo '  tmsh::create /apm policy policy-item /Common/pua_end_deny { agents add { /Common/pua_end_deny_ag { type ending-deny } } caption Deny color 2 item-type ending }' >> $WORKINGDIR/policy.tcl
echo '  tmsh::create /apm policy policy-item /Common/pua_end_deny2 { agents add { /Common/pua_end_deny2_ag { type ending-deny } } caption Deny2 color 4 item-type ending }' >> $WORKINGDIR/policy.tcl
echo '  tmsh::create /apm policy policy-item /Common/pua_ent { caption Start color 1 rules { { caption fallback next-item /Common/pua_end_deny } } }' >> $WORKINGDIR/policy.tcl
echo '  tmsh::create /apm policy access-policy /Common/pua { default-ending /Common/pua_end_deny items add { pua_end_allow { } pua_end_deny { } pua_end_deny2 { } pua_ent { } } start-item pua_ent }' >> $WORKINGDIR/policy.tcl
echo '  tmsh::create /apm profile access /Common/pua { accept-languages add { en } access-policy /Common/pua}' >> $WORKINGDIR/policy.tcl
echo '  tmsh::create /apm profile connectivity pua-connectivity defaults-from connectivity' >> $WORKINGDIR/policy.tcl
echo '  tmsh::commit_transaction' >> $WORKINGDIR/policy.tcl
echo '  }'  >> $WORKINGDIR/policy.tcl
OUTPUT=$(tmsh run cli script file $WORKINGDIR/policy.tcl)
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo -n "Creating Webtop Virtual Server... "
OUTPUT=$(tmsh create ltm virtual pua_webtop { destination $WEBTOPVIP:443 ip-protocol tcp mask 255.255.255.255 profiles add { http pua rewrite-portal tcp { } pua-connectivity { context clientside } clientssl { context clientside } serverssl-insecure-compatible { context serverside } } source-address-translation { type automap } rules { $EPHEMERALILXPLUGIN/APM_ephemeral_auth } source 0.0.0.0/0 })
RESULT="$?" 2>&1
CMD="!-1" 2>&1
checkoutput

echo
echo -n "Do you want to configure this BIG-IP to authenticate against itself for testing purposes (Y/n)? "
echo -n "You typed $SERVICENAME_VIP, is that correct (Y/n)? "
read -n1 YESNO
if [ "$YESNO" != "n" ]; then
  echo;echo
  echo -n "Creating RADIUS Configuration... "
  echo 'proc script::run {} {' > $WORKINGDIR/radius.tcl
  echo '  tmsh::begin_transaction' >> $WORKINGDIR/radius.tcl
  echo "  tmsh::create /auth radius-server system_auth_name1 secret radius_secret server $RADIUSVIP" >> $WORKINGDIR/radius.tcl
  echo '  tmsh::create /auth radius system-auth { servers add { system_auth_name1 } }' >> $WORKINGDIR/radius.tcl
  echo '  tmsh::modify /auth remote-user default-role guest remote-console-access tmsh' >> $WORKINGDIR/radius.tcl
  echo '  tmsh::modify /auth source type radius' >> $WORKINGDIR/radius.tcl
  echo '  tmsh::commit_transaction' >> $WORKINGDIR/radius.tcl
  echo '}' >> $WORKINGDIR/radius.tcl >> $WORKINGDIR/radius.tcl
  OUTPUT=$(tmsh run cli script file $WORKINGDIR/radius.tcl)
  RESULT="$?" 2>&1
  CMD="!-1" 2>&1
  checkoutput
  echo;echo
  echo "You can test your new configuration now by browsing to:"
  echo
  echo "  https://$WEBSSH2VIP:2222/ssh/host/$MGMTIP"
  echo
  echo "  username: testuser"
  echo "  password: anypassword"
  echo
fi

echo "Task complete."
echo
echo "Now go build an APM policy for pua!"
