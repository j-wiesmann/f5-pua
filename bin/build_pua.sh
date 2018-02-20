#!/bin/bash
# Filename: build_pua.sh
#
# Builds out a reference PUA deployment on a BIG-IP running TMOS 13.1.0.2
#
# Bill Church - bill@f5.com
#
# v1.0.0 - 20180219 - Initial Release
# v1.0.1 - 20180219 - Disabled SNAT automap for webtop virtual server
# v1.0.2 - 20180220 - Cleaned up error reporting

clear

shopt -s nocasematch

WORKINGDIR=/tmp/pua

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
PROVLEVEL=nominal
MODULESREQUIRED="apm ltm ilx"

# dont try to figure it out, just ask bill@f5.com
DEFAULTIP=
MGMTIP=$(ifconfig mgmt | awk '/inet addr/{print substr($2,6)}')
read STATUS </var/prompt/ps1

if [[ "$STATUS" != "Active" ]]; then
  tput bel;tput bel;tput bel;tput bel
  echo
  echo "Your BIG-IP system does not appear to be in a consistent state, status reports: $STATUS"
  echo
  echo "Please correct the condition and try running this script again."
  echo
  exit 255
fi

pushd . > /dev/null
SCRIPT_PATH="${BASH_SOURCE[0]}";
while([ -h "${SCRIPT_PATH}" ]); do
    cd "`dirname "${SCRIPT_PATH}"`"
    SCRIPT_PATH="$(readlink "`basename "${SCRIPT_PATH}"`")";
done
cd "`dirname "${SCRIPT_PATH}"`" > /dev/null
SCRIPT_PATH="`pwd`";
popd  > /dev/null

checkoutput() {
  if [ $RESULT -eq 0 ]; then
    echo "[OK]"
    return
  else
    #failure
    tput bel;tput bel;tput bel;tput bel
    echo "[FAILED]"
    echo -e "\n\n"
    echo "Previous command failed in ${SCRIPT_PATH}/$0 with error level: ${RESULT} on line: $PREVLINE:"
    echo
    sed "${PREVLINE}q;d" ${SCRIPT_PATH}/$0 | awk '{$1=$1};1'
    echo -e "\n\n"
    echo "STDOUT/STDERR:"
    echo ${OUTPUT}
    exit 255
  fi
}

getvip() {
  YESNO="n"
  while [ "$YESNO" == "n" ]
    do
    echo
    if [ "$DEFAULTIP" == "" ]; then
      echo "Type the IP address of your $SERVICENAME service virtual server"
      echo -n "and press ENTER: "
    else
      echo "Type the IP address of your $SERVICENAME service virtual server"
      echo -n "and press ENTER [$DEFAULTIP]: "
    fi
    read SERVICENAME_VIP
    if [[ ("$SERVICENAME_VIP" == "") && ("$DEFAULTIP" != "") ]]; then
      SERVICENAME_VIP=$DEFAULTIP
    fi
    echo
    echo -n "You typed $SERVICENAME_VIP, is that correct (Y/n)? "
    read -n1 YESNO
    if [ "$SERVICENAME_VIP" == "$WEBSSH2VIP" ]; then
      echo
      echo
      tput bel;tput bel;tput bel;tput bel;
      echo ERROR: $SERVICENAME VIP must not equal WEBSSH Service VIP
      YESNO="n"
      echo
    else
      echo
      if [[ ("$YESNO" != "n") && ("$SERVICENAME_VIP" != "$CHECKEDIP") ]]; then
        echo -n "Checking IP... "
        OUTPUT=$(ping -c 1 $SERVICENAME_VIP 2>&1)
        if [[ $? -eq 0 ]]; then
          tput bel;tput bel;tput bel;tput bel;
          echo "[FAILED]"
          echo
          echo "ERROR: IP address $SERVICENAME_VIP appears to be taken by another host on the network already."
          echo
          arp -a $SERVICENAME_VIP
          echo
          echo "Pick a different host or investigate the issue."
          echo
          YESNO="n"
        else
          echo "[OK]"
          CHECKEDIP=$SERVICENAME_VIP
        fi
      fi
    fi
  done
  return
}

downloadAndCheck() {
  echo "Checking for $FNAME..."
  if [ ! -f $FNAME ]; then
    echo -n "Downloading $FNAME... "
    OUTPUT=$((curl --progress-bar $URL > $FNAME) 2>&1)
    RESULT="$?" 2>&1
    PREVLINE=$(($LINENO-2))
    checkoutput
    echo -n "Downloading $FNAME.sha256... "
    OUTPUT=$((curl --progress-bar $URL.sha256 > $FNAME.sha256) 2>&1)
    RESULT="$?" 2>&1
    PREVLINE=$(($LINENO-2))
    checkoutput
  fi
  echo "Checking $FNAME hash..."
  sha256sum -c $FNAME.sha256
  if [ $? -gt 0 ]; then
    echo "SHA256 checksum failed. Halting."
    exit 255
  fi
}

checkProvision() {
  MISSINGMOD=""
  echo -e "\n\n"
  echo "Checking modules are provisioned."
  echo
  for i in $MODULESREQUIRED; do
    echo -n "Checking $i... "
    OUTPUT=$(tmsh list sys provision $i one-line|awk '{print $6}')
    if [ "$OUTPUT" == "" ]; then
      echo "[FAILED]"
      echo
      MISSINGMOD+="$i "
    else
      echo "OK"
      echo
    fi
  done
  if [ "$MISSINGMOD" == "" ]; then
    echo "SUCCESS: All modules provisioned."
  else
    echo "Modules: $MISSINGMOD are not provisioned."
    tput bel;tput bel
    echo
    echo "$MISSINGMOD may be provisioned to the level of $PROVLEVEL."
    echo
    echo "This could result in service interruption and a reboot may be required."
    echo
    echo -n "Would you like to provision them (Y/n)? "
    read -n1 YESNO
    if [ "$YESNO" != "n" ]; then
      echo
      echo -n "Provisioning "
      echo 'proc script::run {} {' > $WORKINGDIR/provision.tcl
      echo '  tmsh::begin_transaction' >> $WORKINGDIR/provision.tcl
      for i in $MISSINGMOD; do
        echo "  tmsh::modify /sys provision $i level $PROVLEVEL" >> $WORKINGDIR/provision.tcl
      done
      echo '  tmsh::commit_transaction' >> $WORKINGDIR/provision.tcl
      echo '}' >> $WORKINGDIR/provision.tcl
      OUTPUT=$((tmsh run cli script file $WORKINGDIR/provision.tcl)  2>&1)
      RESULT="$?" 2>&1
      PREVLINE=$(($LINENO-2))
      checkoutput
      sleep 10
      echo
      echo -n "Saving config "
      OUTPUT=$((tmsh save /sys config) 2>&1)
      RESULT="$?" 2>&1
      PREVLINE=$(($LINENO-2))
      checkoutput
      STATUS=
      echo
      echo -n "Waiting for provisioning to quiesce "
      while [[ "$STATUS" != "Active" ]]; do
        sleep 1
        echo -n .
        read STATUS </var/prompt/ps1
        if [ "$STATUS" == "REBOOT REQUIRED" ]; then
          tput bel;tput bel;tput bel;tput bel
          echo
          echo
          echo "Due to provisioning requirements, a reboot of this sytems is required."
          echo
          echo "Please reboot the system and re-run this script to continue."
          exit 255
        fi
      done
      echo "[OK]"
    else
      tput bel;tput bel;tput bel;tput bel
      echo -e "\n\n"
      echo "ERROR: Refusing to run until modules are provisioned. Please provision LTM APM and ILX"
      echo "and run script again."
      echo
      exit 255
    fi
  fi
  echo
}

echo -e "\n\n"
echo -n "Preparing environment... "
OUTPUT=$((mkdir -p $WORKINGDIR) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Changing to $WORKINGDIR... "
OUTPUT=$((cd $WORKINGDIR) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo "Adding directory ILX archive directory"
OUTPUT=$((mkdir -p $ILXARCHIVEDIR) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

checkProvision

tput bel;tput bel
echo
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
echo -e "\n\n"

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
OUTPUT=$((mv $STARTUPFNAME /config) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Placing $WEBSSHFNAME in $ILXARCHIVEDIR... "
OUTPUT=$((mv $WORKINGDIR/$WEBSSHFNAME $ILXARCHIVEDIR/$WEBSSHFNAME) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Placing $EPHEMERALFNAME in $ILXARCHIVEDIR... "
OUTPUT=$((mv $WORKINGDIR/$EPHEMERALFNAME $ILXARCHIVEDIR/$EPHEMERALFNAME) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating ephemeral_config data group... "
OUTPUT=$((tmsh create ltm data-group internal ephemeral_config { records add { DEBUG { data 2 } DEBUG_PASSWORD { data 1 } RADIUS_SECRET { data radius_secret } RADIUS_TESTMODE { data 1 } RADIUS_TESTUSER { data testuser } ROTATE { data 0 } pwrulesLen { data 8 } pwrulesLwrCaseMin { data 1 } pwrulesNumbersMin { data 1 } pwrulesPunctuationMin { data 1 } pwrulesUpCaseMin { data 1 } } type string }) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating ephemeral_LDAP_Bypass data group... "
OUTPUT=$((tmsh create ltm data-group internal ephemeral_LDAP_Bypass { records add { "cn=f5 service account,cn=users,dc=mydomain,dc=local" { } cn=administrator,cn=users,dc=mydomain,dc=local { } cn=proxyuser,cn=users,dc=mydomain,dc=local { } } type string }) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating ephemeral_RADIUS_Bypass data group... "
OUTPUT=$((tmsh create ltm data-group internal ephemeral_RADIUS_Bypass { type string }) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating ephemeral_radprox_host_groups data group... "
OUTPUT=$((tmsh create ltm data-group internal ephemeral_radprox_host_groups { type string }) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating ephemeral_radprox_radius_attributes data group... "
OUTPUT=$((tmsh create ltm data-group internal ephemeral_radprox_radius_attributes { records add { BLUECOAT { data "[['Service-Type', <<<VALUE>>>]]" } CISCO { data "[['Vendor-Specific', 9, [['Cisco-AVPair', 'shell:priv-lvl=<<<VALUE>>>']]]]" } DEFAULT { data "[['Vendor-Specific', 9, [['Cisco-AVPair', 'shell:priv-lvl=<<<VALUE>>>']]]]" } F5 { data "[['Vendor-Specific', 3375, [['F5-LTM-User-Role, <<<VALUE>>>]]]]" } PALOALTO { data "[['Vendor-Specific', 25461, [['PaloAlto-Admin-Role', <<<VALUE>>>]]]]" } } type string }) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating ephemeral_radprox_radius_client data group... "
OUTPUT=$((tmsh create ltm data-group internal ephemeral_radprox_radius_client { type string }) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Importing WebSSH2 Workspace... "
# create ilx workspace new from-uri https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-ILX-WebSSH2-current.tgz
OUTPUT=$((tmsh create ilx workspace $WEBSSHILXNAME from-archive $WEBSSHFNAME) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Importing Ephemeral Authentication Workspace... "
OUTPUT=$((tmsh create ilx workspace $EPHEMERALILXNAME from-archive $EPHEMERALFNAME) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Modifying Ephemeral Authentication Workspace... "
OUTPUT=$((tmsh modify ilx workspace $EPHEMERALILXNAME node-version 6.9.1) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo -e "\n\n"
echo -n "Creating WEBSSH Proxy Service Virtual Server... "
OUTPUT=$((tmsh create ltm virtual webssh_proxy { destination $WEBSSH2VIP:2222 ip-protocol tcp mask 255.255.255.255 profiles add { clientssl-insecure-compatible { context clientside } tcp { } } source 0.0.0.0/0 translate-address disabled translate-port disabled }) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating tmm route for Plugin... "
OUTPUT=$((tmsh create net route webssh_tmm_route gw 127.1.1.254 network $WEBSSH2VIP/32) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Installing webssh tmm vip startup script... "
OUTPUT=$((bash /config/$STARTUPFNAME $WEBSSH2VIP) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

#echo -n "Modifying WebSSH2 Workspace config.json... "
#OUTPUT=$(jq '.listen.ip = "0.0.0.0"' $ILXARCHIVEDIR/../$WEBSSHILXNAME/extensions/WebSSH2/config.json > $ILXARCHIVEDIR/../$WEBSSHILXNAME/extensions/WebSSH2/config.json)
#RESULT="$?" 2>&1
#PREVLINE=$(($LINENO-2))
#checkoutput

echo
echo -n "Creating WebSSH2 Plugin... "
OUTPUT=$((tmsh create ilx plugin $WEBSSHILXPLUGIN from-workspace $WEBSSHILXNAME extensions { webssh2 { concurrency-mode single ilx-logging enabled  } }) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating Ephemeral Authentication Plugin... "
OUTPUT=$((tmsh create ilx plugin $EPHEMERALILXPLUGIN from-workspace $EPHEMERALILXNAME extensions { ephemeral_auth { ilx-logging enabled } }) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating RADIUS Proxy Service Virtual Server... "
OUTPUT=$((tmsh create ltm virtual radius_proxy { destination $RADIUSVIP:1812 ip-protocol udp mask 255.255.255.255 profiles add { udp { } } source-address-translation { type automap } source 0.0.0.0/0 rules { $EPHEMERALILXPLUGIN/radius_proxy }}) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating LDAP Proxy Service Virtual Server... "
OUTPUT=$((tmsh create ltm virtual ldap_proxy { destination $LDAPVIP:389 ip-protocol tcp mask 255.255.255.255 profiles add { tcp { } } source-address-translation { type automap } source 0.0.0.0/0 rules { $EPHEMERALILXPLUGIN/ldap_proxy }}) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating LDAPS (ssl) Proxy Service Virtual Server... "
OUTPUT=$((tmsh create ltm virtual ldaps_proxy { destination $LDAPSVIP:636 ip-protocol tcp mask 255.255.255.255 profiles add { tcp { } clientssl { context clientside } serverssl-insecure-compatible { context serverside } } source-address-translation { type automap } source 0.0.0.0/0 rules { $EPHEMERALILXPLUGIN/ldap_proxy_ssl }}) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo -n "Creating pua APM Policy..."
cat >$WORKINGDIR/policy.tcl<<EOF
proc script::run {} {
  tmsh::begin_transaction
  tmsh::create /apm policy agent ending-allow /Common/pua_end_allow_ag { }
  tmsh::create /apm policy agent ending-deny /Common/pua_end_deny_ag { }
  tmsh::create /apm policy policy-item /Common/pua_end_allow { agents add { /Common/pua_end_allow_ag { type ending-allow } } caption Allow color 1 item-type ending }
  tmsh::create /apm policy policy-item /Common/pua_end_deny { agents add { /Common/pua_end_deny_ag { type ending-deny } } caption Deny color 2 item-type ending }
  tmsh::create /apm policy policy-item /Common/pua_ent { caption Start color 1 rules { { caption fallback next-item /Common/pua_end_deny } } }
  tmsh::create /apm policy access-policy /Common/pua { default-ending /Common/pua_end_deny items add { pua_end_allow { } pua_end_deny { } pua_ent { } } start-item pua_ent }
  tmsh::create /apm profile access /Common/pua { accept-languages add { en } access-policy /Common/pua}
  tmsh::create /apm profile connectivity pua-connectivity defaults-from connectivity
  tmsh::commit_transaction
}
EOF
OUTPUT=$((tmsh run cli script file $WORKINGDIR/policy.tcl) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo -n "Creating Webtop Virtual Server... "
OUTPUT=$((tmsh create ltm virtual pua_webtop { destination $WEBTOPVIP:443 ip-protocol tcp mask 255.255.255.255 profiles add { http pua rewrite-portal tcp { } pua-connectivity { context clientside } clientssl { context clientside } serverssl-insecure-compatible { context serverside } } rules { $EPHEMERALILXPLUGIN/APM_ephemeral_auth } source 0.0.0.0/0 }) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo
echo "RADIUS Testing Option:"
echo
echo "You can automatcially configure the BIG-IP for RADIUS authentication against itself for testing"
echo "purposes. If this is running on a production system, this may impact access and is not recommended."
echo "This option is recommended for lab and demo use only."
echo
tput bel;tput bel
echo -n "Do you want to configure this BIG-IP to authenticate against itself for testing purposes (y/N)? "
read -n1 YESNO
if [ "$YESNO" == "y" ]; then
  YESNO=n
  echo
  echo
  echo -n "Are you really sure!? (y/N)? "
  read -n1 YESNO
  echo
fi
if [ "$YESNO" == "y" ]; then
  echo -e "\n\n"
  echo -n "Modifying BIG-IP for RADIUS authentication against itself... "
cat >$WORKINGDIR/radius.tcl <<RADIUS
proc script::run {} {
  tmsh::begin_transaction
  tmsh::create /auth radius-server system_auth_pua secret radius_secret server $RADIUSVIP
  tmsh::create /auth radius system-auth { servers add { system_auth_pua } }
  tmsh::modify /auth remote-user default-role guest remote-console-access tmsh
  tmsh::modify /auth source type radius
  tmsh::commit_transaction
}
RADIUS
  OUTPUT=$((tmsh run cli script file $WORKINGDIR/radius.tcl) 2>&1)
  RESULT="$?" 2>&1
  PREVLINE=$(($LINENO-2))
  checkoutput
  echo -e "\n\n"
  echo "You can test your new configuration now by browsing to:"
  echo
  echo "  https://$WEBSSH2VIP:2222/ssh/host/$MGMTIP"
  echo
  echo "  username: testuser"
  echo "  password: anypassword"
  echo
  echo "This will allow anyone using the username testuser to log in with any password as a guest"
  echo
fi

echo -n "Saving config... "
OUTPUT=$((tmsh save /sys config) 2>&1)
RESULT="$?" 2>&1
PREVLINE=$(($LINENO-2))
checkoutput

echo "Task complete."
echo
echo "Now go build an APM policy for pua!"


exit 0
