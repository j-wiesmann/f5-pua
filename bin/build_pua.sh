#!/bin/bash
# Filename: build_pua.sh
#
# Builds out a reference PUA deployment on a BIG-IP running TMOS 13.1.0.2
#
# Bill Church - bill@f5.com
set -o history -o histexpand

WORKINGDIR=/tmp/pua

STARTUPURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/startup_script_webssh_commands.sh
STARTUPFNAME=startup_script_webssh_commands.sh
WEBSSHURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-ILX-WebSSH2-current.tgz
WEBSSHFNAME=BIG-IP-ILX-WebSSH2-current.tgz
WEBSSHSUM=733a9aa1f9db001e469a8e825d304c497dc9c743f46e6a7d973927015d5fb765
WEBSSHILXNAME=WebSSH2-0.2.0
EPHEMERALURL=https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-ILX-ephemeral_auth-current.tgz
EPHEMERALFNAME=BIG-IP-ILX-ephemeral_auth-current.tgz
EPHEMERALILXNAME=ephemeral_auth-0.2.8
ILXARCHIVEDIR=/var/ilx/workspaces/Common/archive/

checkoutput() {
  if [ $RESULT -eq 0 ]; then
    echo SUCCESS: $CMD
    return
  else
    #failure
    echo;echo;echo "Previous command failed: $CMD"
    exit
  fi
}

mkdir -p $WORKINGDIR
CMD=$!! RESULT=$?
checkoutput

cd $WORKINGDIR
CMD=$!! RESULT=$?
checkoutput

curl $STARTUPURL > $STARTUPFNAME
CMD=$!! RESULT=$?
checkoutput

curl $WEBSSHURL > $WEBSSHFNAME
CMD=$!! RESULT=$?
checkoutput

curl $EPHEMERALURL > $EPHEMERALFNAME
CMD=$!! RESULT=$?
checkoutput

mv $WORKINGDIR/$WEBSSHFNAME $ILXARCHIVEDIR/$WEBSSHFNAME
CMD=$!! RESULT=$?
checkoutput

mv $WORKINGDIR/$EPHEMERALFNAME $ILXARCHIVEDIR/$EPHEMERALFNAME
CMD=$!! RESULT=$?
checkoutput

# create ilx workspace new from-uri https://raw.githubusercontent.com/billchurch/f5-pua/master/bin/BIG-IP-ILX-WebSSH2-current.tgz
create ilx workspace $WEBSSHILXNAME from-archive $WEBSSHFNAME
CMD=$!! RESULT=$?
checkoutput

create ilx workspace$EPHEMERALILXNAME from-archive $EPHEMERALFNAME
CMD=$!! RESULT=$?
checkoutput
