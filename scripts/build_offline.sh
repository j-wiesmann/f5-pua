#!/bin/bash
#
# build offline version of build_pua.sh

cd bin/

cp build_pua.sh build_pua_offline.sh
echo __PUA_ARCHIVE__ >> build_pua_offline.sh
tar -cvzf - -T ../scripts/ARCHIVE.LIST | base64 >> build_pua_offline.sh
zip build_pua_offline.zip build_pua_offline.sh
zip build_pua.zip build_pua.sh
