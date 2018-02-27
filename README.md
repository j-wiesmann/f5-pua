# Introduction

This script will configure a reference implementation of the F5 Privileged User Authentication
solution. The only requirements are a running and licensed system ("Active"), initial configuration complete (licensed, VLANs, self IPs), and preferably already provisioned for LTM+APM+ILX. The script will check for and can enable it for you if you wish.

You will be prompted for IP addresses for 5 services:

1. WebSSH Proxy - This IP address may not be shared with any other IP on the BIG-IP. This will be the only service with this restriction. This proxy is ultimately called by the APM web top. It’s also important to note that SNAT may not be used on this virtual server. (webssh_proxy)

2. RADIUS Proxy – This runs the RADIUS Ephemeral Authentication Service. This IP may be shared with other IPs on the BIG-IP system if the protocol/port (udp/1812) do not conflict. (radius_proxy)

3. LDAP Proxy – This runs the LDAP Ephemeral Authentication Service. This IP may be shared with other IPs on the BIG-IP system if the protocol/port (tcp/389) do not conflict. (ldap_proxy)

4. LDAPS Proxy – This runs the LDAPS (ssl) Ephemeral Authentication Service. This IP may be shared with other IPs on the BIG-IP system if the protocol/port (tcp/636) do not conflict. (ldaps_proxy)

5. Web top – This runs the LDAP Ephemeral Authentication Service. This IP may be shared with other IPs on the BIG-IP system if the protocol/port (tcp/443) do not conflict. By default SNAT is disabled for this vs as the WebSSH proxy may not interoperate with SNAT. If you change this option be sure to institute some sort of selective disable option (iRule) when connecting to the webssh_proxy as a portal resource.

WebSSH, LDAPS, and web top will all be initially configured with a default client-ssl profile, after testing this should be changed to use a legitimate certificate.

A blank APM policy is created and attached to the web top vs “pua_webtop”, this policy will need to be built out for the pua_webtop service to operate correctly.

# RADIUS Testing

The BIG-IP administrative interface can be configured to authenticate against itself for testing. This will allow “admin” and anyone using the test account “testuser” with ANY password to authenticate as a guest to the GUI or SSH. If you enable this option, instructions will be provided at the end of this script for testing.

# Non-interactive mode
A file called `pua_config.sh` may be placed in the same directory as `build_pua.sh` or `build_pua_offline.sh` to fully automate the install, or provide defaults for a "semi-automatic" deployment. See [pua_config.sh](https://github.com/billchurch/f5-pua/blob/master/pua_config.sh) as an example.

When started, `build_pua.sh` or `build_pua_offline.sh` both check for the existence of this file.

Additionally, most of the variables set in the top of `pua_config.sh` and `pua_config_offline.sh` may be overridden by this file.

# Instructions
A full guide is available at [PUA Solution Install Guide.docx](https://raw.githubusercontent.com/billchurch/f5-pua/master/docs/PUA%20Solution%20Install%20Guide.docx)

- Configure a BIG-IP with VLAN and self IP
- download [build_pua_offline.zip](https://github.com/billchurch/f5-pua/blob/master/build_pua.zip) and copy to BIG-IP
- unzip `build_pua_offline.zip`
- run `bash build_pua_offline.sh`
- follow the directions
- build out/customize APM policy
- profit?

# Windows Users

Don't try to download the `.sh` files... Your OS will mess those bash scripts up something good. Just get their `.zip` versions. :)

# Mac and Linux Users

Feel free to download [build_pua.sh](https://github.com/billchurch/f5-pua/blob/master/bin/build_pua.sh) and [build_pua_offline.sh](https://github.com/billchurch/f5-pua/blob/master/bin/build_pua_offline.sh) directly and save yourself a step... Go nuts!

# Folders
**scripts/** - my maintance scripts for building out these packages, they won't help you a bit

**bin/** - deployment folder which is either referenced by these scripts `build_pua.(sh|zip)` or embedded in them `build_pua_offline.(sh|zip)`. You won't need anything from here usually...
