# Introduction

This script will configure a reference implementation of the F5 Privileged User Authentication
solution. The only requirements are a running and licensed system ("Active"), initial configuration complete (licensed, VLANs, self IPs), and preferably already provisioned for LTM+APM+ILX. The script will check for and can enable it for you if you wish.

You will be prompted for IP addresses for 5 services:

1. WebSSH Proxy - This IP address may not be shared with any other IP on the BIG-IP. This will be the only service with this restriction. This proxy is ultimately called by the APM web top. It’s also important to note that SNAT may not be used on this virtual server. (webssh_proxy)

2. RADIUS Proxy – This runs the RADIUS Ephemeral Authentication Service. This IP may be shared with other IPs on the BIG-IP system if the protocol/port (udp/1812) do not conflict. (radius_proxy)

3. LDAP Proxy – This runs the LDAP Ephemeral Authentication Service. This IP may be shared with other IPs on the BIG-IP system if the protocol/port (tcp/389) do not conflict. (ldap_proxy)

4. LDAPS Proxy – This runs the LDAPS (ssl) Ephemeral Authentication Service. This IP may be shared with other IPs on the BIG-IP system if the protocol/port (tcp/389) do not conflict. (ldaps_proxy)

5. Web top – This runs the LDAP Ephemeral Authentication Service. This IP may be shared with other IPs on the BIG-IP system if the protocol/port (tcp/389) do not conflict. By default SNAT is disabled for this vs as the WebSSH proxy may not interoperate with SNAT. If you change this option be sure to institute some sort of selective disable option (iRule) when connecting to the webssh_proxy as a portal resource.

WebSSH, LDAPS, and web top will all be initially configured with a default client-ssl profile, after testing this should be changed to use a legitimate certificate.

A blank APM policy is created and attached to the web top vs “pua_webtop”, this policy will need to be built out for the pua_webtop service to operate correctly.

# RADIUS Testing

The BIG-IP administrative interface can be configured to authenticate against itself for testing. This will allow “admin” and anyone using the test account “testuser” with ANY password to authenticate as a guest to the GUI or SSH. If you enable this option, instructions will be provided at the end of this script for testing.



# Instructions

- Configure a BIG-IP with VLAN and self IP
- download `bin/build_pua_offline.sh` and copy to BIG-IP
- run `bash build_pua_offline.sh`
- follow the directions
- build out/customize APM policy
- profit?

# Windows Users

Download the `.zip` versions of the `.sh` files... Your OS will mess those bash scripts up something good. :)
