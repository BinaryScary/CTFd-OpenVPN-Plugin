from CTFd.utils.decorators import authed_only
from CTFd.utils.user import get_current_user, get_current_team
from flask import request, send_from_directory, Flask
import os
from slugify import slugify
from OpenSSL import crypto, SSL

# download page markdown
# !replace the urls with the current domain!
"""
# OpenVPN Download Page
### User Certificate Download
A certificate can only establish one connection at a time, avoid using the same certificate to prevent networking issues.
- [User Generated Certificate](openvpn_certificate)

### Rules
- OpenVPN server is out of scope/play for CTF challenges
- Foulplay will result in user ban and removal from game.

### Help
For VPN connection help please follow the appropriate guide listed below.
- [Windows Connection Guide](https://openvpn.net/vpn-server-resources/connecting-to-access-server-with-windows/)
- [Linux Connection Guide](https://openvpn.net/vpn-server-resources/connecting-to-access-server-with-linux/)
- [Mac OS Connection Guide](https://openvpn.net/vpn-server-resources/connecting-to-access-server-with-macos/)
"""

app = Flask(__name__)
# replace with /opt/openvpn/client-configs if CTF docker container is used
CLIENT_CERT_DIR  = os.path.join(app.root_path, "client-configs") 
# inline certificate to avoid filereads, not safe!
SERIAL = 0x00000000000000000000000000000000
BASECONF = """##############################################
#    client-side OpenVPN 2.0 config file     #
# for connecting to multi-client server.     #
#                                            #
# This configuration can be used by multiple #
# clients, however each client should have   #
# its own cert and key files.                #
#                                            #
# On Windows, you might want to rename this  #
# file so it has a .ovpn extension           #
##############################################

# Specify that we are a client and that we
# will be pulling certain config file directives
# from the server.
client

# Use the same setting as you are using on
# the server.
# On most systems, the VPN will not function
# unless you partially or fully disable
# the firewall for the TUN/TAP interface.
;dev tap
dev tun

# Windows needs the TAP-Win32 adapter name
# from the Network Connections panel
# if you have more than one.  On XP SP2,
# you may need to disable the firewall
# for the TAP adapter.
;dev-node MyTap

# Are we connecting to a TCP or
# UDP server?  Use the same setting as
# on the server.
;proto tcp
proto udp

# The hostname/IP and port of the server.
# You can have multiple remote entries
# to load balance between the servers.
remote vpn.domain.tld 1194

# Choose a random host from the remote
# list for load-balancing.  Otherwise
# try hosts in the order specified.
;remote-random

# Keep trying indefinitely to resolve the
# host name of the OpenVPN server.  Very useful
# on machines which are not permanently connected
# to the internet such as laptops.
resolv-retry infinite

# Most clients don't need to bind to
# a specific local port number.
nobind

# Downgrade privileges after initialization (non-Windows only)
user nobody
group nogroup

# Try to preserve some state across restarts.
persist-key
persist-tun

# If you are connecting through an
# HTTP proxy to reach the actual OpenVPN
# server, put the proxy server/IP and
# port number here.  See the man page
# if your proxy server requires
# authentication.
;http-proxy-retry # retry on connection failures
;http-proxy [proxy server] [proxy port #]

# Wireless networks often produce a lot
# of duplicate packets.  Set this flag
# to silence duplicate packet warnings.
;mute-replay-warnings

# SSL/TLS parms.
# See the server config file for more
# description.  It's best to use
# a separate .crt/.key file pair
# for each client.  A single ca
# file can be used for all clients.
;ca ca.crt
;cert client.crt
;key client.key

# Verify server certificate by checking that the
# certicate has the correct key usage set.
# This is an important precaution to protect against
# a potential attack discussed here:
#  http://openvpn.net/howto.html#mitm
#
# To use this feature, you will need to generate
# your server certificates with the keyUsage set to
#   digitalSignature, keyEncipherment
# and the extendedKeyUsage to
#   serverAuth
# EasyRSA can do this for you.
remote-cert-tls server

# If a tls-auth key is used on the server
# then every client must also have the key.
;tls-auth ta.key 1

# Select a cryptographic cipher.
# If the cipher option is used on the server
# then you must also specify it here.
# Note that v2.4 client/server will automatically
# negotiate AES-256-GCM in TLS mode.
# See also the ncp-cipher option in the manpage
cipher AES-256-GCM
auth SHA256

# key direction for tls-auth
key-direction 1

# resolvconf
; script-security 2
; up /etc/openvpn/update-resolv-conf
; down /etc/openvpn/update-resolv-conf
# systemd-resolved
; script-security 2
; up /etc/openvpn/update-systemd-resolved
; down /etc/openvpn/update-systemd-resolved
; down-pre
; dhcp-option DOMAIN-ROUTE .

# Enable compression on the VPN link.
# Don't enable this unless it is also
# enabled in the server config file.
#comp-lzo

# Set log file verbosity.
verb 3

# Silence repeating messages
;mute 20 """

# this is not safe
CACERT = """-----BEGIN CERTIFICATE-----
REDACTED
-----END CERTIFICATE-----"""
CAKEY = """-----BEGIN EC PRIVATE KEY-----
REDACTED
-----END EC PRIVATE KEY-----"""
TAKEY = """-----BEGIN OpenVPN Static key V1-----
REDACTED
-----END OpenVPN Static key V1-----"""

# Create a new keypair of specified algorithm and number of bits.
def make_keypair(algorithm=crypto.TYPE_RSA, numbits=2048):
    pkey = crypto.PKey()
    pkey.generate_key(algorithm, numbits)
    return pkey

# Creates a certificate signing request (CSR) given the specified subject attributes.
def make_csr(pkey, CN, C=None, ST=None, L=None, O=None, OU=None, emailAddress=None, hashalgorithm='sha256WithRSAEncryption'):
    req = crypto.X509Req()
    req.get_subject()
    subj  = req.get_subject()

    if C:
        subj.C = C
    if ST:
        subj.ST = ST
    if L:
        subj.L = L
    if O:
        subj.O = O
    if OU:
        subj.OU = OU
    if CN:
        subj.CN = CN
    if emailAddress:
        subj.emailAddress = emailAddress

    req.set_pubkey(pkey)
    req.sign(pkey, hashalgorithm)
    return req

# Create a new cert.
# does not have to include client extensions
def make_cert(csr, cakey, cacert, serial):
    cert = crypto.X509()
    cert.set_serial_number(serial)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60*60*24*365*1) # 1 yr 
    cert.set_issuer(cacert.get_subject())
    cert.set_subject(csr.get_subject())
    cert.set_pubkey(csr.get_pubkey())
    cert.set_version(2)

    extensions = []
    extensions.append(crypto.X509Extension(b'basicConstraints', False ,b'CA:FALSE'))

    extensions.append(crypto.X509Extension(b'subjectKeyIdentifier' , False , b'hash', subject=cert))
    extensions.append(crypto.X509Extension(b'authorityKeyIdentifier' , False, b'keyid:always,issuer:always', subject=cacert, issuer=cacert))

    cert.add_extensions(extensions)
    cert.sign(cakey, 'sha256WithRSAEncryption')

    return cert

# clientname/common name does not have to be unique
def make_client_cert(clientname):
    # load CA cert and key
    cacert = crypto.load_certificate(crypto.FILETYPE_PEM, CACERT)
    cakey  = crypto.load_privatekey(crypto.FILETYPE_PEM, CAKEY)

    # Generate a new private key pair for a new certificate.
    key = make_keypair()
    # Generate a certificate request
    csr = make_csr(key, clientname)
    # Sign the certificate with the new csr
    crt = make_cert(csr, cakey, cacert, SERIAL)

    # create a .ovpn file
    clientkey  = crypto.dump_privatekey(crypto.FILETYPE_PEM,key).decode("utf-8") 
    clientcert = crypto.dump_certificate(crypto.FILETYPE_PEM,crt).decode("utf-8") 
    ovpn = "%s\n<ca>\n%s\n</ca>\n<cert>\n%s\n</cert>\n<key>\n%s\n</key>\n<tls-crypt>\n%s\n</tls-crypt>\n" % (BASECONF, CACERT, clientcert, clientkey, TAKEY)

    return ovpn

# create client certificates and serve, max 3 per team
def load(app):
    @app.route('/openvpn_certificate', methods=['GET'])
    @authed_only
    def download_config():
        # slugify filename (teams can game this to create dup certs)
        team = get_current_team()
        if team == None:
            team_name = "NONE"
        else:
            team_name = slugify(str(team.name))

        # get cert filename, common name, and directory
        user = get_current_user()
        user_id = str(user.id)
        user_name = slugify(str(user.name))
        
        common_name = "%s-%s-%s" % (team_name,user_name,user_id)
        cert_name = "%s.ovpn" % (common_name)

        # make client config directory if it does not exist
        if not os.path.exists(CLIENT_CERT_DIR):
            os.makedirs(CLIENT_CERT_DIR)
        
        # create cert if does not exist
        cert_path = os.path.join(CLIENT_CERT_DIR,cert_name)
        if not os.path.exists(cert_path):
            ovpn = make_client_cert(common_name)
            with open(cert_path, "w") as f:
                f.write(ovpn)

        return send_from_directory(directory=CLIENT_CERT_DIR, filename=cert_name)
