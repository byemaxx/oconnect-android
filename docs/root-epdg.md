# Experimental Root ePDG mode

This opt-in, per-profile experiment keeps OConnect's original authentication,
certificate verification, cookie, CSTP and DTLS code. It replaces only the
TUN establishment with a privileged native helper and an FD passed over a
local Unix socket. The service still inherits VpnService for existing UI and
permission/foreground lifecycle, but does not call Builder.establish() in
root mode and does not register a VPN NetworkAgent. Android may still show its
initial permission dialog. This is not a general VPN, privacy tunnel or
kill switch.

## Build

Use the original project's build instructions:

    git submodule update --init --recursive
    make -C external install
    ./gradlew testDebugUnitTest lintDebug assembleDebug

The native helper is built for the existing four ABIs and packaged with the
other native executables. For a OnePlus 13, ARM64-only native build:
    make -C external install-arch-arm64

Install the debug APK from app/build/outputs/apk/debug/app-debug.apk.
A debug build may not update an upstream APK signed with a different key.
Back up profiles before uninstalling the upstream APK; do not disable
signature checks.

## Use

1. Ensure the VPN operator authorizes the intended traffic and third-party
   client. Do not bypass authentication, server routes or device policy.
2. Disconnect all Android VPNs and root transparent proxies.
3. On a known-working network, capture/resolve the actual carrier ePDG IPv4.
   For Freedom Mobile the candidate home ePDG name is
   epdg.epc.mnc490.mcc302.pub.3gppnetwork.org; verify the actual target.
4. Edit the VPN profile > Advanced > Experimental root networking.
   Enable ROOT ePDG only, enter that IPv4 address, leave split-tunnel mode
   Automatic, and connect manually. Grant the app root when requested.
5. Check logcat -s OConnectRoot and the app log.
6. Trigger Wi-Fi Calling again (e.g. airplane mode, Wi-Fi on, IMS retry).
   Confirm a real IMS registration; a connected VPN alone is not success.

The helper installs only two local IPv4 UDP policy rules for the configured
destination (500/4500), a /32 route in table 19270, narrowly scoped SNAT,
and ingress/forwarding guards for its private interface ocroot0. The assigned
VPN IPv4 address is configured as a /32 so the server subnet does not add
an unintended connected route to the main table. It will
refuse an occupied interface/table/priorities and a target excluded by the
VPN server. No global default route, DNS changes, telephony changes,
IPv6 changes on physical interfaces, or cellular routes. A nonpersistent
TUN and the local control socket tie the routes to the session. Disconnect
to roll back. Reconnect manually if the underlying connection changes.
Turn off the app\'s pause-on-screen-off setting if you need the experiment
while the display is off; pause requests disconnect this root mode.

## Diagnostics (root)

    ip -br addr show dev ocroot0
    ip -4 rule show | grep -E '9100:|9101:'
    ip -4 route show table 19270
    iptables -t nat -L POSTROUTING -v -n -x | grep oconnect-root-epdg
    logcat -s OConnectRoot

With tcpdump available:

    tcpdump -i ocroot0 -nn 'udp port 500 or udp port 4500'

Compare with wlan0 to distinguish bypass from actual VPN transport.
If no packet reaches the tunnel, Qualcomm may not have initiated IKE,
may bind its socket to a physical device, may use a different ePDG or
IPv6 address, or Android/SELinux may reject the helper or route selectors.
DNS continues to use the normal network. This first version does not
route DNS, raw ESP, arbitrary apps or IPv6. It does not promise VoWiFi.
The VPN server's advertised route restrictions are respected; server-side
UDP policy may still block traffic.

After disconnect the two rules, route and tagged firewall entries should
be absent. A forced SIGKILL of the helper may prevent rollback; reboot
clears nonpersistent kernel state. Do not flush global route/firewall
tables. Never enable always-on/lockdown for this experimental mode.
No root connection is automatically started at boot.

## Validation

The policy unit tests cover address parsing, route inclusion/exclusion,
and invalid input. Device tests are still required for the Android
root executable, FD transfer, SELinux, route selectors, DNS, NAT, and
actual IMS registration.
