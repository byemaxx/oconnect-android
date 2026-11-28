# Experimental Root ePDG mode

This opt-in mode preserves the existing OpenConnect authentication/UI, but does not call `VpnService.Builder.establish()`. The service class and Android's original VPN permission flow remain for compatibility. A native root helper opens a non-persistent TUN, authenticates the application UID on a random abstract Unix socket and transfers its descriptor using SCM_RIGHTS. Only outbound locally generated IPv4 UDP 500/4500 traffic to configured public ePDG addresses is routed into the tunnel. Source NAT uses the VPN-assigned IPv4 address. Other traffic, system DNS and cellular IMS are not deliberately redirected. No SELinux changes or modem changes are made.

## Test

1. Confirm that use of the VPN for Wi-Fi Calling is allowed by the VPN operator.
2. Install the debug APK; it has the upstream application ID and a different signing key, so it cannot replace an upstream release in place. Back up/export profiles before uninstalling or use a test device.
3. Disable any other VPN, proxy, and previous IKE routing modules. Connect to Wi-Fi (airplane mode with Wi-Fi enabled is recommended).
4. In Advanced Settings, enable **Root ePDG mode (experimental)** and set the target domain or known-good IPv4 addresses from a successful control test.
5. Tap **Test root access** to verify UID 0 and temporary TUN creation. The test does not add routes or NAT rules. Connect normally and grant root permission; root is checked again before authentication. Root ePDG mode automatically ensures TUN support even if the optional switch is off. Authentication and MFA are unchanged.
6. Confirm no Android VPN NetworkAgent was established with `dumpsys connectivity`; check `ip -br addr`, `ip -4 rule show`, and `logcat -s OConnectRoot`. Retry IMS registration.
7. Disconnect and check that the helper's routing and SNAT rules are removed. Disable root mode and reconnect to restore normal behavior.

The prototype supports IPv4 only and refuses nonempty server split-includes. It does not change ePDG DNS selection or circumvent VPN server/client compliance checks. The Android system still sees the physical Wi-Fi; DNS or Qualcomm socket interface binding can prevent successful registration. It has not been verified on a device. Root mode is not a full-device VPN, and Android's VPN lockdown/always-on semantics do not apply. Do not use it with other VPNs. On abrupt root helper termination (SIGKILL), session-specific rules may remain until reboot; check the logged interface and routing table. A normal disconnect or app-process death closes the control socket and initiates cleanup.

Build using `git submodule update --init --recursive`, `make -C external install-arch-arm64 ANDROID_NDK="$ANDROID_HOME/ndk/27.2.12479018"`, then `./gradlew testDebugUnitTest assembleDebug`. The GitHub Actions workflow uploads the ARM64 debug APK when the build succeeds.

## TUN compatibility option

On Android 8+, **Ensure TUN support** (formerly Load tun module) is always selectable. When enabled, it first checks whether UID 0 can create a temporary TUN interface. If successful, it skips module loading, including kernels with CONFIG_TUN=y. If neither TUN device node is usable and `/proc/misc` confirms that TUN is not registered, it tries only an existing OS-provided tun.ko at a known system/vendor module path and verifies TUN afterward. Permission errors, an already registered driver with missing device nodes, and an unreadable registration state do not trigger module loading. No foreign kernel module is bundled or forced into the running kernel. Root ePDG mode automatically runs the same check before authentication, irrespective of this switch; the switch only controls the optional preflight for ordinary VPN mode.

## Wi-Fi preflight

Before requesting VPN credentials or MFA, Root ePDG mode selects a physical Wi-Fi internet network (including Wi-Fi that is not the default network), resolves the ePDG targets on it, and binds only the OConnect application process to that network. An active Android VPN is rejected before authentication. The binding is restored on session termination. After CSTP setup, the code verifies only the selected Wi-Fi is still available and uses the pre-resolved targets; it no longer treats a cellular default network as a missing Wi-Fi connection. Wi-Fi loss during setup can still cause a real connection failure. The ordinary VpnService mode is unchanged.

## Freedom relay on Qualcomm Wi-Fi

Set **Freedom Wi-Fi Calling endpoint** on the main VPN profile editor to enable the relay in either Global or Wi-Fi Calling only mode. Open **Wi-Fi Calling** from the home screen to choose the connection mode or target SIM, check root access, or configure the Wi-Fi Calling only ePDG target. Enter `auto` in the profile to resolve the Freedom ePDG hostname on the selected physical Wi-Fi when connecting. Global mode selects the first DNS IPv4 candidate allowed by the VPN server's routes. Only one endpoint is used per session; a DNS answer and a permitted route do not guarantee IKE reachability. A known-good profile IPv4 remains supported unchanged (the historical uOttawa Staff endpoint was `208.98.222.239`), as does the older `freedom=208.98.222.239` Wi-Fi Calling only setting. Leave the profile field blank to disable its relay.

This mode requires Wi-Fi IPv4, an IPv4 or link-local IPv6 Wi-Fi resolver, Qualcomm reverse rmnet interfaces, and a Wi-Fi egress clsact. It answers only the Freedom ePDG hostname and carries the selected endpoint's UDP 500 and 4500 over the VPN. It returns IKE signaling to the modem and encrypted IMS packets to the Wi-Fi input path. When network-change reconnect is enabled, the app rebuilds the session after a Wi-Fi interface, IPv4 address, or DNS change. The VPN server may request authentication again.

A normal disconnect removes the relay workers, its two Wi-Fi filters, its root-only route and its temporary capture interface.

Global mode uses the Android VPN TUN for both app traffic and the selected ePDG. The relay checks the server IPv4 inclusion and exclusion routes for the configured endpoint. Manual split-route profiles are outside this mode. Connection details report the relay stage and query the phone for Freedom IMS availability when that view is open.

The device smoke test in `external/tests` passes a test TUN descriptor to the broker and checks rule cleanup at disconnect and after a filter collision. Build the client with the ARM64 Android NDK compiler, push the client, helper, and shell script to a rooted Qualcomm test device, and run the script under root with the helper and client paths.

## SIM-based discovery

For Global VPN, opt in using **Enable ePDG relay for this profile**; existing nonempty endpoint settings retain their previous opt-in unless explicitly disabled. Wi-Fi Calling only mode defaults to automatic relay discovery when its advanced override is empty. Select Target SIM in Wi-Fi Calling settings if multiple SIMs cannot be distinguished by their Wi-Fi Calling enabled state. The app reads the target subscription and home PLMN through a bounded root probe, tries a configured static IWLAN address and then the standard home PLMN hostname, and resolves on physical Wi-Fi. The native DNS worker matches the exact selected hostname. An IPv4 override retains the target SIM's standard home hostname. Bare legacy targets in Wi-Fi Calling only mode still use direct routing. Qualcomm reverse rmnet, IPv4 endpoints, and one relay endpoint per session remain limitations. PCO/visited-country discovery and automatic IKE failover are not implemented. No device validation is implied by CI.
