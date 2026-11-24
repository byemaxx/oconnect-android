# Experimental Root ePDG mode

This opt-in mode preserves the existing OpenConnect authentication/UI, but does not call `VpnService.Builder.establish()`. The service class and Android's original VPN permission flow remain for compatibility. A native root helper opens a non-persistent TUN, authenticates the application UID on a random abstract Unix socket and transfers its descriptor using SCM_RIGHTS. Only outbound locally generated IPv4 UDP 500/4500 traffic to configured public ePDG addresses is routed into the tunnel. Source NAT uses the VPN-assigned IPv4 address. Other traffic, system DNS and cellular IMS are not deliberately redirected. No SELinux changes or modem changes are made.

## Test

1. Confirm that use of the VPN for Wi-Fi Calling is allowed by the VPN operator.
2. Install the debug APK; it has the upstream application ID and a different signing key, so it cannot replace an upstream release in place. Back up/export profiles before uninstalling or use a test device.
3. Disable any other VPN, proxy, and previous IKE routing modules. Connect to Wi-Fi (airplane mode with Wi-Fi enabled is recommended).
4. In Advanced Settings, enable **Root ePDG mode (experimental)** and set the target domain or known-good IPv4 addresses from a successful control test.
5. Tap **Test root access** to verify UID 0 and temporary TUN creation. The test does not add routes or NAT rules. Connect normally and grant root permission; root is checked again before authentication. Authentication and MFA are unchanged.
6. Confirm no Android VPN NetworkAgent was established with `dumpsys connectivity`; check `ip -br addr`, `ip -4 rule show`, and `logcat -s OConnectRoot`. Retry IMS registration.
7. Disconnect and check that the helper's routing and SNAT rules are removed. Disable root mode and reconnect to restore normal behavior.

The prototype supports IPv4 only and refuses nonempty server split-includes. It does not change ePDG DNS selection or circumvent VPN server/client compliance checks. The Android system still sees the physical Wi-Fi; DNS or Qualcomm socket interface binding can prevent successful registration. It has not been verified on a device. Root mode is not a full-device VPN, and Android's VPN lockdown/always-on semantics do not apply. Do not use it with other VPNs. On abrupt root helper termination (SIGKILL), session-specific rules may remain until reboot; check the logged interface and routing table. A normal disconnect or app-process death closes the control socket and initiates cleanup.

Build using `git submodule update --init --recursive`, `make -C external install-arch-arm64 ANDROID_NDK="$ANDROID_HOME/ndk/27.2.12479018"`, then `./gradlew testDebugUnitTest assembleDebug`. The GitHub Actions workflow uploads the ARM64 debug APK when the build succeeds.

## TUN compatibility option

On Android 8+, **Ensure TUN support** (formerly Load tun module) is always selectable. When enabled, it first checks whether UID 0 can create a temporary TUN interface. If successful, it skips module loading, including kernels with CONFIG_TUN=y. If the TUN device is absent, it tries only an existing OS-provided tun.ko at a known system/vendor module path and verifies TUN afterward. Permission errors do not trigger module loading. No foreign kernel module is bundled or forced into the running kernel. The option is independent of Root ePDG mode and is optional on devices that already support TUN.

## Wi-Fi preflight

Before requesting VPN credentials or MFA, Root ePDG mode selects a physical Wi-Fi internet network (including Wi-Fi that is not the default network), resolves the ePDG targets on it, and binds only the OConnect application process to that network. An active Android VPN is rejected before authentication. The binding is restored on session termination. After CSTP setup, the code verifies only the selected Wi-Fi is still available and uses the pre-resolved targets; it no longer treats a cellular default network as a missing Wi-Fi connection. Wi-Fi loss during setup can still cause a real connection failure. The ordinary VpnService mode is unchanged.
