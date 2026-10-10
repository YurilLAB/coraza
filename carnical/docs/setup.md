# Set up an installed Carnical WAF

On Windows (PowerShell) or Linux, run:

```sh
carnical setup
```

If the binary is not on PATH, use `./carnical setup` on Linux or `./carnical.exe setup`
in PowerShell. Build from `carnical/` with `go build -o carnical ./cmd/carnical` on Linux
or `go build -o carnical.exe ./cmd/carnical` on Windows.

The wizard asks for:

- Website names, including every name visitors will use.
- A separate origin URL or IP. A bare address means HTTPS; use an explicit `http://` for a local HTTP origin.
- Exact allowances for a local/private origin and the HTTP Host it expects.
- A listening IP/port and visitor TLS arrangement.
- Existing visitor certificates, optional origin CA/client certificate files, and trusted gateway peers.
- Detection or blocking mode, WordPress protection, and an optional origin connection check.

Choose `https` for direct visitor TLS. The certificate must be current, match its key and
cover every website name. Choose `local` for loopback HTTP tests, or `proxy` behind an
existing TLS gateway. Gateway HTTP requires a specific loopback/private listener and trusted
peer addresses; restrict network access to those peers. Trusting forwarding headers alone
does not restrict who can connect. Certificate issuance and renewal remain with the operator.

Setup runs the normal startup validation without starting a listener. The optional origin
check resolves the origin and checks TCP/TLS within ten seconds; it sends no HTTP request.
Setup does not change DNS, firewall rules, certificates or installed services.

## Save and start

After validation, the wizard asks whether to save. Answer `n` to leave no configuration or
key file. Answer `y`, choose a new site file (default `site.json`) and a separate key file.
Existing files are never replaced. Interrupted setup before saving also leaves no files.

It prints commands such as:

```sh
carnical -config site.json -check
carnical -config site.json
```

For a custom key location, the printed commands include `-config-key-file`. The printed
quoting is for the host's shell: PowerShell on Windows, a POSIX shell on Linux.
Run the WAF with the same account as setup, or prepare the key for the service account below.
Settings load once, before listening and confinement; changes require restart.

Detection mode records CRS findings and monitors request formats. Blocking mode enables
both content layers. Flood and proxy safety checks still enforce in detection mode. Review
real application traffic before changing production policy. CLI options override site-file
values, including encrypted fields; invalid ciphertext still fails startup.

## What is encrypted

The site file keeps website names, listener, modes and WordPress settings in its readable
`flags` object. The `private` object contains a random key ID and AES-256-GCM ciphertext for
the origin URL, origin HTTP Host, private allowances, trusted peers and certificate/key paths.
Each save creates an independent random 32-byte key and random nonce. Authentication failure,
unknown fields, duplicate flags across sections and unsafe key files fail startup.

An error that stops startup or `-check` leaves the encrypted settings out, along with any address
(the origin's resolved address follows from them): `invalid origin range "[private setting]"`.
To see the values, give the same settings as flags on the command line.

The default key location is:

| Platform | Key directory |
| --- | --- |
| Linux | `$XDG_CONFIG_HOME/carnical/keys`, or `$HOME/.config/carnical/keys` |
| Windows | `%APPDATA%\carnical\keys` |

If the account has no configuration directory, enter an explicit key-file path. A blank answer
is refused. The printed check and start commands include `-config-key-file` for that path.

The key file contains exactly 32 binary bytes. Linux keys require owner-only permissions;
setup writes 0600. Windows setup uses a protected ACL with access only for the setup account
and SYSTEM. Windows applies that ACL during exclusive file creation, before another
account can obtain an inherited read handle. Inherited or additional grants are refused
when loading the key. Windows filenames with streams, reserved devices or trailing dots
and spaces are refused. Existing files remain untouched.

Private certificate/key contents remain in their existing credential files. Setup asks for
paths, never raw passwords, tokens or private keys, and does not rewrite those files. Protect
them using the [origin credential requirements](website-onboarding.md#operator-authenticate-the-waf-to-the-origin).

Encryption protects private settings when the site file is copied without its key. It does
not protect them from an administrator or a compromised WAF account that can read the key.
Public settings remain editable operator policy; encryption does not authenticate those
settings. Keep configuration, key files and parent directories under operator control.

## Services, backups and updates

For another account, copy the key through an approved secret-transfer path and grant access
only to that account (plus SYSTEM on Windows). Pass its absolute path with
`-config-key-file`; the key ID in the site file does not need to change.
Install the configuration where the service account can read it, while keeping write access
with the operator. Setup's initial configuration is private to the setup account.
On Linux, install it with the service account as owner and mode 0600. On Windows, replace the
setup account's ACL entry with the service account's entry, retain SYSTEM and disable inheritance.
Validate under the actual service identity before restarting. Containers can mount the key
read-only with owner-only permissions; this is separate from the site-file mount.

Run the wizard again into a new file to change encrypted settings. Review the new settings,
validate with the production service identity, then arrange the replacement and restart.
Ordinary readable settings can still be edited or overridden through CLI flags.

Back up the site file and key separately. Losing the key requires recreating the configuration;
there is no recovery key. A failed configuration write may leave its newly created key behind;
the error identifies that file and no existing configuration is replaced. The wizard does not
store a plaintext copy of private settings or put the key itself in printed commands.

Before DNS cutover, follow [website onboarding](website-onboarding.md) to restrict direct-origin
access, test real hostnames through the WAF and record rollback settings.

Review: [wizard](../cmd/carnical/setup.go), [strict loader](../cmd/carnical/siteconfig.go),
[encryption and files](../cmd/carnical/siteprivate.go),
[Windows ACLs](../cmd/carnical/siteprivate_windows.go).
Crypto reference: [Go authenticated encryption](https://pkg.go.dev/crypto/cipher#NewGCMWithRandomNonce).
