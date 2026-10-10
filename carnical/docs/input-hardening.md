# Supplemental rules and API contracts

Use [CLI API contracts](#executable-api-contracts) for schema enforcement and the [local rule
table](#local-rules) for supplemental detection. Source: [API guard](../apiguard/), [local CRS
rules](../crs/local/), [CLI](../cmd/carnical/main.go).

## Local rules

Carnical supplements the verified, unmodified CRS release with local rules under `crs/local/`. These
inspect ARGS, XML text/attributes and cookies (5006011, the request path), adding five inbound PL1
anomaly points per finding before the CRS blocking evaluation. They load after CRS score initialization and before its attack
rules, preserving scores in multiphase builds. They share `-mode` and thresholds;
`-local-rules=false` omits them. The library setting is `crs.Settings.DisableLocalRules`. URL, HTML
and JavaScript decoding is for detection only; values are not rewritten.

| Rule | Family |
| --- | --- |
| 5006001, 5006002, 5006009 | XPath predicates, unions and comment obfuscation |
| 5006003, 5006004, 5006010 | Shell chaining/substitution, interpreters and obfuscated spelling |
| 5006005 | Template arithmetic, configuration and runtime expressions |
| 5006006 | Parent traversal, including nested percent-encoded markers |
| 5006007 | Base64/hex Java serialization stream markers |
| 5006008 | Non-HTTP fetch protocols and ambiguous numeric/userinfo authorities |
| 5006011 | Paths only an attacker asks for: PHPUnit's `eval-stdin.php`, PHP in WordPress's uploads, cache or upgrade folders (also behind a second extension or path info), the File Manager connectors and PHP in its files folder, Slider Revolution's update folder, and well-known web shells by name. The path is decoded, normalized and lower-cased for matching. It runs for every site, since a scanner asks whether or not WordPress is there; the site's WordPress protections (`wordpress.enabled`) refuse scripts in more of its writable folders and limit logins and xmlrpc.php |

Default match logs contain fixed family labels, rule IDs, severity and transaction IDs, omitting
request content. `-log-details` enables sensitive details. Format rules 5002608/5002809 additionally
refuse mixed scalar/container names, root aliases that PHP mangles to the same name, and malformed
brackets. Both ordering directions are checked; single-byte form names keep their bytes. These rules
have independent block/monitor/off actions and appear in the existing bounded per-rule format
totals.

## Origin error signals

Operational upstream failures also emit rule ID 5000050 with a fixed error class and, when present,
a numeric OS error code. They are availability signals, not attack detections. Default records omit
addresses and error text; `-log-details` additionally exposes the error and request context and must
be treated as sensitive logging.

Rule 5000051 records local socket-bind retries. Only an address-in-use error during TCP connection
creation is retried, with at most three total attempts and the origin policy checked each time.
Cancellation and other failures remain terminal; established-connection errors do not replay
requests.

This preserves separate connections for body-bearing requests and the existing desynchronization
defense. Windows 10048 was reproduced under this load test; [Microsoft documents its
address-collision
meaning](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2).

## Repeated parameters

Plain repeated parameters remain monitored by default because legitimate multi-valued APIs use them.
Enable `form-duplicate-param`/`query-duplicate-param` blocking for a scalar-only application, or use
an explicit API contract so arrays remain usable. Repeated explicit `tags[]` and distinct nested
fields are structurally valid; the application must decide whether it accepts them. Structural
validity does not establish safe concatenation in an application sink.

## Executable API contracts

Supply a local OpenAPI JSON/YAML file using `-api-spec`. It is read once before listening, as a
regular file of at most 5 MiB. No URL is fetched. The guard runs after format inspection, including
decompression, and before CRS.

```powershell
go run ./cmd/carnical -upstream http://127.0.0.1:8081 -origin-allow 127.0.0.1/32 -mode block -formats-mode block -api-spec ./site-api.json
```

`-api-spec-mode block` is the default and requires `-formats-mode block`. It independently checks
JSON validity and duplicate keys, even if the corresponding format rule is disabled. It enforces
supported scalar/array parameters, required values, exact query names, JSON body schemas,
unknown/read-only properties and declared content types.

Numeric checks use exact decimal values, including enums, integer formats, bounds, `multipleOf` and
array uniqueness. A numeric bound or multiple that cannot be preserved by the SDK's float64
representation is an import error, so the CLI refuses startup with that contract.

See [numeric support limits](apiguard.md#5-level-1-in-detail). Bracket aliases of scalar/ordinary
array parameters are unknown names, not an exemption. Explicit OpenAPI `style: form, explode: true`
arrays can repeat plain names while scalar repetition is refused.

Enforcement refuses startup for empty models, importer warnings, object/deepObject parameters,
unspecified allowed body media, multiple body media types, non-JSON bodies and wildcard body media.
Some advanced schemas are not implemented by the existing importer; use monitor mode to see
warnings, then correct the contract. Monitor mode records findings without enforcing them; it does
not make unsupported constraints valid. The specification covers described routes and the guard's
API classification; it is not a deny-list for every non-API path.

```powershell
go run ./cmd/carnical -upstream http://127.0.0.1:8081 -origin-allow 127.0.0.1/32 -api-spec ./site-api.json -api-spec-mode monitor
```

[The example](examples/api-contract.json) declares a bounded integer lookup, an explicit repeated
array and a resource URL constrained to one HTTPS host and a narrow public-image path. It is a
generic example contract. Replace its routes, properties and destinations with the protected
application's actual definitions.

## Application-dependent admissions

Ordinary remote URLs need allowed destinations or resource identifiers. Request filtering cannot
guarantee DNS results, redirect handling or application authorization. Use a guarded outbound client
and network egress policy too. [OWASP SSRF
prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).

Keep XPath expressions fixed and bind values; typed constraints complement binding. [OWASP XPath
prevention](https://cheatsheetseries.owasp.org/cheatsheets/XPath_Injection_Prevention_Cheat_Sheet.html).
XPath 2+ comments can nest and occupy whitespace positions, motivating independent comment
detection. [W3C XPath comments](https://www.w3.org/TR/xpath-31/#id-comments).

Avoid commands constructed from visitor strings; use an application API or fixed argument contracts.
[OWASP command injection
defense](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html).
Parameter expansion and quote removal can change spelling after filtering. [Bash expansion
order](https://www.gnu.org/s/bash/manual/html_node/Shell-Expansions.html).

PHP transforms dots and spaces in top-level parameter names into underscores, motivating root-alias
checks. [PHP parse_str](https://www.php.net/parse-str). Template arithmetic can be parenthesized.
[Thymeleaf
arithmetic](https://www.thymeleaf.org/doc/tutorials/3.1/usingthymeleaf.html#arithmetic-operations).

Diagnostic paths and scanner names are indicators, not proof of an exploitable service.
Restrict/authenticate real diagnostic/admin services and patch plugins. Enable `-wordpress` on a
WordPress deployment for the existing upload/cache script, XML-RPC and login protections.
Application/plugin-specific virtual patches still require integration of the existing virtual-patch
package; this change does not install a universal plugin deny-list.
