# Availability and portable deployment

Carnical can run as a standalone binary or a Linux container. Run multiple edges behind a load
balancer for rolling changes and node failure tolerance. Every edge must compile and enforce the
same reviewed site policy, authenticate to the origin, and have enough capacity for the traffic
remaining after a node fails.

Choose a [binary](#standalone-binary) or [container](#linux-container) deployment, then review
[health/draining](#runtime-checks-and-draining) and [replica state](#state-and-replica-contracts).
The [validated platform scope](#supported-and-validated-scope) distinguishes live checks from
cross-builds. Source: [lifecycle](../cmd/carnical/lifecycle.go), [container
files](../deploy/container/).

## Runtime checks and draining

Enable a separate private listener:

```sh
carnical -config /etc/carnical/site.json \
  -health-listen 127.0.0.1:8082 -drain-delay 5s -shutdown-timeout 30s
carnical -health-listen 127.0.0.1:8082 -probe live
carnical -health-listen 127.0.0.1:8082 -probe ready
```

The probe command exits zero only for HTTP 200. It needs neither a website configuration nor a
shell, does not load CRS, cannot follow redirects or use environment proxies, and only connects to a
numeric loopback address.

| Endpoint | Meaning |
| --- | --- |
| `/livez` | The private HTTP server can answer. A CrowdSec outage does not fail liveness. |
| `/readyz` | The visitor server has entered its accept loop, the process is not draining, and any required CrowdSec snapshot is fresh. |

For a remote load balancer, use a trusted local agent to publish readiness through its supported
control interface, or check an ordinary protected application route and its expected response/body.
The CLI does not provide a remote load-balancer management connector.

Health is disabled by default. Both IPv4 loopback and `[::1]:port` are accepted. The listener
refuses hostnames, wildcard/public addresses and port zero. Only exact GET/HEAD health targets
without a body are supported; there is no control, configuration or application forwarding endpoint.
Visitor paths such as `/readyz` still pass through the complete WAF to the application.

Keep the health port in the process's private network namespace. Do not publish it, proxy visitor
traffic to it, or add a WAF exclusion for a health URL. The health listener is unauthenticated local
status; it does not replace the authenticated control API. Processes sharing the namespace can read
its status.

With the default CrowdSec fail-closed policy, stale decisions make readiness return 503 and ordinary
unlisted visitors receive 503; unexpired bans keep returning 403. A successful refresh restores
readiness without a restart. Explicit `-crowdsec-fail-open` keeps readiness healthy while permitting
unlisted visitors during staleness; existing bans still apply. Use that option only when the
reviewed outage policy calls for it.

On SIGTERM, SIGHUP or an interrupt, readiness immediately becomes false (there is no configuration to
reload, so a hang-up stops the edge the same way). A second signal during the stop ends the process at
once, without waiting for the budget below. During `-drain-delay` the edge
still accepts and inspects traffic already routed to it, and CrowdSec refresh continues. It then
closes the visitor listener and lets active HTTP requests finish. `-shutdown-timeout` is the
**total** budget including the delay: its default is 30s, configurable from 100ms to 10m. The delay
defaults to zero, can be at most 1m, and must be shorter than the total budget.

A deadline aborts remaining ordinary connections, logs `shutdown incomplete` and exits with failure.
A clean stop logs `shutdown complete`. Set the supervisor's stop timeout longer than this budget and
match it to legitimate uploads and responses; the default can interrupt long requests. Protocol
upgrades are off by default; explicitly allowed upgrades are uninspected and disconnect when the
process exits, without a graceful WebSocket-close guarantee.

Readiness does not contact the origin, measure flood capacity or prove a healthy
application/database. Check origin DNS/TCP/TLS and optional HTTP acceptance with the [onboarding
preflight](website-onboarding.md), then use separate end-to-end synthetic checks for application
availability. Do not turn a shared origin outage or short traffic spike into simultaneous liveness
restarts on all edges.

## State and replica contracts

| Feature | What the deployment must account for |
| --- | --- |
| CRS, strict formats, explicit API contracts, proxy checks | Every replica loads its reviewed rules/files before listening. Pin the same application revision and compare policy hashes/configuration. |
| Origin mTLS | Authorize every edge's exact client identity at the origin; preferably issue separate keys/certificates per replica. Keep alternate origin paths closed. Roll out new approved identities before removing old ones. |
| CrowdSec | Use a **separate bouncer credential for every running replica**. LAPI stream cursors belong to credentials; sharing one can cause replicas to miss updates. Separate local LAPI services or a verified resilient upstream avoid a common dependency outage. |
| Shield flood detection, baseline, bans and connection budgets | State and reserved-client capacity belong to one process. Supply a measured `-ddos-baseline-rate` so a restart during a flood does not learn that flood as normal. Size limits per node, including file descriptors and N-1 capacity. |
| Browser challenges/clearance | Keys and browser-hash seeds are created per process. Answers/cookies do not transfer to another replica or survive restart. Use affinity for challenge-enabled deployments, or disable browser challenges and use the reviewed refusal policy. Never exempt the verification path from the rest of the deployment's security controls. |
| API/login quotas | Budgets are local and reset on restart. Client requests spread across N replicas can consume N budgets. Use shared enforcement for a fleet-wide quota; increasing replicas does not preserve an exact global ceiling. |
| Signed configuration/control/virtual-patch SDKs | These are integration packages, not extra services automatically started by the CLI. Implement durable rollback floors, consistent publication, authenticated management and replay/idempotency coordination before deploying multiple control replicas. The file sequence store's mutex is per instance; it is not a multi-process distributed store. |
| Monitoring | Logs and counters are per process. Attach node/revision labels in the collector, aggregate externally, and alert on stale decisions, failed refreshes, failed startup, shutdown deadlines, certificate expiry, origin errors and policy drift. Default logs omit request bodies and credentials. |

A front proxy must preserve and overwrite the client identity header, and only its actual peer
ranges belong in `-trusted-proxies`. A NAT/load balancer that merges visitors into one address
changes per-client budgets. Preserve source addresses where possible; test IPv4 **and** IPv6 paths
and failover. Do not trust arbitrary forwarded headers to compensate for a deployment that loses
identity.

The CLI forwards to one origin and does not automatically retry failed requests across origins. Put
a separately authenticated, tested origin load balancer behind it when origin redundancy is
required. Blindly replaying a POST during failover can duplicate a transaction.

## Standalone binary

From `carnical/`, build on the target platform:

```sh
CGO_ENABLED=0 go build -trimpath -o carnical ./cmd/carnical
./carnical -config /etc/carnical/site.json -check
./carnical -config /etc/carnical/site.json -check -check-origin -check-origin-http
./carnical -config /etc/carnical/site.json -health-listen 127.0.0.1:8082
```

On Windows PowerShell:

```powershell
$env:CGO_ENABLED = "0"
go build -trimpath -o carnical.exe ./cmd/carnical
.\carnical.exe -config C:\Carnical\site.json -check
.\carnical.exe -config C:\Carnical\site.json -health-listen 127.0.0.1:8082
```

Use absolute file paths in production configuration. Run as a dedicated service account; protect
keys, configuration and parent directories with filesystem permissions or Windows ACLs.
Certificate/configuration changes require a checked restart. A supervisor must deliver a supported
stop signal for graceful draining; Windows `TerminateProcess` and forced container termination abort
immediately. The binary is a console program, not a native Windows Service Control Manager service;
service-manager integration needs a correctly tested wrapper.

For the hardened [systemd deployment](../deploy/README.md), the unit reserves 40s for the default
30s shutdown budget. If health is enabled, its `SocketBindDeny=any` requires a narrow drop-in
permitting that additional port:

```ini
[Service]
SocketBindAllow=ipv4:tcp:8082
TimeoutStopSec=40s
```

Keep the CLI health address loopback. Apply the drop-in and corresponding `CARNICAL_ARGS`, run the
startup check, and validate forwarding and confinement on that machine. Larger shutdown budgets
require a matching supervisor timeout.

## Linux container

The [Dockerfile](../deploy/container/Dockerfile) builds the local Carnical and Coraza source with
CGO disabled. Its official Go builder is pinned by digest; the runtime contains only the binary,
system CA bundle and upload directory. It runs as UID/GID 65532, with no shell. The CA bundle
supports verified public HTTPS origins; private issuers still need `-origin-ca-file`.

From the repository root:

```sh
docker build -f carnical/deploy/container/Dockerfile -t carnical:local .
docker buildx build --platform linux/amd64,linux/arm64 \
  -f carnical/deploy/container/Dockerfile -t YOUR_REGISTRY/carnical:YOUR_REVISION --push .
```

The build context is scoped to required engine/application packages and excludes deployment files,
conventional key files, test fixtures and local worktrees. Keep other credentials outside source
packages. Review the image and pin its resulting digest before production deployment; builder and CA
updates need a reviewed image rebuild.

The [Compose example](../deploy/container/compose.yaml) publishes visitor port 443 to 8443 and
leaves health on loopback. Beside it, install a reviewed `site.json`, `tls/` visitor certificates,
and `origin/` client credentials using the [authenticated site example](examples/site-edge.json).
Its absolute paths already match those mounts. Make directories traversable and private keys
readable by GID 65532 (for example root-owned 0750 directories and 0640 keys). Never make private
keys world-readable. Configure the private issuer bundle explicitly if needed.

```sh
docker compose -f carnical/deploy/container/compose.yaml config --quiet
docker compose -f carnical/deploy/container/compose.yaml build
docker compose -f carnical/deploy/container/compose.yaml run --rm edge \
  -config /etc/carnical/site.json -listen :8443 -upload-dir /var/lib/carnical/uploads -check
docker compose -f carnical/deploy/container/compose.yaml up -d
```

The image's default command sets `-listen :8443`, private health port 8082, a private upload
directory and a 5s/30s drain/stop budget, overriding those site-file flags. When replacing the
command, supply the same protections and update the Docker health check if its address changes. The
example uses a read-only root, drops all capabilities, forbids gaining privileges and provides a
bounded noexec/nosuid/nodev upload tmpfs. Memory, CPU, process and file-descriptor limits are
starting budgets; tune them against the actual workload.

Containerization does not provide the host's nftables policy or guarantee Landlock availability.
Optional `-confine` needs the supported kernel, runtime syscall policy and allowed origin/LAPI/DNS
ports. Validate it live; do not silently enable best-effort confinement to hide incompatibility. On
Docker Desktop or behind a bridge/proxy, verify the actual peer/client addresses before enabling
per-client limits or trusting forwarded headers.

## Kubernetes integration recipe

<details>
<summary>Kubernetes-specific probes, permissions and mounts</summary>

Use a reviewed image digest, at least two replicas on separate nodes, rolling updates with
`maxUnavailable: 0`, a disruption budget, resource requests/limits and spare capacity. Configure
`terminationGracePeriodSeconds` above the Carnical shutdown budget. Pod deletion withdraws the
Kubernetes endpoint; the application drain delay allows for routing propagation.

Use executable probes against the private loopback endpoint; a kubelet HTTP probe normally targets
the Pod IP, where this listener is deliberately absent:

```yaml
startupProbe:
  exec:
    command: ["/carnical", "-health-listen", "127.0.0.1:8082", "-probe", "live"]
  periodSeconds: 5
  failureThreshold: 30
livenessProbe:
  exec:
    command: ["/carnical", "-health-listen", "127.0.0.1:8082", "-probe", "live"]
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
readinessProbe:
  exec:
    command: ["/carnical", "-health-listen", "127.0.0.1:8082", "-probe", "ready"]
  periodSeconds: 5
  timeoutSeconds: 5
  failureThreshold: 1
```

Do not publish a health Service. Set `runAsNonRoot`, UID/GID 65532, `allowPrivilegeEscalation:
false`, `readOnlyRootFilesystem: true`, dropped capabilities and `seccompProfile: RuntimeDefault`.
Give uploads a private, bounded writable volume. Use `fsGroup: 65532` and private key mode 0640 when
service-group access is needed.

ConfigMap/Secret directory projections expose **symlinks**. The site and origin credential readers
intentionally reject final symlinks. Mount each such file using a reviewed **file `subPath` mount**,
or materialize regular private files with a trusted provisioning step. SubPath files do not receive
projected updates: roll out a new checked revision after policy or certificate rotation. Do not
weaken the file guards to support hot projection updates.

Apply NetworkPolicies for origin/LAPI/resolver egress and the actual ingress peers, preserve source
identity where the load-balancer implementation supports it, and validate both address families. The
recipe is guidance, not a cluster-specific manifest or a tested Kubernetes installation.

</details>

## Supported and validated scope

| Deployment | Scope |
| --- | --- |
| Linux amd64 binary | Native CLI, live TCP, replica/outage/drain tests and kernel protection checks. |
| Windows amd64 binary | Native CLI, forwarding, health/probe and input-validation tests; Linux-specific switches remain unsupported. |
| Linux amd64 container | Actual Docker build/runtime tests, non-root/read-only/capability checks, HTTPS trust and the live replica/outage/drain suite. |
| Linux arm64 | Cross-compiled binary and container image; the availability suite is not an arm64 hardware run. |
| macOS amd64/arm64 | Cross-compilation checks; native runtime/service-manager behavior still requires platform validation. |
| Kubernetes, other distributions or container runtimes | Integration guidance; validate the exact cluster/kernel/runtime, storage permissions, source identity and rollback before cutover. |

CI runs `.github/security/test_deployment.py` on the binary and container with fresh temporary
credentials. It exercises varied good/bad requests, local probe isolation, stale-cache
withdrawal/recovery, a surviving replica, continued ban updates during drain, admitted-request
completion and deadline aborts. This is a bounded correctness test, not a massive-site capacity or
production SLA test.

References: [Go HTTP shutdown](https://pkg.go.dev/net/http#Server.Shutdown), [Kubernetes
probes](https://kubernetes.io/docs/concepts/workloads/pods/probes/), [Pod
termination](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#pod-termination),
[projected volumes and subPath updates](https://kubernetes.io/docs/concepts/storage/volumes/),
[Docker multi-platform builds](https://docs.docker.com/build/building/multi-platform/).
