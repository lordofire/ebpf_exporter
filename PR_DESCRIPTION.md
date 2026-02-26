# Add Kubernetes pod/namespace/container labels for pod-related metrics

## Summary

This PR adds support for resolving Kubernetes pod metadata (pod name, namespace, container name, pod UID) when decoding eBPF metrics, and wires it to the Kubernetes API with a node-scoped, cache-based backend. Pod-related metrics (e.g. OOM kill) can then be labeled with `kube_pod`, `kube_namespace`, `kube_container`, and `kube_pod_uid` when running in a cluster.

## What’s included

### 1. Kubecontext and decoders (commit 8c1277c)

- **Kubecontext resolver** (`decoder/kubecontext.go`): Resolves cgroup ID or PID to `PodMeta` (pod, namespace, container, pod UID) via cgroup path parsing and a pluggable backend.
- **Decoders**: New label decoders for use in configs:
  - From cgroup ID: `kube_pod_name_from_cgroupid`, `kube_namespace_from_cgroupid`, `kube_container_name_from_cgroupid`, `kube_pod_uid_from_cgroupid`
  - From PID: `kube_pod_name_from_pid`, `kube_namespace_from_pid`, `kube_container_name_from_pid`, `kube_pod_uid_from_pid`
- **Example**: `examples/oomkill.yaml` updated to use the new kube decoders so OOM events are labeled with pod/namespace (and container when available).
- **Exporter**: Integrates a KubeBackend (K8s API when enabled and in-cluster, otherwise Noop) and a KubeResolver with path caching.

### 2. K8s backend optimization and cleanup (commit eb54854)

- **Node-scoped list**: The K8s backend (`decoder/kubecontext_utils.go`) lists only pods on the current node via `fieldSelector=spec.nodeName=NODE_NAME`. No cluster-wide pagination; single request per cache refresh.
- **NODE_NAME**: Node name is read only from the `NODE_NAME` environment variable (e.g. set via downward API in a DaemonSet). If unset, the backend returns `ErrNodeNameRequired` so metric decode fails instead of silently returning “unknown”.
- **Cache**: One unbounded cache (pod UID → pod + container list). On cache miss, the cache is replaced under a mutex (thread-safe); no negative caching. KubeResolver uses a plain `map[string]PodMeta` for path caching instead of an LRU.
- **Retry**: The pods List API call is retried (e.g. 3 attempts with backoff) for robustness against transient failures.
- **Pod-only queries**: When the upstream query is pod-level (e.g. cgroup path without container ID), container metadata is left empty instead of guessing.
- **Code trim**: Reduced debug logging to critical-only (e.g. NODE_NAME unset, List API error); removed negative cache on unparseable path; added `kubeDecodeFromMeta` helper so all eight kube decoders share one implementation.
- **Enable flag**: `--kubecontext.enable` (default `true`) controls whether the Kubernetes API backend is used. When disabled, the Noop backend is used and pod/namespace/container labels stay “unknown”. The previous cache-size parameter is removed; caches are unbounded.

## Deployment

- **RBAC**: ServiceAccount must have `get`, `list`, `watch` on `pods` (e.g. ClusterRole + RoleBinding).
- **NODE_NAME**: DaemonSet (or deployment) should set `NODE_NAME` via the downward API so the node-scoped list works:

  ```yaml
  env:
  - name: NODE_NAME
    valueFrom:
      fieldRef:
        fieldPath: spec.nodeName
  ```

- **Disable**: Run with `--kubecontext.enable=false` to turn off K8s resolution and use “unknown” labels.

## Testing

- Decoder and kubecontext tests updated/added; OOM example can be exercised in-cluster with the above env and RBAC.
- `go build ./decoder/...` succeeds (full `go build ./...` may still depend on libbpf/CGO in some environments).

## Commits

- `8c1277c` — Add the k8s labels support for pod related metrics  
- `eb54854` — K8s backend: node-scoped list, NODE_NAME, retry, code trim, enable flag
