---
name: Pod labels for metrics
overview: Add pod-related labels (kube_pod, kube_namespace, kube_container) as normal labels in the same list as cgroup, using a reuse flag so multiple labels read the same 8-byte cgroup ID. New decoders use a shared LRU cache (cgroup path or ID → PodMeta) so pod lookup is done once per key; cgroup module is reused for ID→path. No separate kubecontext block; cgroup ID only.
todos: []
isProject: false
---

# Pod-related labels for Prometheus metrics

## Goal

Expose pod-related labels (e.g. `kube_pod`, `kube_namespace`, `kube_container`) on existing metrics so application users can target alerts and dashboards by pod/namespace. The solution must be **modular**, **aligned with current architecture**, and **low-latency**. Labels are defined in a **single** `labels` list; no parallel config block.

## Current architecture (relevant parts)

- **Metrics flow**: BPF map key (bytes) → **decoder pipeline** (per-label, sequential by offset) → `[]string` label values → **aggregate** → Prometheus metric.
- **Label**: Each label has `name`, `size`, `padding`, `decoders`. The key is split by offset; total key size = sum of (size + padding) for all labels (today). Each label reads `in[off : off+size]`; then offset advances by `size + padding`.
- **Cgroup decoder**: cgroup ID (string) → cgroup path via cgroup monitor. Path is then parsed for pod UID / container ID; backend resolves to pod name, namespace, container name.

## Why cgroup ID only (no PID)

- **PID recycle** and **OOM teardown**: Cgroup ID is stable for the cgroup’s lifetime; the cgroup outlives the process. Single source of truth.

---

## Rationale for reuse + shared cache

- **reuse**: Avoids key bloat (8 bytes instead of 32) and keeps “one logical input (cgroup ID) feeds multiple labels” explicit in the config. The decoder stays “one label = one segment” except that segments can overlap when `reuse: true`, so the same bytes are decoded multiple times with different decoder chains. No new concept of “derived labels with no key bytes”; the key still fully determines the segments, and key size is well-defined (max over segments of segment end).
- **Shared cache**: The three kube decoders run in sequence for the same key (same 8 bytes). Without a cache, each would do cgroup ID → path (cgroup module) + parse + backend (three full lookups per key). With one LRU cache keyed by cgroup path (or ID), the first decoder does the full lookup and stores PodMeta; the next two decoders find the same path/ID in the cache and return .Namespace and .Container. So we do **one** path resolution and **one** backend call per distinct cgroup ID per scrape (or until eviction). Code duplication is avoided by reusing the cgroup module for ID→path and a single resolver (parse + backend) with cache for path→PodMeta.

---

## Design: reuse flag + kube decoders in labels

1. `**reuse` on Label**: When `reuse: true`, this label **does not advance** the read offset for the next label. So multiple labels can read the **same** segment of the key. Key size is computed so that the key only needs to cover the union of segments (no double-counting reused segments).
2. **Same list, same key**: Pod/namespace/container are **normal** labels in the same `labels` list as `cgroup`. All four (cgroup, kube_pod, kube_namespace, kube_container) read the same 8-byte cgroup ID when `reuse: true` is set on the last three. No separate `kubecontext` block; dependency is explicit (same bytes → same logical input).
3. **Shared cache**: A single LRU cache (cgroup path or cgroup ID → PodMeta) is shared by the three kube decoders. The **first** of the three that runs (e.g. kube_pod) performs the full lookup (cgroup ID → path via cgroup module, parse path, backend); the result is cached. The other two (kube_namespace, kube_container) hit the cache and return their field. So pod lookup is done **once** per distinct cgroup ID per decode; no code duplication of the heavy path.
4. **Cgroup module reuse**: ID → path is done via the existing **cgroup** monitor (same as the cgroup decoder). The kube decoders receive cgroup ID (after `uint` decoder); they call cgroup monitor to get path, then use the kubecontext resolver (parse + backend, with cache). So the cgroup package is reused, not duplicated.

---

## Config shape: labels with reuse

```yaml
metrics:
  counters:
    - name: my_metric_total
      help: "..."
      labels:
        - name: cgroup
          size: 8
          reuse: true
          decoders:
            - name: uint
            - name: cgroup
        - name: container
          size: 8
          reuse: true
          decoders:
            - name: uint
            - name: kube_container_name
        - name: namespace
          size: 8
          reuse: true
          decoders:
            - name: uint
            - name: kube_namespace
        - name: pod
          size: 8
          reuse: true
          decoders:
            - name: uint
            - name: kube_pod_name
        - name: uid
          size: 8
          reuse: true
          decoders:
            - name: uint
            - name: kube_pod_uid
```

- `**reuse**` (optional, bool): If `true`, this label reads from the **same** offset as the previous label (offset is not advanced after this label). So all four labels above read bytes 0–7 (one 8-byte cgroup ID). Key size for the metric is **8**, not 32.
- **Offset and key size**: For each label index `i`, compute `offset[i]`: `offset[0] = 0`; for `i > 0`, `offset[i] = offset[i-1]` if `label[i].Reuse` else `offset[i-1] + size[i-1] + padding[i-1]`. **Key size** = `max over i of (offset[i] + size[i])` (padding does not extend the key). Validation: `len(key) >= key size`.
- **Decoder names**: Use `**uint**` (not `unit`) for the first decoder in each kube label so the 8-byte value is decoded to a decimal string (cgroup ID) before the kube decoder.

---

## Decoder pipeline with reuse

- In [decoder/decoder.go](decoder/decoder.go) `decodeLabels`: replace the single running offset and totalSize sum with **per-label offset** from the reuse rule. For each label, read `in[offset[i] : offset[i]+size[i]]`, run the decoder chain, then set `values[i]`. No change to the decoder interface; only the way offsets and total key size are computed changes when `reuse` is present.
- **kube_pod_name, kube_namespace, kube_container_name, kube_pod_uid decoders**: Each receives the same 8-byte segment; after `uint` it gets cgroup ID (string). Decoder does: (1) resolve cgroup ID → path (reuse **cgroup.Monitor.Resolve**), (2) call shared **kubecontext resolver** (path → parse → backend; cache by path or ID). Resolver returns **PodMeta** (Pod, Namespace, Container). kube_pod returns `.Pod`, kube_namespace returns `.Namespace`, kube_container returns `.Container`. First call populates cache; subsequent calls for the same key hit cache.

---

## Shared cache (LRU) and resolver

- **Cache**: Fixed-size LRU keyed by **cgroup path** (or cgroup ID). Key = path is preferred so one resolution (path → PodMeta) is cached. When a decoder is called with cgroup ID, it gets path via cgroup monitor, then looks up path in cache; on miss, parse path + backend, then cache by path.
- **Resolver**: Lives in `kubecontext` package. `Resolve(cgroupID string) (PodMeta, bool)`: ID → path (cgroup monitor), then parse path → container ID + pod UID, then backend `Resolve(containerID, podUID) → PodMeta`, cache by path, return PodMeta. Decoder set holds a reference to this resolver (injected like cgroup monitor) so kube_pod, kube_namespace, kube_container decoders can call it. Pod lookup is performed once per distinct cgroup ID; the three decoders for the same key share the cache.

---

## Parsing cgroup path (unchanged)

- **Systemd** / **cgroupfs** patterns; single `ParseCgroupPath(path string) (podUID, containerID string, ok bool)` in `kubecontext/parse.go`. Backend interface `Resolve(containerID, podUID string) (PodMeta, bool)`; implementations CRI, K8s API, Docker.

---

## Exporter integration

- **Describe**: Label names come **only** from the `labels` list (no extra names). With reuse, the list has four entries → four label names: cgroup, kube_pod, kube_namespace, kube_container. No special case.
- **Collect**: Unchanged. `mapValues` / decode runs as today; the decoder pipeline (with new offset logic and the three kube decoders) produces four values per key. Aggregate and emit. Perf event array: CounterVec is created with the same four label names from the config; after decode we get four values and call `WithLabelValues(...).Inc()`.
- No post-decode enrichment step; all labels are produced by the decoder pipeline.

---

## Recommended eBPF strategy (OOM and similar)

- **Hook**: e.g. `oom:mark_victim`; capture **cgroup ID** in BPF; key remains 8 bytes.
- **Exporter**: Key (8 bytes) → decode with four labels (all reading the same 8 bytes via reuse) → cgroup path + pod + namespace + container. No PID.

---

## File-level impact


| Area                    | Files / changes                                                                                                                                                                                                                                                                                                      |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Config**              | [config/config.go](config/config.go): Add `Reuse bool` to `Label`. No `Kubecontext` block. Validation: key size from reuse rule.                                                                                                                                                                                     |
| **Decoder**             | [decoder/decoder.go](decoder/decoder.go): Compute per-label offset when `Reuse` is used; key size = max(offset[i]+size[i]). New decoders: `kube_pod_name`, `kube_namespace`, `kube_container_name`, `kube_pod_uid` in [decoder/kube_pod.go](decoder/kube_pod.go) etc., each taking shared resolver + cgroup monitor. |
| **Kubecontext package** | `kubecontext/resolver.go` (path or ID → PodMeta, LRU cache), `kubecontext/parse.go`, `kubecontext/backend.go`, `kubecontext/cri.go`, etc. Resolver uses cgroup monitor for ID→path.                                                                                                                                  |
| **Exporter**            | No structural change to Describe/Collect; label names and values come from config and decoder only.                                                                                                                                                                                                                  |
| **Main**                | [cmd/ebpf_exporter/main.go](cmd/ebpf_exporter/main.go): Build kubecontext resolver (LRU size, backend), pass to decoder.NewSet(..., monitor, resolver).                                                                                                                                                              |
| **Docs**                | [ARCHITECTURE.md](ARCHITECTURE.md): Document `reuse`, key size rule, and kube decoders + shared cache.                                                                                                                                                                                                               |


---

## Summary

- **Single labels list**: cgroup and kube_pod / kube_namespace / kube_container are all in `labels`; no parallel `kubecontext` block.
- `**reuse: true**`: Label does not advance the read offset; multiple labels can read the same key segment. Key size = max(offset[i]+size[i]) so the key stays 8 bytes for four labels.
- **One lookup per key**: Shared LRU cache (path → PodMeta); first kube decoder does ID→path (cgroup module) + parse + backend and caches; the other two decoders hit the cache.
- **Cgroup module**: Reused for ID→path inside the kube decoders (or inside the resolver); no duplication.
- **Decoder typo**: Use `**uint**` (not `unit`) in YAML for the first decoder in each kube label.

