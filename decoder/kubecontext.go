package decoder

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/cloudflare/ebpf_exporter/v2/cgroup"
	"github.com/cloudflare/ebpf_exporter/v2/config"
)

// PodMeta is the normalized Kubernetes pod identity returned by backends.
type PodMeta struct {
	Pod       string
	Namespace string
	Container string
	PodUID    string
}

// KubeBackend resolves container ID and pod UID to Kubernetes pod metadata.
// Implementations may use CRI, K8s API, or Docker.
// When err != nil the caller should propagate it so the metric decode fails (e.g. missing NODE_NAME).
type KubeBackend interface {
	Resolve(containerID, podUID string) (PodMeta, bool, error)
}

// NoopKubeBackend returns unknown for all lookups. Used when no runtime backend is configured.
type NoopKubeBackend struct{}

// Resolve implements KubeBackend.
func (NoopKubeBackend) Resolve(_, _ string) (PodMeta, bool, error) {
	return PodMeta{
		Pod:       "unknown",
		Namespace: "unknown",
		Container: "unknown",
		PodUID:    "unknown",
	}, false, nil
}

// ParseCgroupPath extracts pod UID and container ID from a cgroup path.
// Supports systemd (slice/scope) and cgroupfs layouts used by Kubernetes.
// Returns ok false for unknown path formats.
func ParseCgroupPath(path string) (podUID, containerID string, ok bool) {
	path = strings.TrimPrefix(path, "/")
	if idx := strings.Index(path, ":"); idx >= 0 && len(path) > idx+1 && path[idx+1] == '/' {
		path = path[idx+2:]
	}
	path = strings.TrimPrefix(path, "sys/fs/cgroup/")
	path = strings.TrimPrefix(path, "sys/fs/cgroup")
	path = strings.Trim(path, "/")
	if path == "" {
		return "", "", false
	}

	segments := strings.Split(path, "/")

	for i, seg := range segments {
		if strings.HasSuffix(seg, ".slice") {
			re := regexp.MustCompile(`^kubepods(?:-[a-z]+)*-pod(.+)\.slice$`)
			if m := re.FindStringSubmatch(seg); len(m) == 2 {
				podUID = strings.ReplaceAll(m[1], "_", "-")
				if i+1 < len(segments) {
					next := segments[i+1]
					if strings.HasSuffix(next, ".scope") {
						scopeRe := regexp.MustCompile(`^(?:crio|cri-containerd|docker)-(.+)\.scope$`)
						if cm := scopeRe.FindStringSubmatch(next); len(cm) == 2 {
							containerID = cm[1]
							return podUID, containerID, true
						}
					}
				}
				return podUID, "", true
			}
		}
	}

	for i, seg := range segments {
		if seg == "kubepods" && i+1 < len(segments) {
			rest := segments[i+1:]
			var podDir, containerDir string
			if len(rest) >= 2 && (rest[0] == "besteffort" || rest[0] == "burstable" || rest[0] == "guaranteed") {
				if len(rest) >= 3 {
					podDir = rest[1]
					containerDir = rest[2]
				}
			} else if len(rest) >= 2 {
				podDir = rest[0]
				if len(rest) >= 3 {
					containerDir = rest[1]
				}
			}
			if podDir != "" {
				podUID = strings.TrimPrefix(podDir, "pod")
				podUID = filepath.Clean(podUID)
				containerID = containerDir
				return podUID, containerID, true
			}
		}
	}

	return "", "", false
}

// CgroupPathFromPID returns the cgroup path for the given process ID by reading
// <procfsRoot>/<pid>/cgroup. procfsRoot must be non-empty (caller supplies default if needed).
// Prefers the unified cgroup v2 line (0::/path) if present, otherwise uses the first line.
// Returns empty string if the process does not exist or the file cannot be read (e.g. PID reuse, process gone).
func CgroupPathFromPID(procfsRoot string, pidStr string) string {
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return ""
	}
	cgroupPath := filepath.Join(procfsRoot, strconv.Itoa(pid), "cgroup")
	f, err := os.Open(cgroupPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	var unified, first string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := strings.TrimPrefix(parts[2], "/")
		if first == "" {
			first = path
		}
		// cgroup v2: hierarchy 0, empty controller list
		if parts[0] == "0" && parts[1] == "" {
			unified = path
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return first
	}
	if unified != "" {
		return unified
	}
	return first
}

// KubeResolver resolves cgroup ID or PID to PodMeta. Path resolution is by
// cgroup monitor (ID→path) or procfs (PID→path); then a shared path→PodMeta
// step (parse, backend, cache by path).
type KubeResolver struct {
	monitor    *cgroup.Monitor
	backend    KubeBackend
	procfsRoot string // root of procfs for PID→cgroup (e.g. "/proc" or "/host/proc")
	cache      map[string]PodMeta
	mu         sync.Mutex
}

// NewKubeResolver creates a resolver with the given cgroup monitor, backend, and procfs root.
// procfsRoot is the root of the proc filesystem used to read <procfs>/<pid>/cgroup; must be non-empty (caller sets default at parse time).
func NewKubeResolver(monitor *cgroup.Monitor, backend KubeBackend, procfsRoot string) (*KubeResolver, error) {
	if procfsRoot == "" {
		return nil, errors.New("kubecontext procfs root must be non-empty")
	}
	r := &KubeResolver{
		monitor:    monitor,
		backend:    backend,
		procfsRoot: procfsRoot,
	}
	r.cache = make(map[string]PodMeta)
	return r, nil
}

// resolvePath is the shared path→PodMeta logic: cache lookup, parse path,
// backend resolve, cache by path. Used by both ResolveByCgroupID and ResolveByPID.
func (r *KubeResolver) resolvePath(path string) (PodMeta, bool, error) {
	if path == "" {
		return PodMeta{}, false, nil
	}
	if r.cache != nil {
		r.mu.Lock()
		if meta, ok := r.cache[path]; ok {
			r.mu.Unlock()
			return meta, true, nil
		}
		r.mu.Unlock()
	}

	podUID, containerID, ok := ParseCgroupPath(path)
	if !ok {
		return PodMeta{Pod: "unknown", Namespace: "unknown", Container: "unknown", PodUID: "unknown"}, true, nil
	}

	meta, found, err := r.backend.Resolve(containerID, podUID)
	if err != nil {
		return PodMeta{}, false, err
	}
	if !found {
		meta = PodMeta{Pod: "unknown", Namespace: "unknown", Container: "unknown", PodUID: podUID}
	} else if meta.PodUID == "" {
		meta.PodUID = podUID
	}

	if r.cache != nil {
		r.mu.Lock()
		r.cache[path] = meta
		r.mu.Unlock()
	}
	return meta, true, nil
}

// ResolveByCgroupID resolves a cgroup ID (decimal string) to PodMeta via
// cgroup monitor (ID→path) then resolvePath.
func (r *KubeResolver) ResolveByCgroupID(cgroupIDStr string) (PodMeta, bool, error) {
	cgroupID, err := strconv.Atoi(cgroupIDStr)
	if err != nil {
		return PodMeta{}, false, nil
	}
	path := r.monitor.Resolve(cgroupID)
	if path == "" || strings.HasPrefix(path, "unknown_cgroup_id:") {
		return PodMeta{}, false, nil
	}
	return r.resolvePath(path)
}

// ResolveByPID resolves a PID (decimal string) to PodMeta via r.procfsRoot (PID→path)
// then resolvePath. Process may be gone or PID reused; returns (PodMeta{}, false, nil) on failure.
func (r *KubeResolver) ResolveByPID(pidStr string) (PodMeta, bool, error) {
	path := CgroupPathFromPID(r.procfsRoot, pidStr)
	if path == "" {
		return PodMeta{}, false, nil
	}
	return r.resolvePath(path)
}

// kubeDecodeFromMeta maps (meta, ok, err) from a resolver to a label value or error.
func kubeDecodeFromMeta(_ []byte, meta PodMeta, ok bool, err error, field string) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	if !ok {
		return []byte("unknown"), nil
	}
	switch field {
	case "Pod":
		return []byte(meta.Pod), nil
	case "Namespace":
		return []byte(meta.Namespace), nil
	case "Container":
		return []byte(meta.Container), nil
	case "PodUID":
		return []byte(meta.PodUID), nil
	default:
		return []byte("unknown"), nil
	}
}

// --- Decoders: from_cgroupid (input = cgroup ID string) ---

// KubePodNameFromCgroupID resolves cgroup ID to pod name.
type KubePodNameFromCgroupID struct {
	Resolver *KubeResolver
}

func (k *KubePodNameFromCgroupID) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok, err := k.Resolver.ResolveByCgroupID(string(in))
	return kubeDecodeFromMeta(in, meta, ok, err, "Pod")
}

// KubeNamespaceFromCgroupID resolves cgroup ID to namespace.
type KubeNamespaceFromCgroupID struct {
	Resolver *KubeResolver
}

func (k *KubeNamespaceFromCgroupID) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok, err := k.Resolver.ResolveByCgroupID(string(in))
	return kubeDecodeFromMeta(in, meta, ok, err, "Namespace")
}

// KubeContainerNameFromCgroupID resolves cgroup ID to container name.
type KubeContainerNameFromCgroupID struct {
	Resolver *KubeResolver
}

func (k *KubeContainerNameFromCgroupID) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok, err := k.Resolver.ResolveByCgroupID(string(in))
	return kubeDecodeFromMeta(in, meta, ok, err, "Container")
}

// KubePodUIDFromCgroupID resolves cgroup ID to pod UID.
type KubePodUIDFromCgroupID struct {
	Resolver *KubeResolver
}

func (k *KubePodUIDFromCgroupID) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok, err := k.Resolver.ResolveByCgroupID(string(in))
	return kubeDecodeFromMeta(in, meta, ok, err, "PodUID")
}

// --- Decoders: from_pid (input = PID string) ---

// KubePodNameFromPID resolves PID to pod name.
type KubePodNameFromPID struct {
	Resolver *KubeResolver
}

func (k *KubePodNameFromPID) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok, err := k.Resolver.ResolveByPID(string(in))
	return kubeDecodeFromMeta(in, meta, ok, err, "Pod")
}

// KubeNamespaceFromPID resolves PID to namespace.
type KubeNamespaceFromPID struct {
	Resolver *KubeResolver
}

func (k *KubeNamespaceFromPID) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok, err := k.Resolver.ResolveByPID(string(in))
	return kubeDecodeFromMeta(in, meta, ok, err, "Namespace")
}

// KubeContainerNameFromPID resolves PID to container name.
type KubeContainerNameFromPID struct {
	Resolver *KubeResolver
}

func (k *KubeContainerNameFromPID) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok, err := k.Resolver.ResolveByPID(string(in))
	return kubeDecodeFromMeta(in, meta, ok, err, "Container")
}

// KubePodUIDFromPID resolves PID to pod UID.
type KubePodUIDFromPID struct {
	Resolver *KubeResolver
}

func (k *KubePodUIDFromPID) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok, err := k.Resolver.ResolveByPID(string(in))
	return kubeDecodeFromMeta(in, meta, ok, err, "PodUID")
}
