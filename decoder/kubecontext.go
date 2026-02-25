package decoder

import (
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/cloudflare/ebpf_exporter/v2/cgroup"
	"github.com/cloudflare/ebpf_exporter/v2/config"
	lru "github.com/hashicorp/golang-lru/v2"
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
type KubeBackend interface {
	Resolve(containerID, podUID string) (PodMeta, bool)
}

// NoopKubeBackend returns unknown for all lookups. Used when no runtime backend is configured.
type NoopKubeBackend struct{}

// Resolve implements KubeBackend.
func (NoopKubeBackend) Resolve(_, _ string) (PodMeta, bool) {
	return PodMeta{
		Pod:       "unknown",
		Namespace: "unknown",
		Container: "unknown",
		PodUID:    "unknown",
	}, false
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

// KubeResolver resolves cgroup ID to PodMeta using cgroup monitor, path parsing, and a backend.
// Results are cached by cgroup path to avoid repeated lookups.
type KubeResolver struct {
	monitor *cgroup.Monitor
	backend KubeBackend
	cache   *lru.Cache[string, PodMeta]
	mu      sync.Mutex
}

// NewKubeResolver creates a resolver with the given cgroup monitor, backend, and cache size.
// If cacheSize <= 0, no cache is used.
func NewKubeResolver(monitor *cgroup.Monitor, backend KubeBackend, cacheSize int) (*KubeResolver, error) {
	r := &KubeResolver{
		monitor: monitor,
		backend: backend,
	}
	if cacheSize > 0 {
		cache, err := lru.New[string, PodMeta](cacheSize)
		if err != nil {
			return nil, err
		}
		r.cache = cache
	}
	return r, nil
}

// Resolve resolves a cgroup ID (as decimal string) to PodMeta.
func (r *KubeResolver) Resolve(cgroupIDStr string) (PodMeta, bool) {
	cgroupID, err := strconv.Atoi(cgroupIDStr)
	if err != nil {
		return PodMeta{}, false
	}
	path := r.monitor.Resolve(cgroupID)
	if path == "" || strings.HasPrefix(path, "unknown_cgroup_id:") {
		return PodMeta{}, false
	}

	if r.cache != nil {
		r.mu.Lock()
		if meta, ok := r.cache.Get(path); ok {
			r.mu.Unlock()
			return meta, true
		}
		r.mu.Unlock()
	}

	podUID, containerID, ok := ParseCgroupPath(path)
	if !ok {
		unknown := PodMeta{Pod: "unknown", Namespace: "unknown", Container: "unknown", PodUID: "unknown"}
		if r.cache != nil {
			r.mu.Lock()
			r.cache.Add(path, unknown)
			r.mu.Unlock()
		}
		return unknown, true
	}

	meta, found := r.backend.Resolve(containerID, podUID)
	if !found {
		meta = PodMeta{Pod: "unknown", Namespace: "unknown", Container: "unknown", PodUID: podUID}
	} else if meta.PodUID == "" {
		meta.PodUID = podUID
	}

	if r.cache != nil {
		r.mu.Lock()
		r.cache.Add(path, meta)
		r.mu.Unlock()
	}
	return meta, true
}

// KubePodName is a decoder that resolves cgroup ID to pod name via KubeResolver.
type KubePodName struct {
	Resolver *KubeResolver
}

// Decode implements Decoder.
func (k *KubePodName) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok := k.Resolver.Resolve(string(in))
	if !ok {
		return []byte("unknown"), nil
	}
	return []byte(meta.Pod), nil
}

// KubeNamespace is a decoder that resolves cgroup ID to namespace via KubeResolver.
type KubeNamespace struct {
	Resolver *KubeResolver
}

// Decode implements Decoder.
func (k *KubeNamespace) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok := k.Resolver.Resolve(string(in))
	if !ok {
		return []byte("unknown"), nil
	}
	return []byte(meta.Namespace), nil
}

// KubeContainerName is a decoder that resolves cgroup ID to container name via KubeResolver.
type KubeContainerName struct {
	Resolver *KubeResolver
}

// Decode implements Decoder.
func (k *KubeContainerName) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok := k.Resolver.Resolve(string(in))
	if !ok {
		return []byte("unknown"), nil
	}
	return []byte(meta.Container), nil
}

// KubePodUID is a decoder that resolves cgroup ID to pod UID via KubeResolver.
type KubePodUID struct {
	Resolver *KubeResolver
}

// Decode implements Decoder.
func (k *KubePodUID) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	meta, ok := k.Resolver.Resolve(string(in))
	if !ok {
		return []byte("unknown"), nil
	}
	return []byte(meta.PodUID), nil
}
