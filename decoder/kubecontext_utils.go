package decoder

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const listPodsRetries = 3
const listPodsBackoff = 200 * time.Millisecond

// ErrNodeNameRequired is returned by K8sKubeBackend.Resolve when NODE_NAME env is not set.
// The DaemonSet must set NODE_NAME via downward API (spec.nodeName) for node-scoped pod list.
var ErrNodeNameRequired = errors.New("NODE_NAME is required for node-scoped pod list; set via downward API in DaemonSet")

// containerMeta holds container ID (without runtime prefix) and name for lookup.
type containerMeta struct {
	ID   string
	Name string
}

// podCacheValue is the cached value per pod UID; includes list of containers for PID-based resolve.
type podCacheValue struct {
	Pod        string
	Namespace  string
	PodUID     string
	Containers []containerMeta
}

// K8sKubeBackend resolves pod UID (and optionally container ID) to PodMeta using the
// Kubernetes API. It lists only pods on the current node (NODE_NAME) and replaces the
// cache on each miss. DaemonSet must set NODE_NAME via downward API for this to work.
type K8sKubeBackend struct {
	client   *kubernetes.Clientset
	nodeName string
	cache    map[string]podCacheValue
	mu       sync.Mutex
}

// NewK8sKubeBackend creates a KubeBackend that uses the Kubernetes API with node-scoped
// list (fieldSelector=spec.nodeName=NODE_NAME). NODE_NAME is read from the environment only;
// if unset, Resolve returns ErrNodeNameRequired so the metric decode fails.
func NewK8sKubeBackend() (KubeBackend, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	nodeName := strings.TrimSpace(os.Getenv("NODE_NAME"))
	b := &K8sKubeBackend{
		client:   client,
		nodeName: nodeName,
		cache:    make(map[string]podCacheValue),
	}
	return b, nil
}

// Resolve implements KubeBackend. Node-scoped: on cache miss, lists pods on this node,
// replaces cache (thread-safe), then looks up again. No negative caching.
// When podUID is found but containerID is not (e.g. init/not-ready), returns container "unknown".
func (b *K8sKubeBackend) Resolve(containerID, podUID string) (PodMeta, bool, error) {
	if b.nodeName == "" {
		return PodMeta{}, false, ErrNodeNameRequired
	}
	if podUID == "" {
		return PodMeta{}, false, nil
	}

	b.mu.Lock()
	val, hit := b.cache[podUID]
	b.mu.Unlock()

	if hit {
		return b.podCacheValueToMeta(val, containerID), true, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	opts := metav1.ListOptions{FieldSelector: "spec.nodeName=" + b.nodeName}

	var list *corev1.PodList
	var err error
	for attempt := 0; attempt < listPodsRetries; attempt++ {
		list, err = b.client.CoreV1().Pods(metav1.NamespaceAll).List(ctx, opts)
		if err == nil {
			break
		}
		if attempt < listPodsRetries-1 {
			time.Sleep(listPodsBackoff * time.Duration(attempt+1))
		} else {
			return PodMeta{}, false, err
		}
	}

	newCache := make(map[string]podCacheValue, len(list.Items))
	for i := range list.Items {
		pod := &list.Items[i]
		uid := string(pod.UID)
		containers := make([]containerMeta, 0, len(pod.Status.ContainerStatuses))
		for j := range pod.Status.ContainerStatuses {
			s := &pod.Status.ContainerStatuses[j]
			id := trimRuntimePrefix(s.ContainerID)
			if id != "" {
				containers = append(containers, containerMeta{ID: id, Name: s.Name})
			}
		}
		newCache[uid] = podCacheValue{
			Pod:        pod.Name,
			Namespace:  pod.Namespace,
			PodUID:     uid,
			Containers: containers,
		}
	}
	b.mu.Lock()
	b.cache = newCache
	val, found := b.cache[podUID]
	b.mu.Unlock()

	if !found {
		return PodMeta{Pod: "unknown", Namespace: "unknown", Container: "unknown", PodUID: podUID}, true, nil
	}
	return b.podCacheValueToMeta(val, containerID), true, nil
}

// podCacheValueToMeta converts cache value to PodMeta. When containerID is empty (pod-level query),
// only pod/namespace/podUID are set; Container is left empty. For PID-based (containerID set),
// finds matching container or "unknown".
func (b *K8sKubeBackend) podCacheValueToMeta(val podCacheValue, containerID string) PodMeta {
	meta := PodMeta{Pod: val.Pod, Namespace: val.Namespace, PodUID: val.PodUID}
	if containerID == "" {
		return meta
	}
	for _, c := range val.Containers {
		if matchContainerIDStrings(c.ID, containerID) {
			meta.Container = c.Name
			return meta
		}
	}
	meta.Container = "unknown"
	return meta
}

func matchContainerIDStrings(containerIDStored, containerIDQuery string) bool {
	return strings.Contains(containerIDStored, containerIDQuery) || strings.Contains(containerIDQuery, containerIDStored)
}

func trimRuntimePrefix(id string) string {
	for _, prefix := range []string{"containerd://", "docker://", "crio://"} {
		if strings.HasPrefix(id, prefix) {
			return strings.TrimPrefix(id, prefix)
		}
	}
	return id
}
