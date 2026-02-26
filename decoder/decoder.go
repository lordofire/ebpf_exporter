package decoder

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync"

	"github.com/cloudflare/ebpf_exporter/v2/cgroup"
	"github.com/cloudflare/ebpf_exporter/v2/config"
	"github.com/cloudflare/ebpf_exporter/v2/kallsyms"
	lru "github.com/hashicorp/golang-lru/v2"
)

// debugDecode enables [decode:debug] and [kube:debug] logs when EBPF_EXPORTER_DEBUG_DECODE=1.
var debugDecode bool

func init() {
	v, _ := strconv.ParseBool(os.Getenv("EBPF_EXPORTER_DEBUG_DECODE"))
	debugDecode = v
}

// ErrSkipLabelSet instructs exporter to skip label set
var ErrSkipLabelSet = errors.New("this label set should be skipped")

// Decoder transforms byte field value into a byte value representing string
// to either use as an input for another Decoder or to use as the final
// label value for Prometheus metrics
type Decoder interface {
	Decode(in []byte, conf config.Decoder) ([]byte, error)
}

// Set is a set of Decoders that may be applied to produce a label
type Set struct {
	mu        sync.Mutex
	decoders  map[string]Decoder
	cache     map[string]map[string][]string
	skipCache *lru.Cache[string, struct{}]
}

func NewSet(skipCacheSize int, monitor *cgroup.Monitor, resolver *KubeResolver) (*Set, error) {
	ksym, err := kallsyms.NewDecoder("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("error creating ksym decoder: %w", err)
	}

	s := &Set{
		decoders: map[string]Decoder{
			"cgroup":                            &CGroup{monitor},
			"dname":                             &Dname{},
			"errno":                             &Errno{},
			"hex":                               &Hex{},
			"ifname":                            &IfName{},
			"inet_ip":                           &InetIP{},
			"kstack":                            &KStack{ksym},
			"ksym":                              &KSym{ksym},
			"kube_container_name_from_cgroupid": &KubeContainerNameFromCgroupID{Resolver: resolver},
			"kube_container_name_from_pid":      &KubeContainerNameFromPID{Resolver: resolver},
			"kube_namespace_from_cgroupid":      &KubeNamespaceFromCgroupID{Resolver: resolver},
			"kube_namespace_from_pid":           &KubeNamespaceFromPID{Resolver: resolver},
			"kube_pod_name_from_cgroupid":       &KubePodNameFromCgroupID{Resolver: resolver},
			"kube_pod_name_from_pid":            &KubePodNameFromPID{Resolver: resolver},
			"kube_pod_uid_from_cgroupid":        &KubePodUIDFromCgroupID{Resolver: resolver},
			"kube_pod_uid_from_pid":             &KubePodUIDFromPID{Resolver: resolver},
			"majorminor":                        &MajorMinor{},
			"pci_class":                         &PCIClass{},
			"pci_device":                        &PCIDevice{},
			"pci_subclass":                      &PCISubClass{},
			"pci_vendor":                        &PCIVendor{},
			"regexp":                            &Regexp{},
			"static_map":                        &StaticMap{},
			"string":                            &String{},
			"syscall":                           &Syscall{},
			"uint":                              &UInt{},
		},
		cache: map[string]map[string][]string{},
	}

	if skipCacheSize > 0 {
		skipCache, err := lru.New[string, struct{}](skipCacheSize)
		if err != nil {
			return nil, err
		}
		s.skipCache = skipCache
	}
	return s, nil
}

// decode transforms input byte field into a string according to configuration
func (s *Set) decode(in []byte, label config.Label) ([]byte, error) {
	result := in

	for _, decoder := range label.Decoders {
		if _, ok := s.decoders[decoder.Name]; !ok {
			return result, fmt.Errorf("unknown decoder %q", decoder.Name)
		}

		decoded, err := s.decoders[decoder.Name].Decode(result, decoder)
		if err != nil {
			if errors.Is(err, ErrSkipLabelSet) {
				if s.skipCache != nil {
					s.skipCache.Add(string(in), struct{}{})
				}
				return decoded, err
			}

			return decoded, fmt.Errorf("error decoding with decoder %q: %w", decoder.Name, err)
		}

		result = decoded
	}

	return result, nil
}

// DecodeLabelsForMetrics transforms eBPF map key bytes into a list of label values
// according to configuration (different label sets require different names).
// This decoder method variant does caching and is suitable for metrics.
func (s *Set) DecodeLabelsForMetrics(in []byte, name string, labels []config.Label) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cache, ok := s.cache[name]
	if !ok {
		cache = map[string][]string{}
		s.cache[name] = cache
	}

	// string(in) must not be a variable to avoid allocation:
	// * https://github.com/golang/go/commit/f5f5a8b6209f8
	if cached, ok := cache[string(in)]; ok {
		if debugDecode {
			log.Printf("[decode:debug] metric %q cache HIT key=%s values=%q", name, hex.EncodeToString(in), cached)
		}
		return cached, nil
	}

	// Also check the skip cache if the input would have return ErrSkipLabelSet
	// and return the error early.
	if s.skipCache != nil {
		if _, ok := s.skipCache.Get(string(in)); ok {
			if debugDecode {
				log.Printf("[decode:debug] metric %q skip-cache HIT key=%s", name, hex.EncodeToString(in))
			}
			return nil, ErrSkipLabelSet
		}
	}

	values, err := s.decodeLabels(in, labels)
	if err != nil {
		if debugDecode {
			log.Printf("[decode:debug] metric %q decodeLabels err key=%s err=%v", name, hex.EncodeToString(in), err)
		}
		return nil, err
	}

	cache[string(in)] = values
	if debugDecode {
		log.Printf("[decode:debug] metric %q cache MISS (decoded) key=%s values=%q", name, hex.EncodeToString(in), values)
	}
	return values, nil
}

// DecodeLabelsForTracing transforms eBPF map key bytes into a list of label values
// according to configuration (different label sets require different names).
// This decoder method variant does not do caching and is suitable for tracing.
func (s *Set) DecodeLabelsForTracing(in []byte, labels []config.Label) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.decodeLabels(in, labels)
}

// decodeLabels is the inner function of DecodeLabels without any caching.
// When a label has Reuse set, the read offset is not advanced for the next label.
func (s *Set) decodeLabels(in []byte, labels []config.Label) ([]string, error) {
	values := make([]string, len(labels))
	off := uint(0)

	for i, label := range labels {
		size := label.Size
		if size == 0 {
			return nil, fmt.Errorf("error decoding label %q: size is zero or not set", label.Name)
		}
		if uint(len(in)) < off+size {
			return nil, fmt.Errorf("error decoding labels: total size of key %#v is %d bytes, but we need at least %d", in, len(in), off+size)
		}
		if len(label.Decoders) == 0 {
			return nil, fmt.Errorf("error decoding label %q: no decoders set", label.Name)
		}
		slice := in[off : off+size]
		if debugDecode {
			names := make([]string, len(label.Decoders))
			for j, d := range label.Decoders {
				names[j] = d.Name
			}
			log.Printf("[decode:debug] label[%d] name=%q offset=%d size=%d reuse=%v decoders=%v slice_hex=%s",
				i, label.Name, off, size, label.Reuse, names, hex.EncodeToString(slice))
		}
		decoded, err := s.decode(slice, label)
		if err != nil {
			return nil, err
		}
		values[i] = string(decoded)
		if debugDecode {
			v := string(decoded)
			if len(v) > 64 {
				v = v[:64] + "..."
			}
			log.Printf("[decode:debug] label[%d] name=%q => %q", i, label.Name, v)
		}
		if !label.Reuse {
			off += size + label.Padding
		}
	}

	return values, nil
}
