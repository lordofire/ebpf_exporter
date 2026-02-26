package decoder

import "testing"

func TestParseCgroupPath_Systemd(t *testing.T) {
	tests := []struct {
		path          string
		wantPodUID    string
		wantContainer string
		wantOK        bool
	}{
		{
			path:          "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-poda1b2c3d4_e5f6_7890_abcd_ef1234567890.slice/crio-abc123def456.scope",
			wantPodUID:    "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			wantContainer: "abc123def456",
			wantOK:        true,
		},
		{
			path:          "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-podxyz.slice/cri-containerd-xyz.scope",
			wantPodUID:    "xyz",
			wantContainer: "xyz",
			wantOK:        true,
		},
		{
			path:       "/sys/fs/cgroup/system.slice",
			wantPodUID: "",
			wantOK:     false,
		},
	}
	for _, tt := range tests {
		gotPod, gotContainer, gotOK := ParseCgroupPath(tt.path)
		if gotOK != tt.wantOK || gotPod != tt.wantPodUID || gotContainer != tt.wantContainer {
			t.Errorf("ParseCgroupPath(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tt.path, gotPod, gotContainer, gotOK, tt.wantPodUID, tt.wantContainer, tt.wantOK)
		}
	}
}

func TestParseCgroupPath_Cgroupfs(t *testing.T) {
	podUID, containerID, ok := ParseCgroupPath("/sys/fs/cgroup/kubepods/besteffort/pod12345678-90ab-cdef/pause")
	if !ok {
		t.Fatalf("expected ok")
	}
	if podUID != "12345678-90ab-cdef" {
		t.Errorf("podUID = %q", podUID)
	}
	if containerID != "pause" {
		t.Errorf("containerID = %q", containerID)
	}
}
