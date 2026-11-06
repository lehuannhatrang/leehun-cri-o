package server

import (
	"testing"

	spec "github.com/opencontainers/runtime-spec/specs-go"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
)

func devicePaths(devices []*types.Device) []string {
	paths := make([]string, 0, len(devices))
	for _, d := range devices {
		paths = append(paths, d.GetContainerPath())
	}

	return paths
}

func equalPaths(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}

	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}

	return true
}

// A checkpoint records the GPU device nodes of the run it was taken from.
// Restoring on another GPU must not resurrect those nodes: both the NVIDIA
// nodes and the DRM card/render nodes paired with them by the CDI spec are
// re-injected from the CDI registry for the GPU allocated now.

func TestBuildRestoreDevicesDropsCDIManagedDevices(t *testing.T) {
	dumpSpec := &spec.Spec{
		Linux: &spec.Linux{
			Devices: []spec.LinuxDevice{
				{Path: "/dev/nvidia3"},
				{Path: "/dev/nvidiactl"},
				{Path: "/dev/nvidia-modeset"},
				{Path: "/dev/nvidia-caps/nvidia-cap1"},
				{Path: "/dev/dri/card4"},
				{Path: "/dev/dri/renderD131"},
				{Path: "/dev/fuse"},
			},
		},
	}

	got := devicePaths(buildRestoreDevices(nil, dumpSpec))
	want := []string{"/dev/fuse"}

	if !equalPaths(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestBuildRestoreDevicesPrefersRequestDevices(t *testing.T) {
	createDevices := []*types.Device{
		{ContainerPath: "/dev/dri/card3", HostPath: "/dev/dri/card3", Permissions: "rw"},
	}
	dumpSpec := &spec.Spec{
		Linux: &spec.Linux{
			Devices: []spec.LinuxDevice{
				{Path: "/dev/dri/card4"},
				{Path: "/dev/fuse"},
			},
		},
	}

	got := devicePaths(buildRestoreDevices(createDevices, dumpSpec))
	want := []string{"/dev/dri/card3", "/dev/fuse"}

	if !equalPaths(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestBuildRestoreDevicesDoesNotDuplicateSharedPaths(t *testing.T) {
	createDevices := []*types.Device{
		{ContainerPath: "/dev/fuse", HostPath: "/dev/fuse", Permissions: "rwm"},
	}
	dumpSpec := &spec.Spec{
		Linux: &spec.Linux{
			Devices: []spec.LinuxDevice{{Path: "/dev/fuse"}},
		},
	}

	devices := buildRestoreDevices(createDevices, dumpSpec)
	if len(devices) != 1 {
		t.Fatalf("expected a single device, got %v", devicePaths(devices))
	}

	if devices[0].GetPermissions() != "rwm" {
		t.Fatalf("expected the request device to win, got permissions %q", devices[0].GetPermissions())
	}
}

func TestBuildRestoreDevicesWithoutLinuxSection(t *testing.T) {
	createDevices := []*types.Device{
		{ContainerPath: "/dev/fuse", HostPath: "/dev/fuse", Permissions: "rw"},
	}

	got := devicePaths(buildRestoreDevices(createDevices, &spec.Spec{}))
	want := []string{"/dev/fuse"}

	if !equalPaths(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestProcessMountsKeepsPodSuppliedDevShm(t *testing.T) {
	dumpSpec := &spec.Spec{Mounts: []spec.Mount{
		{Destination: "/dev/shm", Source: "/var/lib/kubelet/pods/old/volumes/kubernetes.io~empty-dir/shared-mem"},
		{Destination: "/proc", Source: "proc"},
		{Destination: "/workspace", Source: "/var/lib/kubelet/pods/old/volumes/kubernetes.io~configmap/workspace"},
	}}
	createMounts := []*types.Mount{
		{ContainerPath: "/dev/shm", HostPath: "/var/lib/kubelet/pods/new/volumes/kubernetes.io~empty-dir/shared-mem"},
		{ContainerPath: "/workspace", HostPath: "/var/lib/kubelet/pods/new/volumes/kubernetes.io~configmap/workspace", Readonly: true},
	}

	mounts, missing := processMounts(t.Context(), dumpSpec, createMounts, &NVIDIADriverInfo{})
	if len(missing) != 0 {
		t.Fatalf("unexpected missing mounts %v", missing)
	}

	got := map[string]string{}
	for _, m := range mounts {
		got[m.GetContainerPath()] = m.GetHostPath()
	}

	if got["/dev/shm"] != createMounts[0].GetHostPath() {
		t.Fatalf("/dev/shm = %q, want the pod's emptyDir %q", got["/dev/shm"], createMounts[0].GetHostPath())
	}

	if _, ok := got["/proc"]; ok {
		t.Fatal("/proc must stay ignored")
	}

	if len(mounts) != 2 {
		t.Fatalf("got %d mounts, want 2: %v", len(mounts), got)
	}
}

func TestProcessMountsDevShmWithoutPodVolume(t *testing.T) {
	// No volume at /dev/shm in the request: CRI-O's own sandbox shm is used,
	// so the checkpointed /dev/shm is neither kept nor reported missing.
	dumpSpec := &spec.Spec{Mounts: []spec.Mount{
		{Destination: "/dev/shm", Source: "/run/containers/storage/overlay-containers/x/userdata/shm"},
	}}

	mounts, missing := processMounts(t.Context(), dumpSpec, nil, &NVIDIADriverInfo{})
	if len(mounts) != 0 || len(missing) != 0 {
		t.Fatalf("mounts=%v missing=%v, want none", mounts, missing)
	}
}

func TestUpdateAnnotationsRefreshesRestartCount(t *testing.T) {
	original := map[string]string{
		"io.kubernetes.pod.uid":                "old-uid",
		"io.kubernetes.container.hash":         "old-hash",
		"io.kubernetes.container.restartCount": "0",
		"io.kubernetes.container.ports":        "[]",
	}
	create := map[string]string{
		"io.kubernetes.container.hash":         "new-hash",
		"io.kubernetes.container.restartCount": "3",
	}

	updateAnnotations(original, "new-uid", create)

	want := map[string]string{
		"io.kubernetes.pod.uid":                "new-uid",
		"io.kubernetes.container.hash":         "new-hash",
		"io.kubernetes.container.restartCount": "3",
		"io.kubernetes.container.ports":        "[]",
	}
	for k, v := range want {
		if original[k] != v {
			t.Errorf("%s = %q, want %q", k, original[k], v)
		}
	}
}
