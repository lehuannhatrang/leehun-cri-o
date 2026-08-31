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
