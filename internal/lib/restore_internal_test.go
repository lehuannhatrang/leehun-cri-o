package lib

import (
	"context"
	"slices"
	"testing"

	rspec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"

	libconfig "github.com/cri-o/cri-o/pkg/config"
)

// testHAMiVGPUPrefixes mirrors the shipped defaults so the helper tests
// exercise the same prefixes CRI-O uses out of the box.
var testHAMiVGPUPrefixes = libconfig.DefaultHAMiVGPUMountPrefixes

// The HAMi DRA driver (Project-HAMi/k8s-dra-driver) bind-mounts a per-claim
// cache directory at /usr/local/vgpu/claims/<ResourceClaim-UID>. Older
// device-plugin builds used /usr/local/vgpu/containers/<UUID>_<container_name>.
// Both must be recognised so checkpoints survive a HAMi version change.

func TestExtractHAMiVGPUSourcesClaimsPath(t *testing.T) {
	spec := &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/usr/local/vgpu/claims/3f1c9a2e-uid", Destination: "/usr/local/vgpu/claims/3f1c9a2e-uid"},
			{Source: "/etc/resolv.conf", Destination: "/etc/resolv.conf"},
		},
	}

	got := extractHAMiVGPUSources(spec, testHAMiVGPUPrefixes)
	if len(got) != 1 || got[0] != "/usr/local/vgpu/claims/3f1c9a2e-uid" {
		t.Fatalf("expected DRA claims mount to be detected, got %v", got)
	}
}

func TestExtractHAMiVGPUSourcesLegacyContainersPath(t *testing.T) {
	spec := &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/usr/local/vgpu/containers/0123456789abcdef0123456789abcdef0123_ctr"},
		},
	}

	got := extractHAMiVGPUSources(spec, testHAMiVGPUPrefixes)
	if len(got) != 1 {
		t.Fatalf("expected legacy containers mount to still be detected, got %v", got)
	}
}

func TestBuildHAMiExtMountMapLinesClaimsRemap(t *testing.T) {
	oldPaths := []string{"/usr/local/vgpu/claims/old-claim-uid"}
	g := &generate.Generator{Config: &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/usr/local/vgpu/claims/new-claim-uid"},
		},
	}}

	got := buildHAMiExtMountMapLines(context.Background(), oldPaths, g, testHAMiVGPUPrefixes)
	want := "ext-mount-map /usr/local/vgpu/claims/old-claim-uid:/usr/local/vgpu/claims/new-claim-uid\n"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestBuildHAMiExtMountMapLinesCrossVersionRemap(t *testing.T) {
	// Checkpoint taken on a legacy (containers) host, restored on a DRA
	// (claims) host: the old and new prefixes differ but a single vGPU mount
	// must still be paired positionally.
	oldPaths := []string{"/usr/local/vgpu/containers/0123456789abcdef0123456789abcdef0123_ctr"}
	g := &generate.Generator{Config: &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/usr/local/vgpu/claims/new-claim-uid"},
		},
	}}

	got := buildHAMiExtMountMapLines(context.Background(), oldPaths, g, testHAMiVGPUPrefixes)
	want := "ext-mount-map /usr/local/vgpu/containers/0123456789abcdef0123456789abcdef0123_ctr:/usr/local/vgpu/claims/new-claim-uid\n"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestExtractHAMiVGPUSourcesCustomPrefix(t *testing.T) {
	// An operator can point CRI-O at a non-default HAMi layout; only mounts
	// under the configured prefix must be selected.
	prefixes := []string{"/custom/hami/root/"}
	spec := &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/custom/hami/root/some-uid"},
			{Source: "/usr/local/vgpu/claims/default-uid"},
		},
	}

	got := extractHAMiVGPUSources(spec, prefixes)
	if len(got) != 1 || got[0] != "/custom/hami/root/some-uid" {
		t.Fatalf("expected only the custom-prefixed mount, got %v", got)
	}
}

func TestContainerServerHAMiVGPUMountPrefixes(t *testing.T) {
	c := &ContainerServer{}

	// nil config -> built-in defaults.
	if got := c.hamiVGPUMountPrefixes(); !slices.Equal(got, libconfig.DefaultHAMiVGPUMountPrefixes) {
		t.Fatalf("expected defaults when config is nil, got %v", got)
	}

	// empty configured list -> built-in defaults.
	c.config = &libconfig.Config{}
	if got := c.hamiVGPUMountPrefixes(); !slices.Equal(got, libconfig.DefaultHAMiVGPUMountPrefixes) {
		t.Fatalf("expected defaults when configured list is empty, got %v", got)
	}

	// configured list -> honoured verbatim.
	c.config.HAMiVGPUMountPrefixes = []string{"/custom/hami/root/"}
	if got := c.hamiVGPUMountPrefixes(); !slices.Equal(got, []string{"/custom/hami/root/"}) {
		t.Fatalf("expected configured prefixes, got %v", got)
	}
}

// Checkpoints taken from a container restored by a CRI-O build that
// bind-mounted every device onto itself carry one external mount per device.
// CRIU needs an ext-mount-map entry for each of them, otherwise restore fails
// with "No mapping for <id>:<path> mountpoint".

func TestBuildDeviceExtMountMapLines(t *testing.T) {
	mappings := []deviceMapping{
		{HostPath: "/dev/nvidia-modeset", ContainerPath: "/dev/nvidia-modeset"},
		{HostPath: "/dev/dri/card1", ContainerPath: "/dev/dri/card1"},
	}

	got := buildDeviceExtMountMapLines(mappings)
	want := "ext-mount-map /dev/nvidia-modeset:/dev/nvidia-modeset\n" +
		"ext-mount-map /dev/dri/card1:/dev/dri/card1\n"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestBuildDeviceExtMountMapLinesSkipsDuplicatesAndEmptyPaths(t *testing.T) {
	mappings := []deviceMapping{
		{HostPath: "/dev/nvidia0", ContainerPath: "/dev/nvidia0"},
		{HostPath: "/dev/nvidia0", ContainerPath: "/dev/nvidia0"},
		{HostPath: "", ContainerPath: "/dev/nvidia1"},
		{HostPath: "/dev/nvidia2", ContainerPath: ""},
	}

	got := buildDeviceExtMountMapLines(mappings)
	want := "ext-mount-map /dev/nvidia0:/dev/nvidia0\n"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestBuildDeviceExtMountMapLinesNoDevices(t *testing.T) {
	if got := buildDeviceExtMountMapLines(nil); got != "" {
		t.Fatalf("expected no lines without devices, got %q", got)
	}
}
