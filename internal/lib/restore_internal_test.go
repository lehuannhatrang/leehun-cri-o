package lib

import (
	"context"
	"reflect"
	"slices"
	"strings"
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

func TestExtractHAMiVGPUDestinationsClaimsPath(t *testing.T) {
	spec := &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/usr/local/vgpu/claims/3f1c9a2e-uid", Destination: "/usr/local/vgpu/claims/3f1c9a2e-uid"},
			{Source: "/etc/resolv.conf", Destination: "/etc/resolv.conf"},
		},
	}

	got := extractHAMiVGPUDestinations(spec, testHAMiVGPUPrefixes)
	if len(got) != 1 || got[0] != "/usr/local/vgpu/claims/3f1c9a2e-uid" {
		t.Fatalf("expected DRA claims mount to be detected, got %v", got)
	}
}

func TestExtractHAMiVGPUDestinationsLegacyContainersPath(t *testing.T) {
	spec := &rspec.Spec{
		Mounts: []rspec.Mount{
			{
				Source:      "/usr/local/vgpu/containers/0123456789abcdef0123456789abcdef0123_ctr",
				Destination: "/usr/local/vgpu/containers/0123456789abcdef0123456789abcdef0123_ctr",
			},
		},
	}

	got := extractHAMiVGPUDestinations(spec, testHAMiVGPUPrefixes)
	if len(got) != 1 {
		t.Fatalf("expected legacy containers mount to still be detected, got %v", got)
	}
}

// A checkpoint taken from an already restored container carries a vGPU mount
// whose source is the host directory of that run while its destination is the
// path CRIU restored the mount at. Only the destination matches the mountpoint
// the next checkpoint will see, so it is the value that must be picked up.
func TestExtractHAMiVGPUDestinationsPrefersDestinationOverSource(t *testing.T) {
	spec := &rspec.Spec{
		Mounts: []rspec.Mount{
			{
				Source:      "/usr/local/vgpu/containers/new-uid_trainer",
				Destination: "/usr/local/vgpu/containers/old-uid_trainer",
			},
		},
	}

	got := extractHAMiVGPUDestinations(spec, testHAMiVGPUPrefixes)
	if len(got) != 1 || got[0] != "/usr/local/vgpu/containers/old-uid_trainer" {
		t.Fatalf("expected the checkpointed destination, got %v", got)
	}
}

func TestExtractHAMiVGPUDestinationsCustomPrefix(t *testing.T) {
	// An operator can point CRI-O at a non-default HAMi layout; only mounts
	// under the configured prefix must be selected.
	prefixes := []string{"/custom/hami/root/"}
	spec := &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/custom/hami/root/some-uid", Destination: "/custom/hami/root/some-uid"},
			{Source: "/usr/local/vgpu/claims/default-uid", Destination: "/usr/local/vgpu/claims/default-uid"},
		},
	}

	got := extractHAMiVGPUDestinations(spec, prefixes)
	if len(got) != 1 || got[0] != "/custom/hami/root/some-uid" {
		t.Fatalf("expected only the custom-prefixed mount, got %v", got)
	}
}

// CRIU restores every mount at the path recorded in the checkpoint and only
// redirects its source, so the restored container keeps the vGPU directory at
// the checkpointed path. The freshly allocated mount that HAMi injects for
// this run must therefore be pointed back at that path, otherwise the runtime
// derives its CRIU external-mount key from a path that is not mounted and the
// next checkpoint aborts with "has unreachable sharing".
func TestAlignHAMiVGPUMountsRewritesDestination(t *testing.T) {
	g := &generate.Generator{Config: &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/etc/resolv.conf", Destination: "/etc/resolv.conf"},
			{
				Source:      "/usr/local/vgpu/containers/new-uid_trainer",
				Destination: "/usr/local/vgpu/containers/new-uid_trainer",
			},
		},
	}}

	got := alignHAMiVGPUMounts(
		context.Background(),
		g,
		[]string{"/usr/local/vgpu/containers/old-uid_trainer"},
		testHAMiVGPUPrefixes,
	)

	want := []hamiVGPUMount{{
		Destination: "/usr/local/vgpu/containers/old-uid_trainer",
		Source:      "/usr/local/vgpu/containers/new-uid_trainer",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}

	m := g.Config.Mounts[1]
	if m.Destination != "/usr/local/vgpu/containers/old-uid_trainer" {
		t.Fatalf("expected the destination to be rewritten, got %q", m.Destination)
	}

	if m.Source != "/usr/local/vgpu/containers/new-uid_trainer" {
		t.Fatalf("expected the source of this run to be kept, got %q", m.Source)
	}

	if g.Config.Mounts[0].Destination != "/etc/resolv.conf" {
		t.Fatalf("unrelated mounts must not be touched, got %q", g.Config.Mounts[0].Destination)
	}
}

// Restores are retried by the kubelet, and every retry re-reads the spec that
// the previous attempt saved. Aligning an already aligned spec must be a no-op
// so retries keep producing the same mapping.
func TestAlignHAMiVGPUMountsIsIdempotent(t *testing.T) {
	g := &generate.Generator{Config: &rspec.Spec{
		Mounts: []rspec.Mount{
			{
				Source:      "/usr/local/vgpu/containers/new-uid_trainer",
				Destination: "/usr/local/vgpu/containers/old-uid_trainer",
			},
		},
	}}
	oldDests := []string{"/usr/local/vgpu/containers/old-uid_trainer"}

	first := alignHAMiVGPUMounts(context.Background(), g, oldDests, testHAMiVGPUPrefixes)
	second := alignHAMiVGPUMounts(context.Background(), g, oldDests, testHAMiVGPUPrefixes)

	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected a stable mapping, got %v then %v", first, second)
	}

	if g.Config.Mounts[0].Destination != "/usr/local/vgpu/containers/old-uid_trainer" {
		t.Fatalf("expected the destination to stay put, got %q", g.Config.Mounts[0].Destination)
	}
}

// A pod with several vGPU mounts must pair them by the container-name part of
// the directory instead of by position.
func TestAlignHAMiVGPUMountsPairsByContainerName(t *testing.T) {
	const uuid = "0123456789abcdef0123456789abcdef0123"

	g := &generate.Generator{Config: &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/usr/local/vgpu/containers/" + uuid + "_worker", Destination: "/usr/local/vgpu/containers/" + uuid + "_worker"},
			{Source: "/usr/local/vgpu/containers/" + uuid + "_trainer", Destination: "/usr/local/vgpu/containers/" + uuid + "_trainer"},
		},
	}}

	oldDests := []string{
		"/usr/local/vgpu/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_trainer",
		"/usr/local/vgpu/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_worker",
	}

	got := alignHAMiVGPUMounts(context.Background(), g, oldDests, testHAMiVGPUPrefixes)

	want := []hamiVGPUMount{
		{
			Destination: "/usr/local/vgpu/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_trainer",
			Source:      "/usr/local/vgpu/containers/" + uuid + "_trainer",
		},
		{
			Destination: "/usr/local/vgpu/containers/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa_worker",
			Source:      "/usr/local/vgpu/containers/" + uuid + "_worker",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

// Checkpoint taken on a legacy (containers) host, restored on a DRA (claims)
// host: the prefixes differ so no container-name suffix matches, but a single
// vGPU mount must still be paired positionally.
func TestAlignHAMiVGPUMountsCrossLayout(t *testing.T) {
	g := &generate.Generator{Config: &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/usr/local/vgpu/claims/new-claim-uid", Destination: "/usr/local/vgpu/claims/new-claim-uid"},
		},
	}}

	got := alignHAMiVGPUMounts(
		context.Background(),
		g,
		[]string{"/usr/local/vgpu/containers/0123456789abcdef0123456789abcdef0123_ctr"},
		testHAMiVGPUPrefixes,
	)

	want := []hamiVGPUMount{{
		Destination: "/usr/local/vgpu/containers/0123456789abcdef0123456789abcdef0123_ctr",
		Source:      "/usr/local/vgpu/claims/new-claim-uid",
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
}

func TestAlignHAMiVGPUMountsWithoutNewMount(t *testing.T) {
	g := &generate.Generator{Config: &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/etc/resolv.conf", Destination: "/etc/resolv.conf"},
		},
	}}

	if got := alignHAMiVGPUMounts(
		context.Background(),
		g,
		[]string{"/usr/local/vgpu/containers/old-uid_trainer"},
		testHAMiVGPUPrefixes,
	); got != nil {
		t.Fatalf("expected no mapping without a vGPU mount in the new spec, got %v", got)
	}

	if g.Config.Mounts[0].Destination != "/etc/resolv.conf" {
		t.Fatalf("unrelated mounts must not be touched, got %q", g.Config.Mounts[0].Destination)
	}
}

func TestAlignHAMiVGPUMountsWithoutCheckpointedMount(t *testing.T) {
	g := &generate.Generator{Config: &rspec.Spec{
		Mounts: []rspec.Mount{
			{Source: "/usr/local/vgpu/claims/new-claim-uid", Destination: "/usr/local/vgpu/claims/new-claim-uid"},
		},
	}}

	if got := alignHAMiVGPUMounts(context.Background(), g, nil, testHAMiVGPUPrefixes); got != nil {
		t.Fatalf("expected no mapping without a checkpointed vGPU mount, got %v", got)
	}

	if g.Config.Mounts[0].Destination != "/usr/local/vgpu/claims/new-claim-uid" {
		t.Fatalf("expected a fresh allocation to be left alone, got %q", g.Config.Mounts[0].Destination)
	}
}

func TestBuildHAMiExtMountMapLines(t *testing.T) {
	mounts := []hamiVGPUMount{
		{Destination: "/usr/local/vgpu/claims/old-claim-uid", Source: "/usr/local/vgpu/claims/new-claim-uid"},
	}

	got := buildHAMiExtMountMapLines(mounts)
	want := "ext-mount-map /usr/local/vgpu/claims/old-claim-uid:/usr/local/vgpu/claims/new-claim-uid\n"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestBuildHAMiExtMountMapLinesNoMounts(t *testing.T) {
	if got := buildHAMiExtMountMapLines(nil); got != "" {
		t.Fatalf("expected no lines without vGPU mounts, got %q", got)
	}
}

// HAMi points libvgpu at its cache file through an environment variable that
// embeds the per-allocation directory. The processes coming back from the
// checkpoint carry the checkpointed value, so the value injected for this run
// has to be rewritten to the same path, otherwise anything exec'ed into the
// restored container looks for the cache below a path that is not mounted.
func TestRewriteHAMiVGPUEnv(t *testing.T) {
	g := &generate.Generator{Config: &rspec.Spec{
		Process: &rspec.Process{
			Env: []string{
				"HOME=/home/jovyan",
				"CUDA_DEVICE_MEMORY_SHARED_CACHE=/usr/local/vgpu/containers/new-uid_trainer/cache-uid.cache",
			},
		},
	}}

	rewriteHAMiVGPUEnv(g, []hamiVGPUMount{{
		Destination: "/usr/local/vgpu/containers/old-uid_trainer",
		Source:      "/usr/local/vgpu/containers/new-uid_trainer",
	}})

	want := []string{
		"HOME=/home/jovyan",
		"CUDA_DEVICE_MEMORY_SHARED_CACHE=/usr/local/vgpu/containers/old-uid_trainer/cache-uid.cache",
	}
	if !reflect.DeepEqual(g.Config.Process.Env, want) {
		t.Fatalf("expected %v, got %v", want, g.Config.Process.Env)
	}
}

func TestRewriteHAMiVGPUEnvWithoutProcess(t *testing.T) {
	g := &generate.Generator{Config: &rspec.Spec{}}

	// Must not panic on a spec without a process section.
	rewriteHAMiVGPUEnv(g, []hamiVGPUMount{{
		Destination: "/usr/local/vgpu/containers/old-uid_trainer",
		Source:      "/usr/local/vgpu/containers/new-uid_trainer",
	}})
}

// The org.criu.config annotation stays in the container's runtime state after
// the restore, so the file it points at is handed to CRIU again at the next
// checkpoint. It must therefore only carry options that are valid for a dump:
// the restore-only action script and the ext-mount-map entries of the previous
// run would otherwise be applied to the checkpoint.
func TestBuildCheckpointCRIUConfig(t *testing.T) {
	got := buildCheckpointCRIUConfig()

	if want := "ghost-limit 104857600\n"; !strings.Contains(got, want) {
		t.Fatalf("expected %q in %q", want, got)
	}

	for _, unwanted := range []string{"action-script", "ext-mount-map", "log-file", "tcp-close"} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("did not expect %q in %q", unwanted, got)
		}
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
