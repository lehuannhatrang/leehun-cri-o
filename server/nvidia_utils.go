package server

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cri-o/cri-o/internal/log"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// NVIDIA mount path prefixes that identify NVIDIA-related mounts
var nvidiaMountPrefixes = []string{
	"/usr/bin/nvidia-",
	"/usr/lib/x86_64-linux-gnu/libEGL",
	"/usr/lib/x86_64-linux-gnu/libGLES",
	"/usr/lib/x86_64-linux-gnu/libGLX_nvidia.",
	"/usr/lib/x86_64-linux-gnu/libglxserver_nvidia.",
	"/usr/lib/x86_64-linux-gnu/libcuda.",
	"/usr/lib/x86_64-linux-gnu/libcudadebugger.",
	"/usr/lib/x86_64-linux-gnu/libnvcuvid.",
	"/usr/lib/x86_64-linux-gnu/libnvidia-",
	"/usr/lib/x86_64-linux-gnu/libnvoptix.",
	"/usr/lib/x86_64-linux-gnu/libOpenGL.",
	"/usr/lib/x86_64-linux-gnu/libOpenCL",
	"/usr/lib/x86_64-linux-gnu/libGLX.",
	"/usr/lib/x86_64-linux-gnu/libGL",
	"/usr/lib/x86_64-linux-gnu/nvidia/",
	"/usr/lib/x86_64-linux-gnu/nvidia/xorg/",
	"/usr/lib/x86_64-linux-gnu/vdpau/libvdpau_nvidia.",
	"/usr/lib64/nvidia/xorg/",
	"/usr/lib/nvidia/xorg/",
	"/usr/share/nvidia/",
	"/usr/share/X11/xorg.conf.d/",
	"/usr/share/egl/egl_external_platform.d/",
	"/usr/share/glvnd/egl_vendor.d/",
	"/lib/firmware/nvidia/",
	"/usr/lib/firmware/nvidia/",
	"/etc/vulkan/icd.d/nvidia_",
	"/etc/vulkan/implicit_layer.d/nvidia_",
	"/run/nvidia-persistenced/",
	"/usr/bin/nvidia-cuda-mps-control",
}

// NVIDIA keywords for pattern matching
var nvidiaKeywords = []string{
	"nvidia", "cuda", "nvml", "nvenc", "nvdec", "nvcuvid", "nvoptix", "nvcuda",
}

// NVIDIA library search paths
var nvidiaLibSearchPaths = []string{
	"/usr/lib/x86_64-linux-gnu",
	"/usr/lib/x86_64-linux-gnu/nvidia/xorg",
	"/usr/lib/x86_64-linux-gnu/nvidia",
	"/usr/lib64",
	"/usr/lib64/nvidia/xorg",
	"/usr/lib64/nvidia",
	"/usr/lib",
	"/usr/lib/nvidia/xorg",
	"/usr/lib/nvidia",
	"/lib/x86_64-linux-gnu",
	"/lib64",
	"/lib",
}

// NVIDIA binary search paths
var nvidiaBinSearchPaths = []string{"/usr/bin", "/bin", "/usr/local/bin"}

// NVIDIA firmware search paths
var nvidiaFirmwareSearchPaths = []string{"/usr/lib/firmware/nvidia", "/lib/firmware/nvidia"}

// NVIDIA command names
var nvidiaCommands = []string{
	"nvidia-smi", "nvidia-ml-py", "nvidia-cuda-mps-control",
	"nvidia-cuda-mps-server", "nvidia-debugdump", "nvidia-persistenced", "nvidia-modprobe",
}

// Regex patterns for NVIDIA libraries
var nvidiaLibPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^libEGL_nvidia\.so\.(.+)$`),
	regexp.MustCompile(`^libGLESv1_CM_nvidia\.so\.(.+)$`),
	regexp.MustCompile(`^libGLESv2_nvidia\.so\.(.+)$`),
	regexp.MustCompile(`^libGLX_nvidia\.so\.(.+)$`),
	regexp.MustCompile(`^libglxserver_nvidia\.so\.(.+)$`),
	regexp.MustCompile(`^libcuda\.so\.(.+)$`),
	regexp.MustCompile(`^libcudadebugger\.so\.(.+)$`),
	regexp.MustCompile(`^libnvcuvid\.so\.(.+)$`),
	regexp.MustCompile(`^libnvidia-(.+)\.so\.(.+)$`),
	regexp.MustCompile(`^libnvoptix\.so\.(.+)$`),
	regexp.MustCompile(`^libvdpau_nvidia\.so\.(.+)$`),
}

var (
	versionPattern       = regexp.MustCompile(`\.so\.[\d.]+$`)
	driverVersionPattern = regexp.MustCompile(`\.so\.(\d+\.\d+\.\d+)$`)
)

// NVIDIADriverInfo contains information about available NVIDIA drivers on the node
type NVIDIADriverInfo struct {
	DriverVersion     string
	LibraryPaths      map[string]string            // maps library basename to full path
	BinaryPaths       map[string]string            // maps binary basename to full path
	FirmwarePaths     map[string]string            // maps firmware filename to full path
	FirmwareByVersion map[string]map[string]string // version -> (filename -> full path)
}

// Global cache for NVIDIA driver detection
var nvidiaDriverCache *NVIDIADriverInfo

// IsNVIDIAMount checks if a mount path is an NVIDIA-related mount
func IsNVIDIAMount(path string) bool {
	for _, prefix := range nvidiaMountPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	lowerPath := strings.ToLower(path)
	for _, keyword := range nvidiaKeywords {
		if strings.Contains(lowerPath, keyword) {
			return true
		}
	}

	return strings.HasPrefix(path, "/dev/nvidia") ||
		strings.HasPrefix(path, "/dev/nvidiactl") ||
		strings.HasPrefix(path, "/dev/nvidia-uvm") ||
		strings.HasPrefix(path, "/dev/nvidia-modeset")
}

// isNVIDIASystemPath is an alias for IsNVIDIAMount (backward compatibility)
func isNVIDIASystemPath(path string) bool {
	return IsNVIDIAMount(path)
}

// hasOption checks if a mount option is present in the options slice
func hasOption(options []string, option string) bool {
	for _, opt := range options {
		if opt == option {
			return true
		}
	}
	return false
}

// createNVIDIAMount creates an NVIDIA mount from the dumpSpec mount information
func createNVIDIAMount(m spec.Mount) *types.Mount {
	propagation := types.MountPropagation_PROPAGATION_PRIVATE
	if hasOption(m.Options, "shared") {
		propagation = types.MountPropagation_PROPAGATION_BIDIRECTIONAL
	} else if hasOption(m.Options, "slave") {
		propagation = types.MountPropagation_PROPAGATION_HOST_TO_CONTAINER
	}

	return &types.Mount{
		ContainerPath:     m.Destination,
		HostPath:          m.Source,
		Readonly:          hasOption(m.Options, "ro"),
		RecursiveReadOnly: false,
		Propagation:       propagation,
	}
}

// detectNVIDIADrivers scans the system for available NVIDIA drivers and libraries
func detectNVIDIADrivers(ctx context.Context) (*NVIDIADriverInfo, error) {
	if nvidiaDriverCache != nil {
		log.Debugf(ctx, "Using cached NVIDIA driver information")
		return nvidiaDriverCache, nil
	}

	info := &NVIDIADriverInfo{
		LibraryPaths:      make(map[string]string),
		BinaryPaths:       make(map[string]string),
		FirmwarePaths:     make(map[string]string),
		FirmwareByVersion: make(map[string]map[string]string),
	}

	// Scan for NVIDIA libraries
	for _, searchPath := range nvidiaLibSearchPaths {
		if _, err := os.Stat(searchPath); os.IsNotExist(err) {
			continue
		}
		_ = filepath.Walk(searchPath, func(path string, fileInfo os.FileInfo, err error) error {
			if err != nil || fileInfo.IsDir() {
				return nil
			}
			filename := fileInfo.Name()
			for _, pattern := range nvidiaLibPatterns {
				if matches := pattern.FindStringSubmatch(filename); matches != nil {
					baseName := getBaseLibraryName(filename)
					if baseName != "" {
						info.LibraryPaths[baseName] = path
						if info.DriverVersion == "" && len(matches) > 1 {
							info.DriverVersion = matches[len(matches)-1]
						}
					}
					break
				}
			}
			return nil
		})
	}

	// Scan for NVIDIA binaries
	for _, searchPath := range nvidiaBinSearchPaths {
		for _, cmd := range nvidiaCommands {
			if fullPath := filepath.Join(searchPath, cmd); fileExists(fullPath) {
				info.BinaryPaths[cmd] = fullPath
			}
		}
	}

	// Scan for NVIDIA firmware blobs
	for _, fwBase := range nvidiaFirmwareSearchPaths {
		if _, err := os.Stat(fwBase); os.IsNotExist(err) {
			continue
		}
		_ = filepath.Walk(fwBase, func(path string, fileInfo os.FileInfo, err error) error {
			if err != nil || fileInfo.IsDir() || !strings.HasSuffix(fileInfo.Name(), ".bin") {
				return nil
			}
			name := fileInfo.Name()
			if rel, relErr := filepath.Rel(fwBase, path); relErr == nil {
				parts := strings.Split(rel, string(os.PathSeparator))
				if len(parts) >= 2 {
					version := parts[0]
					if _, ok := info.FirmwareByVersion[version]; !ok {
						info.FirmwareByVersion[version] = make(map[string]string)
					}
					info.FirmwareByVersion[version][name] = path
				}
			}
			info.FirmwarePaths[name] = path
			return nil
		})
	}

	log.Debugf(ctx, "Detected NVIDIA driver version: %s", info.DriverVersion)
	log.Debugf(ctx, "Found %d NVIDIA libraries and %d binaries", len(info.LibraryPaths), len(info.BinaryPaths))

	nvidiaDriverCache = info
	return info, nil
}

// getBaseLibraryName extracts the base name of an NVIDIA library without version info
func getBaseLibraryName(filename string) string {
	baseName := versionPattern.ReplaceAllString(filename, ".so")
	if strings.HasSuffix(baseName, ".so") {
		return baseName
	}
	return ""
}

// extractDriverVersion extracts the driver version from an NVIDIA library path
func extractDriverVersion(libraryPath string) string {
	if matches := driverVersionPattern.FindStringSubmatch(libraryPath); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// checkDriverCompatibility checks if checkpoint and node driver versions are compatible
func checkDriverCompatibility(ctx context.Context, checkpointPath, nodeDriverVersion string) {
	checkpointVersion := extractDriverVersion(checkpointPath)
	if checkpointVersion == "" || nodeDriverVersion == "" {
		return
	}

	if checkpointVersion != nodeDriverVersion {
		checkpointMajor := strings.Split(checkpointVersion, ".")[0]
		nodeMajor := strings.Split(nodeDriverVersion, ".")[0]

		if checkpointMajor != nodeMajor {
			log.Warnf(ctx, "NVIDIA driver major version mismatch: checkpoint=%s, node=%s - this may cause compatibility issues",
				checkpointVersion, nodeDriverVersion)
		} else {
			log.Infof(ctx, "NVIDIA driver version change detected: checkpoint=%s, node=%s - compatibility should be maintained",
				checkpointVersion, nodeDriverVersion)
		}
	}
}

// mapNVIDIAMountPath maps a checkpoint NVIDIA mount path to the corresponding path on the current node
func mapNVIDIAMountPath(ctx context.Context, checkpointPath string, driverInfo *NVIDIADriverInfo) (string, bool) {
	filename := filepath.Base(checkpointPath)

	// Try to map libraries
	if baseName := getBaseLibraryName(filename); baseName != "" {
		if nodePath, exists := driverInfo.LibraryPaths[baseName]; exists {
			log.Debugf(ctx, "Mapped NVIDIA library: %s -> %s", checkpointPath, nodePath)
			return nodePath, true
		}
		// Fuzzy matching
		basePattern := strings.TrimSuffix(baseName, ".so")
		for libName, nodePath := range driverInfo.LibraryPaths {
			if strings.HasPrefix(libName, basePattern) {
				log.Debugf(ctx, "Mapped NVIDIA library (fuzzy): %s -> %s", checkpointPath, nodePath)
				return nodePath, true
			}
		}
	}

	// Try to map binaries
	if binName := filepath.Base(checkpointPath); strings.HasPrefix(binName, "nvidia-") {
		if nodePath, exists := driverInfo.BinaryPaths[binName]; exists {
			log.Debugf(ctx, "Mapped NVIDIA binary: %s -> %s", checkpointPath, nodePath)
			return nodePath, true
		}
	}

	// Try to map firmware blobs
	if strings.Contains(checkpointPath, "/firmware/nvidia/") && strings.HasSuffix(checkpointPath, ".bin") {
		file := filepath.Base(checkpointPath)
		version := extractFirmwareVersion(checkpointPath)
		if version != "" {
			if byFile, ok := driverInfo.FirmwareByVersion[version]; ok {
				if nodePath, ok2 := byFile[file]; ok2 {
					log.Debugf(ctx, "Mapped NVIDIA firmware (same ver): %s -> %s", checkpointPath, nodePath)
					return nodePath, true
				}
			}
		}
		if nodePath, ok := driverInfo.FirmwarePaths[file]; ok {
			log.Debugf(ctx, "Mapped NVIDIA firmware (fallback): %s -> %s", checkpointPath, nodePath)
			return nodePath, true
		}
	}

	// Check if exact path exists
	if fileExists(checkpointPath) {
		log.Debugf(ctx, "NVIDIA path exists as-is on node: %s", checkpointPath)
		return checkpointPath, true
	}

	log.Debugf(ctx, "Could not map NVIDIA path: %s", checkpointPath)
	return "", false
}

// extractFirmwareVersion extracts version from firmware path
func extractFirmwareVersion(path string) string {
	parts := strings.Split(path, string(os.PathSeparator))
	for i := 0; i+2 < len(parts); i++ {
		if parts[i] == "firmware" && parts[i+1] == "nvidia" {
			return parts[i+2]
		}
	}
	return ""
}

// fileExists checks if a file exists
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
