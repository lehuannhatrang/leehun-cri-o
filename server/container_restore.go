package server

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	"github.com/containers/storage/pkg/archive"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
	kubetypes "k8s.io/kubelet/pkg/types"
	"tags.cncf.io/container-device-interface/pkg/cdi"

	"github.com/cri-o/cri-o/internal/factory/container"
	"github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/log"
	"github.com/cri-o/cri-o/internal/storage"
	"github.com/cri-o/cri-o/pkg/annotations"
	"golang.org/x/sys/unix"
)

// IsNVIDIAMount checks if a mount path is an NVIDIA-related mount
func IsNVIDIAMount(path string) bool {
	// Check exact prefixes first
	nvidiaPrefixes := []string{
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

	for _, prefix := range nvidiaPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	// Check for generic NVIDIA patterns in the path
	lowerPath := strings.ToLower(path)
	nvidiaKeywords := []string{
		"nvidia",
		"cuda",
		"nvml",
		"nvenc",
		"nvdec",
		"nvcuvid",
		"nvoptix",
		"nvcuda",
	}

	for _, keyword := range nvidiaKeywords {
		if strings.Contains(lowerPath, keyword) {
			return true
		}
	}

	// Check for GPU device paths
	if strings.HasPrefix(path, "/dev/nvidia") ||
		strings.HasPrefix(path, "/dev/nvidiactl") ||
		strings.HasPrefix(path, "/dev/nvidia-uvm") ||
		strings.HasPrefix(path, "/dev/nvidia-modeset") {
		return true
	}

	return false
}

// isNVIDIASystemPath checks if a mount path is an NVIDIA system path that's safe to skip during restore
// This function is kept for backward compatibility but now uses IsNVIDIAMount
func isNVIDIASystemPath(path string) bool {
	return IsNVIDIAMount(path)
}

// isNVIDIAGPUDevice checks if a device path is an NVIDIA GPU device node
// These devices should be managed by CDI when restoring to a different GPU
func isNVIDIAGPUDevice(path string) bool {
	// NVIDIA GPU device nodes that are GPU-specific and should be remapped via CDI
	// /dev/nvidia0, /dev/nvidia1, etc. - specific GPU devices
	// /dev/nvidiactl - NVIDIA control device
	// /dev/nvidia-uvm - Unified Virtual Memory device
	// /dev/nvidia-uvm-tools - UVM tools device
	// /dev/nvidia-modeset - modeset device
	// /dev/nvidia-caps/* - capability devices
	return strings.HasPrefix(path, "/dev/nvidia")
}

// isNVIDIAGPUIndexDevice checks if a device path is a specific NVIDIA GPU index device
// (e.g., /dev/nvidia0, /dev/nvidia1, etc.) as opposed to control devices like /dev/nvidiactl
func isNVIDIAGPUIndexDevice(path string) bool {
	if !strings.HasPrefix(path, "/dev/nvidia") {
		return false
	}
	// Check if it's a numbered GPU device like /dev/nvidia0, /dev/nvidia1
	suffix := strings.TrimPrefix(path, "/dev/nvidia")
	if len(suffix) == 0 {
		return false
	}
	// It should be a number (not -uvm, -modeset, ctl, -caps, etc.)
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// resolveCDINVIDIAGPUDevices resolves CDI device references and extracts NVIDIA GPU device host paths
// Returns a sorted list of NVIDIA GPU device host paths (e.g., ["/dev/nvidia0", "/dev/nvidia2"])
func resolveCDINVIDIAGPUDevices(ctx context.Context, cdiDevices []*types.CDIDevice) []string {
	if len(cdiDevices) == 0 {
		return nil
	}

	// Refresh CDI registry to get latest specs
	if err := cdi.Refresh(); err != nil {
		log.Warnf(ctx, "CDI registry has errors during refresh: %v", err)
	}

	// Get the default CDI cache
	cache := cdi.GetDefaultCache()
	if cache == nil {
		log.Warnf(ctx, "CDI cache not available")
		return nil
	}

	var gpuDevicePaths []string

	for _, cdiDev := range cdiDevices {
		deviceName := cdiDev.GetName()
		device := cache.GetDevice(deviceName)
		if device == nil {
			log.Debugf(ctx, "CDI device %s not found in registry", deviceName)
			continue
		}

		// Get device nodes from the CDI device's container edits
		for _, devNode := range device.ContainerEdits.DeviceNodes {
			hostPath := devNode.HostPath
			if hostPath == "" {
				hostPath = devNode.Path // HostPath defaults to Path if not set
			}

			// Check if this is an NVIDIA GPU index device
			if isNVIDIAGPUIndexDevice(hostPath) {
				log.Infof(ctx, "Found NVIDIA GPU device from CDI: %s (container: %s, host: %s)",
					deviceName, devNode.Path, hostPath)
				gpuDevicePaths = append(gpuDevicePaths, hostPath)
			}
		}
	}

	// Sort the GPU device paths for consistent ordering
	sort.Strings(gpuDevicePaths)
	return gpuDevicePaths
}

// getGPUIndexFromDevicePath extracts the GPU index from a device path like /dev/nvidia0
func getGPUIndexFromDevicePath(devicePath string) (int, error) {
	if !isNVIDIAGPUIndexDevice(devicePath) {
		return -1, fmt.Errorf("not a valid NVIDIA GPU index device: %s", devicePath)
	}
	suffix := strings.TrimPrefix(devicePath, "/dev/nvidia")
	index, err := strconv.Atoi(suffix)
	if err != nil {
		return -1, fmt.Errorf("failed to parse GPU index from %s: %w", devicePath, err)
	}
	return index, nil
}

// getGPUUUIDs retrieves GPU UUIDs by running nvidia-smi
// Returns a map of GPU index -> UUID (e.g., {0: "GPU-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"})
func getGPUUUIDs(ctx context.Context) (map[int]string, error) {
	// Run nvidia-smi to get GPU UUIDs
	// nvidia-smi --query-gpu=index,uuid --format=csv,noheader
	cmd := exec.Command("nvidia-smi", "--query-gpu=index,uuid", "--format=csv,noheader")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run nvidia-smi: %w", err)
	}

	uuids := make(map[int]string)
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// Format: "0, GPU-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			log.Warnf(ctx, "Unexpected nvidia-smi output format: %s", line)
			continue
		}
		indexStr := strings.TrimSpace(parts[0])
		uuid := strings.TrimSpace(parts[1])

		index, err := strconv.Atoi(indexStr)
		if err != nil {
			log.Warnf(ctx, "Failed to parse GPU index: %s", indexStr)
			continue
		}
		uuids[index] = uuid
		log.Debugf(ctx, "Found GPU %d with UUID: %s", index, uuid)
	}

	if len(uuids) == 0 {
		return nil, fmt.Errorf("no GPU UUIDs found from nvidia-smi")
	}

	return uuids, nil
}

// createCUDADeviceMap creates the CUDA_DEVICE_MAP environment variable value
// for cuda-checkpoint --device-map option
// Format: "GPU-oldUUID=GPU-newUUID" (for single GPU) or "GPU-old1=GPU-new1,GPU-old2=GPU-new2" (for multiple)
// createCUDADeviceMap creates a BIDIRECTIONAL GPU UUID mapping for cuda-checkpoint --device-map
// cuda-checkpoint requires ALL GPUs to be mapped, even if the application doesn't use them.
// Format: "GPU-old1=GPU-new1,GPU-new1=GPU-old1" for bidirectional mapping
// checkpointGPUPaths: GPU devices from checkpoint (e.g., ["/dev/nvidia1"])
// targetGPUPaths: GPU devices from CDI (e.g., ["/dev/nvidia0"])
func createCUDADeviceMap(ctx context.Context, checkpointGPUPaths, targetGPUPaths []string) (string, error) {
	if len(checkpointGPUPaths) == 0 || len(targetGPUPaths) == 0 {
		return "", fmt.Errorf("no GPU paths provided")
	}

	// Get all GPU UUIDs on this node
	gpuUUIDs, err := getGPUUUIDs(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get GPU UUIDs: %w", err)
	}

	// Use a map to avoid duplicate mappings
	mappingSet := make(map[string]bool)
	var mappings []string

	// Create BIDIRECTIONAL mapping for each checkpoint GPU to its corresponding target GPU
	// cuda-checkpoint requires: oldUUID=newUUID,newUUID=oldUUID for each pair
	for i, checkpointPath := range checkpointGPUPaths {
		if i >= len(targetGPUPaths) {
			log.Warnf(ctx, "No target GPU for checkpoint GPU %s", checkpointPath)
			break
		}
		targetPath := targetGPUPaths[i]

		// Get GPU indices
		checkpointIndex, err := getGPUIndexFromDevicePath(checkpointPath)
		if err != nil {
			log.Warnf(ctx, "Failed to get checkpoint GPU index: %v", err)
			continue
		}
		targetIndex, err := getGPUIndexFromDevicePath(targetPath)
		if err != nil {
			log.Warnf(ctx, "Failed to get target GPU index: %v", err)
			continue
		}

		// Skip if same GPU (no migration needed)
		if checkpointIndex == targetIndex {
			log.Infof(ctx, "Checkpoint and target are same GPU %d, no mapping needed", checkpointIndex)
			continue
		}

		// Get UUIDs for both indices
		checkpointUUID, ok := gpuUUIDs[checkpointIndex]
		if !ok {
			log.Warnf(ctx, "No UUID found for checkpoint GPU index %d - assuming cross-node restore", checkpointIndex)
			continue
		}

		targetUUID, ok := gpuUUIDs[targetIndex]
		if !ok {
			return "", fmt.Errorf("no UUID found for target GPU index %d", targetIndex)
		}

		// Create BIDIRECTIONAL mapping: old->new AND new->old
		// This is required by cuda-checkpoint for proper GPU migration
		mapping1 := fmt.Sprintf("%s=%s", checkpointUUID, targetUUID)
		mapping2 := fmt.Sprintf("%s=%s", targetUUID, checkpointUUID)

		if !mappingSet[mapping1] {
			mappingSet[mapping1] = true
			mappings = append(mappings, mapping1)
			log.Infof(ctx, "CUDA device map (forward): GPU %d (%s) -> GPU %d (%s)",
				checkpointIndex, checkpointUUID, targetIndex, targetUUID)
		}

		if !mappingSet[mapping2] {
			mappingSet[mapping2] = true
			mappings = append(mappings, mapping2)
			log.Infof(ctx, "CUDA device map (reverse): GPU %d (%s) -> GPU %d (%s)",
				targetIndex, targetUUID, checkpointIndex, checkpointUUID)
		}
	}

	if len(mappings) == 0 {
		return "", fmt.Errorf("no GPU UUID mappings created")
	}

	// Join multiple mappings with comma
	deviceMap := strings.Join(mappings, ",")
	log.Infof(ctx, "Full CUDA device map for cuda-checkpoint: %s", deviceMap)
	return deviceMap, nil
}

// createNVIDIAMount creates an NVIDIA mount from the dumpSpec mount information
func createNVIDIAMount(m spec.Mount) *types.Mount {
	// Determine propagation mode based on mount options
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
		RecursiveReadOnly: false, // NVIDIA mounts typically don't need recursive readonly
		Propagation:       propagation,
	}
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

// NVIDIADriverInfo contains information about available NVIDIA drivers on the node
type NVIDIADriverInfo struct {
	DriverVersion     string
	LibraryPaths      map[string]string            // maps library basename to full path
	BinaryPaths       map[string]string            // maps binary basename to full path
	FirmwarePaths     map[string]string            // maps firmware filename to full path
	FirmwareByVersion map[string]map[string]string // version -> (filename -> full path)
}

// Global cache for NVIDIA driver detection to avoid repeated filesystem scans
var nvidiaDriverCache *NVIDIADriverInfo

// detectNVIDIADrivers scans the system for available NVIDIA drivers and libraries
func detectNVIDIADrivers(ctx context.Context) (*NVIDIADriverInfo, error) {
	// Return cached result if available
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

	// Common NVIDIA library search paths
	libSearchPaths := []string{
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

	// Common NVIDIA binary search paths
	binSearchPaths := []string{
		"/usr/bin",
		"/bin",
		"/usr/local/bin",
	}

	// Common NVIDIA firmware search paths
	firmwareSearchPaths := []string{
		"/usr/lib/firmware/nvidia",
		"/lib/firmware/nvidia",
	}

	// Regex patterns for NVIDIA libraries
	nvidiaLibPatterns := []*regexp.Regexp{
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

	// Scan for NVIDIA libraries
	for _, searchPath := range libSearchPaths {
		if _, err := os.Stat(searchPath); os.IsNotExist(err) {
			continue
		}

		err := filepath.Walk(searchPath, func(path string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return nil // Continue on error
			}

			if fileInfo.IsDir() {
				return nil
			}

			filename := fileInfo.Name()
			for _, pattern := range nvidiaLibPatterns {
				if matches := pattern.FindStringSubmatch(filename); matches != nil {
					// Extract base library name without version
					baseName := getBaseLibraryName(filename)
					if baseName != "" {
						info.LibraryPaths[baseName] = path

						// Extract driver version from the first match
						if info.DriverVersion == "" && len(matches) > 1 {
							info.DriverVersion = matches[len(matches)-1]
						}
					}
					break
				}
			}
			return nil
		})

		if err != nil {
			log.Debugf(ctx, "Error walking path %s: %v", searchPath, err)
		}
	}

	// Scan for NVIDIA binaries
	nvidiaCommands := []string{
		"nvidia-smi",
		"nvidia-ml-py",
		"nvidia-cuda-mps-control",
		"nvidia-cuda-mps-server",
		"nvidia-debugdump",
		"nvidia-persistenced",
		"nvidia-modprobe",
	}

	for _, searchPath := range binSearchPaths {
		for _, cmd := range nvidiaCommands {
			fullPath := filepath.Join(searchPath, cmd)
			if _, err := os.Stat(fullPath); err == nil {
				info.BinaryPaths[cmd] = fullPath
			}
		}
	}

	// Scan for NVIDIA firmware blobs (e.g., gsp_tu10x.bin, gsp_ga10x.bin)
	for _, fwBase := range firmwareSearchPaths {
		if _, err := os.Stat(fwBase); os.IsNotExist(err) {
			continue
		}

		_ = filepath.Walk(fwBase, func(path string, fileInfo os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if fileInfo.IsDir() {
				return nil
			}
			name := fileInfo.Name()
			if !strings.HasSuffix(name, ".bin") {
				return nil
			}
			rel, relErr := filepath.Rel(fwBase, path)
			if relErr != nil {
				return nil
			}
			parts := strings.Split(rel, string(os.PathSeparator))
			if len(parts) >= 2 {
				version := parts[0]
				if _, ok := info.FirmwareByVersion[version]; !ok {
					info.FirmwareByVersion[version] = make(map[string]string)
				}
				info.FirmwareByVersion[version][name] = path
			}
			info.FirmwarePaths[name] = path
			return nil
		})
	}

	log.Debugf(ctx, "Detected NVIDIA driver version: %s", info.DriverVersion)
	log.Debugf(ctx, "Found %d NVIDIA libraries and %d binaries", len(info.LibraryPaths), len(info.BinaryPaths))

	// Cache the result for future use
	nvidiaDriverCache = info

	return info, nil
}

// getBaseLibraryName extracts the base name of an NVIDIA library without version info
func getBaseLibraryName(filename string) string {
	// Remove version numbers and get base name
	// e.g., "libEGL_nvidia.so.575.64.03" -> "libEGL_nvidia.so"
	versionPattern := regexp.MustCompile(`\.so\.[\d.]+$`)
	baseName := versionPattern.ReplaceAllString(filename, ".so")

	// Also handle cases like "libnvidia-ml.so.1" -> "libnvidia-ml.so"
	if strings.HasSuffix(baseName, ".so") {
		return baseName
	}

	return ""
}

// extractDriverVersion extracts the driver version from an NVIDIA library path
func extractDriverVersion(libraryPath string) string {
	// Extract version from paths like "/usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.575.64.03"
	versionPattern := regexp.MustCompile(`\.so\.(\d+\.\d+\.\d+)$`)
	if matches := versionPattern.FindStringSubmatch(libraryPath); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// checkDriverCompatibility checks if the checkpoint and node driver versions are compatible
func checkDriverCompatibility(ctx context.Context, checkpointPath, nodeDriverVersion string) {
	checkpointVersion := extractDriverVersion(checkpointPath)
	if checkpointVersion == "" || nodeDriverVersion == "" {
		return // Skip if we can't determine versions
	}

	if checkpointVersion != nodeDriverVersion {
		// Parse major version numbers for compatibility checking
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
	// Extract the base filename from the checkpoint path
	filename := filepath.Base(checkpointPath)

	// Try to map libraries first
	if baseName := getBaseLibraryName(filename); baseName != "" {
		if nodePath, exists := driverInfo.LibraryPaths[baseName]; exists {
			return nodePath, true
		}

		// Try without version-specific matching for broader compatibility
		basePattern := strings.TrimSuffix(baseName, ".so")
		for libName, nodePath := range driverInfo.LibraryPaths {
			if strings.HasPrefix(libName, basePattern) {
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

	// Try to map firmware blobs under /usr/lib/firmware/nvidia/<ver>/gsp_*.bin
	if strings.Contains(checkpointPath, "/firmware/nvidia/") && strings.HasSuffix(checkpointPath, ".bin") {
		file := filepath.Base(checkpointPath)
		// Attempt to extract version directory from checkpoint path
		version := ""
		parts := strings.Split(checkpointPath, string(os.PathSeparator))
		for i := 0; i+2 < len(parts); i++ {
			if parts[i] == "firmware" && parts[i+1] == "nvidia" {
				version = parts[i+2]
				break
			}
		}
		// Prefer same version match
		if version != "" {
			if byFile, ok := driverInfo.FirmwareByVersion[version]; ok {
				if nodePath, ok2 := byFile[file]; ok2 {
					log.Debugf(ctx, "Mapped NVIDIA firmware (same ver): %s -> %s", checkpointPath, nodePath)
					return nodePath, true
				}
			}
		}
		// Fallback: any available same filename
		if nodePath, ok := driverInfo.FirmwarePaths[file]; ok {
			log.Debugf(ctx, "Mapped NVIDIA firmware (fallback): %s -> %s", checkpointPath, nodePath)
			return nodePath, true
		}
	}

	// Check if the exact path exists on the current node (same driver version case)
	if _, err := os.Stat(checkpointPath); err == nil {
		log.Debugf(ctx, "NVIDIA path exists as-is on node: %s", checkpointPath)
		return checkpointPath, true
	}

	log.Debugf(ctx, "Could not map NVIDIA path: %s", checkpointPath)
	return "", false
}

// checkIfCheckpointOCIImage returns checks if the input refers to a checkpoint image.
// It returns the StorageImageID of the image the input resolves to, nil otherwise.
func (s *Server) checkIfCheckpointOCIImage(ctx context.Context, input string) (*storage.StorageImageID, error) {
	if input == "" {
		return nil, nil
	}

	if _, err := os.Stat(input); err == nil {
		return nil, nil
	}

	status, err := s.storageImageStatus(ctx, &types.ImageSpec{Image: input})
	if err != nil {
		return nil, err
	}

	if status == nil || status.Annotations == nil {
		return nil, nil
	}

	ann, ok := status.Annotations[annotations.CheckpointAnnotationName]
	if !ok {
		return nil, nil
	}

	log.Debugf(ctx, "Found checkpoint of container %v in %v", ann, input)

	return &status.ID, nil
}

// taken from Podman.
func (s *Server) CRImportCheckpoint(
	ctx context.Context,
	createConfig *types.ContainerConfig,
	sb *sandbox.Sandbox, sandboxUID string,
) (ctrID string, retErr error) {
	log.Infof(ctx, "=== CRImportCheckpoint called: container=%s, image=%s ===",
		createConfig.GetMetadata().GetName(), createConfig.GetImage().GetImage())
	
	var mountPoint string

	// Ensure that the image to restore the checkpoint from has been provided.
	if createConfig.GetImage() == nil || createConfig.GetImage().GetImage() == "" {
		return "", errors.New(`attribute "image" missing from container definition`)
	}

	if createConfig.GetMetadata() == nil || createConfig.GetMetadata().GetName() == "" {
		return "", errors.New(`attribute "metadata" missing from container definition`)
	}

	inputImage := createConfig.GetImage().GetImage()
	createMounts := createConfig.GetMounts()
	createAnnotations := createConfig.GetAnnotations()
	createLabels := createConfig.GetLabels()

	restoreStorageImageID, err := s.checkIfCheckpointOCIImage(ctx, inputImage)
	if err != nil {
		return "", err
	}

	var restoreArchivePath string

	if restoreStorageImageID != nil {
		systemCtx, err := s.contextForNamespace(sb.Metadata().GetNamespace())
		if err != nil {
			return "", fmt.Errorf("get context for namespace: %w", err)
		}
		// WARNING: This hard-codes an assumption that SignaturePolicyPath set specifically for the namespace is never less restrictive
		// than the default system-wide policy, i.e. that if an image is successfully pulled, it always conforms to the system-wide policy.
		if systemCtx.SignaturePolicyPath != "" {
			return "", fmt.Errorf("namespaced signature policy %s defined for pods in namespace %s; signature validation is not supported for container restore", systemCtx.SignaturePolicyPath, sb.Metadata().GetNamespace())
		}

		log.Debugf(ctx, "Restoring from oci image %s", inputImage)

		// This is not out-of-process, but it is at least out of the CRI-O codebase; containers/storage uses raw strings.
		mountPoint, err = s.ContainerServer.StorageImageServer().GetStore().MountImage(restoreStorageImageID.IDStringForOutOfProcessConsumptionOnly(), nil, "")
		if err != nil {
			return "", err
		}

		log.Debugf(ctx, "Checkpoint image %s mounted at %v\n", restoreStorageImageID, mountPoint)

		defer func() {
			// This is not out-of-process, but it is at least out of the CRI-O codebase; containers/storage uses raw strings.
			if _, err := s.ContainerServer.StorageImageServer().GetStore().UnmountImage(restoreStorageImageID.IDStringForOutOfProcessConsumptionOnly(), true); err != nil {
				log.Errorf(ctx, "Could not unmount checkpoint image %s: %q", restoreStorageImageID, err)
			}
		}()
	} else {
		// First get the container definition from the
		// tarball to a temporary directory
		archiveFile, err := os.Open(inputImage)
		if err != nil {
			return "", fmt.Errorf("failed to open checkpoint archive %s for import: %w", inputImage, err)
		}
		defer func(f *os.File) {
			if err := f.Close(); err != nil {
				log.Errorf(ctx, "Unable to close file %s: %q", f.Name(), err)
			}
		}(archiveFile)

		restoreArchivePath = inputImage
		options := &archive.TarOptions{
			// Here we only need the files config.dump and spec.dump
			ExcludePatterns: []string{
				"artifacts",
				"ctr.log",
				metadata.RootFsDiffTar,
				metadata.NetworkStatusFile,
				metadata.DeletedFilesFile,
				metadata.CheckpointDirectory,
			},
		}

		mountPoint, err = os.MkdirTemp("", "checkpoint")
		if err != nil {
			return "", err
		}

		defer func() {
			if err := os.RemoveAll(mountPoint); err != nil {
				log.Errorf(ctx, "Could not recursively remove %s: %q", mountPoint, err)
			}
		}()

		err = archive.Untar(archiveFile, mountPoint, options)
		if err != nil {
			return "", fmt.Errorf("unpacking of checkpoint archive %s failed: %w", mountPoint, err)
		}

		log.Debugf(ctx, "Unpacked checkpoint in %s", mountPoint)
	}

	// Load spec.dump from temporary directory
	dumpSpec := new(spec.Spec)
	if _, err := metadata.ReadJSONFile(dumpSpec, mountPoint, metadata.SpecDumpFile); err != nil {
		return "", fmt.Errorf("failed to read %q: %w", metadata.SpecDumpFile, err)
	}

	// Load config.dump from temporary directory
	config := new(metadata.ContainerConfig)
	if _, err := metadata.ReadJSONFile(config, mountPoint, metadata.ConfigDumpFile); err != nil {
		return "", fmt.Errorf("failed to read %q: %w", metadata.ConfigDumpFile, err)
	}

	originalAnnotations := make(map[string]string)

	if err := json.Unmarshal([]byte(dumpSpec.Annotations[annotations.Annotations]), &originalAnnotations); err != nil {
		return "", fmt.Errorf("failed to read %q: %w", annotations.Annotations, err)
	}

	if sandboxUID != "" {
		if _, ok := originalAnnotations[kubetypes.KubernetesPodUIDLabel]; ok {
			originalAnnotations[kubetypes.KubernetesPodUIDLabel] = sandboxUID
		}
	}

	if createAnnotations != nil {
		// The hash also needs to be update or Kubernetes thinks the container needs to be restarted
		_, ok1 := createAnnotations["io.kubernetes.container.hash"]
		_, ok2 := originalAnnotations["io.kubernetes.container.hash"]

		if ok1 && ok2 {
			originalAnnotations["io.kubernetes.container.hash"] = createAnnotations["io.kubernetes.container.hash"]
		}
	}

	stopMutex := sb.StopMutex()

	stopMutex.RLock()
	defer stopMutex.RUnlock()

	if sb.Stopped() {
		return "", fmt.Errorf("CreateContainer failed as the sandbox was stopped: %s", sb.ID())
	}

	ctr, err := container.New()
	if err != nil {
		return "", fmt.Errorf("failed to create container: %w", err)
	}

	// Newer checkpoints archives have RootfsImageRef set
	// and using it for the restore is more correct.
	// For the Kubernetes use case the output of 'crictl ps'
	// contains for the original container under 'IMAGE' something
	// like 'registry/path/container@sha256:123444444...'.
	// The restored container was, however, only displaying something
	// like 'registry/path/container'.
	// This had two problems, first, the output from the restored
	// container was different, but the bigger problem was, that
	// CRI-O might pull the wrong image from the registry.
	// If the container in the registry was updated (new latest tag)
	// all of a sudden the wrong base image would be downloaded.
	rootFSImage := config.RootfsImageName

	if config.RootfsImageRef != "" {
		id, err := storage.ParseStorageImageIDFromOutOfProcessData(config.RootfsImageRef)
		if err != nil {
			fmt.Printf("invalid RootfsImageRef %q: %v\n skipping\n", config.RootfsImageRef, err)
			// return "", fmt.Errorf("invalid RootfsImageRef %q: %w", config.RootfsImageRef, err)
		} else {
			// This is not quite out-of-process consumption, but types.ContainerConfig is at least
			// a cross-process API, and this value is correct in that API.
			rootFSImage = id.IDStringForOutOfProcessConsumptionOnly()
		}
	}

	containerConfig := &types.ContainerConfig{
		Metadata: &types.ContainerMetadata{
			Name:    createConfig.GetMetadata().GetName(),
			Attempt: createConfig.GetMetadata().GetAttempt(),
		},
		Image: &types.ImageSpec{
			Image: rootFSImage,
		},
		Linux: &types.LinuxContainerConfig{
			Resources:       &types.LinuxContainerResources{},
			SecurityContext: &types.LinuxContainerSecurityContext{},
		},
		Annotations: originalAnnotations,
		// The labels are nod changed or adapted. They are just taken from the CRI
		// request without any modification (in contrast to the annotations).
		Labels: createLabels,
	}

	if createConfig.GetLinux() != nil {
		if createConfig.GetLinux().GetResources() != nil {
			containerConfig.Linux.Resources = createConfig.GetLinux().GetResources()
		}

		if createConfig.GetLinux().GetSecurityContext() != nil {
			containerConfig.Linux.SecurityContext = createConfig.GetLinux().GetSecurityContext()
		}
	}

	// Handle CDI devices from createConfig for GPU migration support
	// The DRA driver (e.g., Nvidia DRA Driver) generates CDI specs that specify
	// the correct GPU device to use for restore. This is critical for GPU migration
	// where the checkpoint was on one GPU (e.g., /dev/nvidia1) but restore should
	// use a different GPU (e.g., /dev/nvidia0).
	cdiDevicesFromConfig := createConfig.GetCDIDevices()
	hasCDIDevices := len(cdiDevicesFromConfig) > 0
	log.Infof(ctx, "CDI devices check: hasCDIDevices=%v, count=%d", hasCDIDevices, len(cdiDevicesFromConfig))

	// Resolve CDI device references to get the actual NVIDIA GPU device host paths
	var cdiGPUHostPaths []string
	if hasCDIDevices {
		log.Infof(ctx, "CDI devices present for restore - resolving GPU device mappings")
		for _, cdiDev := range cdiDevicesFromConfig {
			log.Debugf(ctx, "CDI device: %s", cdiDev.GetName())
		}
		cdiGPUHostPaths = resolveCDINVIDIAGPUDevices(ctx, cdiDevicesFromConfig)
		// Deduplicate GPU host paths
		seen := make(map[string]bool)
		var uniqueGPUPaths []string
		for _, p := range cdiGPUHostPaths {
			if !seen[p] {
				seen[p] = true
				uniqueGPUPaths = append(uniqueGPUPaths, p)
			}
		}
		cdiGPUHostPaths = uniqueGPUPaths
		if len(cdiGPUHostPaths) > 0 {
			log.Infof(ctx, "Resolved %d unique NVIDIA GPU device(s) from CDI: %v", len(cdiGPUHostPaths), cdiGPUHostPaths)
		}
	}

	// Pass through ALL CDI devices for injection - CDI also provides hooks, mounts,
	// and environment variables that are essential for GPU functionality.
	// Device path remapping is handled via annotation for post-CDI processing.
	containerConfig.CDIDevices = cdiDevicesFromConfig

	// Debug: Log dumpSpec.Linux state
	if dumpSpec.Linux == nil {
		log.Debugf(ctx, "dumpSpec.Linux is nil - no checkpoint Linux config")
	} else {
		log.Debugf(ctx, "dumpSpec.Linux is present")
		if dumpSpec.Linux.Devices == nil {
			log.Debugf(ctx, "dumpSpec.Linux.Devices is nil")
		} else {
			log.Infof(ctx, "dumpSpec.Linux.Devices has %d devices", len(dumpSpec.Linux.Devices))
			for _, d := range dumpSpec.Linux.Devices {
				log.Debugf(ctx, "Checkpoint device: path=%s, type=%s, major=%d, minor=%d",
					d.Path, d.Type, d.Major, d.Minor)
			}
		}
	}

	if dumpSpec.Linux != nil {
		if dumpSpec.Linux.MaskedPaths != nil {
			containerConfig.Linux.SecurityContext.MaskedPaths = dumpSpec.Linux.MaskedPaths
		}

		if dumpSpec.Linux.ReadonlyPaths != nil {
			containerConfig.Linux.SecurityContext.ReadonlyPaths = dumpSpec.Linux.ReadonlyPaths
		}

		// Collect checkpoint GPU index devices for mapping
		var checkpointGPUDevices []string
		if dumpSpec.Linux.Devices != nil {
			for _, d := range dumpSpec.Linux.Devices {
				if isNVIDIAGPUIndexDevice(d.Path) {
					checkpointGPUDevices = append(checkpointGPUDevices, d.Path)
				}
			}
		}
		sort.Strings(checkpointGPUDevices)
		log.Infof(ctx, "Found %d checkpoint GPU index devices: %v", len(checkpointGPUDevices), checkpointGPUDevices)

		// If no GPU devices found in dumpSpec.Linux.Devices, check mounts
		if len(checkpointGPUDevices) == 0 && len(cdiGPUHostPaths) > 0 {
			log.Infof(ctx, "No GPU devices in checkpoint spec, checking mounts...")
			for _, m := range dumpSpec.Mounts {
				if isNVIDIAGPUIndexDevice(m.Destination) {
					checkpointGPUDevices = append(checkpointGPUDevices, m.Destination)
					log.Infof(ctx, "Found checkpoint GPU from mount destination: %s", m.Destination)
				}
			}
			sort.Strings(checkpointGPUDevices)
		}

		// Create GPU device rename mapping (CDI path -> checkpoint path)
		// This mapping is used AFTER CDI injection to rename device paths.
		// CDI creates /dev/nvidia0, we rename it to /dev/nvidia1 (what checkpoint expects)
		// The minor number stays the same (from CDI), only the path changes.
		gpuDeviceRenameMapping := make(map[string]string) // CDI path -> checkpoint path
		if len(cdiGPUHostPaths) > 0 && len(checkpointGPUDevices) > 0 {
			for i, cdiPath := range cdiGPUHostPaths {
				if i < len(checkpointGPUDevices) {
					checkpointPath := checkpointGPUDevices[i]
					gpuDeviceRenameMapping[cdiPath] = checkpointPath
					log.Infof(ctx, "GPU device rename mapping: CDI path %s -> checkpoint path %s",
						cdiPath, checkpointPath)
				}
			}
		}

		// CRITICAL: Modify dumpSpec.Linux.Devices to update GPU device minor numbers
		// CRIU restores device nodes from dumpSpec, so we need to update the minor numbers
		// in dumpSpec before CRIU uses it. This ensures CRIU restores devices with correct minor numbers.
		log.Infof(ctx, "GPU migration check: cdiGPUHostPaths=%d, checkpointGPUDevices=%d, dumpSpec.Linux=%v, dumpSpec.Linux.Devices=%v",
			len(cdiGPUHostPaths), len(checkpointGPUDevices), dumpSpec.Linux != nil,
			dumpSpec.Linux != nil && dumpSpec.Linux.Devices != nil)
		
		if len(cdiGPUHostPaths) > 0 && len(checkpointGPUDevices) > 0 && dumpSpec.Linux != nil && dumpSpec.Linux.Devices != nil {
			log.Infof(ctx, "Modifying dumpSpec for GPU migration: %d checkpoint devices, %d CDI devices",
				len(checkpointGPUDevices), len(cdiGPUHostPaths))

			// Get GPU indices to find target minor numbers
			for i, checkpointPath := range checkpointGPUDevices {
				if i >= len(cdiGPUHostPaths) {
					log.Warnf(ctx, "No CDI device for checkpoint device %s (index %d)", checkpointPath, i)
					break
				}
				cdiPath := cdiGPUHostPaths[i]

				// Get target GPU index from CDI path (e.g., /dev/nvidia0 -> 0)
				targetIndex, err := getGPUIndexFromDevicePath(cdiPath)
				if err != nil {
					log.Warnf(ctx, "Failed to get target GPU index from %s: %v", cdiPath, err)
					continue
				}

				// Update dumpSpec device to use target GPU's minor number
				// Target GPU minor number = GPU index (e.g., GPU-0 has minor=0)
				targetMinor := int64(targetIndex)
				found := false
				for j := range dumpSpec.Linux.Devices {
					if dumpSpec.Linux.Devices[j].Path == checkpointPath {
						oldMinor := dumpSpec.Linux.Devices[j].Minor
						dumpSpec.Linux.Devices[j].Minor = targetMinor
						log.Infof(ctx, "Updated dumpSpec device %s: minor %d -> %d (target GPU %d)",
							checkpointPath, oldMinor, targetMinor, targetIndex)
						found = true
						break
					}
				}
				if !found {
					log.Warnf(ctx, "Checkpoint device %s not found in dumpSpec.Linux.Devices", checkpointPath)
				}
			}

			// Write the modified dumpSpec back to the checkpoint directory
			// CRIU will read this modified spec during restore
			if _, err := metadata.WriteJSONFile(dumpSpec, mountPoint, metadata.SpecDumpFile); err != nil {
				log.Warnf(ctx, "Failed to write modified dumpSpec: %v (CRIU may restore with wrong device minor numbers)", err)
			} else {
				log.Infof(ctx, "Wrote modified dumpSpec with updated GPU device minor numbers")
			}

			// CRITICAL: Update device nodes in checkpoint's /dev directory
			// CRIU restores /dev from checkpoint filesystem, so we need to update
			// the actual device node files in the checkpoint to have correct minor numbers.
			// This ensures CRIU restores devices with correct minor numbers for GPU migration.
			checkpointDevDir := filepath.Join(mountPoint, "rootfs", "dev")
			for i, checkpointPath := range checkpointGPUDevices {
				if i >= len(cdiGPUHostPaths) {
					break
				}
				cdiPath := cdiGPUHostPaths[i]
				
				// Get target GPU index from CDI path (e.g., /dev/nvidia0 -> 0)
				targetIndex, err := getGPUIndexFromDevicePath(cdiPath)
				if err != nil {
					log.Warnf(ctx, "Failed to get target GPU index from %s: %v", cdiPath, err)
					continue
				}

				// Device node filename (e.g., /dev/nvidia1 -> nvidia1)
				deviceName := filepath.Base(checkpointPath)
				devicePath := filepath.Join(checkpointDevDir, deviceName)
				
				// Check if device node exists in checkpoint
				if _, err := os.Stat(devicePath); os.IsNotExist(err) {
					log.Debugf(ctx, "Device node %s does not exist in checkpoint /dev", devicePath)
					continue
				}

				// Get current device info
				var stat unix.Stat_t
				if err := unix.Stat(devicePath, &stat); err != nil {
					log.Warnf(ctx, "Failed to stat device %s: %v", devicePath, err)
					continue
				}

				// Update device node: major stays same (195 for NVIDIA), minor = target GPU index
				targetMinor := uint32(targetIndex)
				currentMajor := unix.Major(stat.Rdev)
				currentMinor := unix.Minor(stat.Rdev)
				if currentMinor != targetMinor {
					newRdev := unix.Mkdev(currentMajor, targetMinor)
					
					// Remove old device node
					if err := os.Remove(devicePath); err != nil {
						log.Warnf(ctx, "Failed to remove old device node %s: %v", devicePath, err)
						continue
					}
					
					// Create new device node with correct minor number
					if err := unix.Mknod(devicePath, unix.S_IFCHR|0666, int(newRdev)); err != nil {
						log.Warnf(ctx, "Failed to create device node %s with minor %d: %v", devicePath, targetMinor, err)
						continue
					}
					
					log.Infof(ctx, "Updated checkpoint device node %s: minor %d -> %d (target GPU %d)",
						devicePath, currentMinor, targetMinor, targetIndex)
				} else {
					log.Debugf(ctx, "Device node %s already has correct minor=%d", devicePath, targetMinor)
				}
			}

			// Also ensure /dev/nvidia0 exists in checkpoint if it's the target GPU
			// This is needed when both GPUs are claimed - both should be present
			for _, cdiPath := range cdiGPUHostPaths {
				targetIndex, err := getGPUIndexFromDevicePath(cdiPath)
				if err != nil {
					continue
				}
				deviceName := filepath.Base(cdiPath) // e.g., "nvidia0"
				devicePath := filepath.Join(checkpointDevDir, deviceName)
				
				// Check if device node exists
				if _, err := os.Stat(devicePath); os.IsNotExist(err) {
					// Create device node for target GPU
					major := uint32(195) // NVIDIA device major number
					minor := uint32(targetIndex)
					rdev := unix.Mkdev(major, minor)
					if err := unix.Mknod(devicePath, unix.S_IFCHR|0666, int(rdev)); err != nil {
						log.Debugf(ctx, "Could not create device node %s (may not be needed): %v", devicePath, err)
					} else {
						log.Infof(ctx, "Created device node %s in checkpoint: major=195, minor=%d", devicePath, minor)
					}
				}
			}

			// Log checkpoint /dev directory contents before CRIU restore
			// This shows what device nodes CRIU will restore from the checkpoint
			// checkpointDevDir is already declared above
			if entries, readErr := os.ReadDir(checkpointDevDir); readErr == nil {
				log.Infof(ctx, "=== Checkpoint /dev directory contents (before CRIU restore) ===")
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}
					devicePath := filepath.Join(checkpointDevDir, entry.Name())
					var stat unix.Stat_t
					if statErr := unix.Stat(devicePath, &stat); statErr == nil {
						if stat.Mode&unix.S_IFMT == unix.S_IFCHR || stat.Mode&unix.S_IFMT == unix.S_IFBLK {
							major := unix.Major(stat.Rdev)
							minor := unix.Minor(stat.Rdev)
							deviceType := "c"
							if stat.Mode&unix.S_IFMT == unix.S_IFBLK {
								deviceType = "b"
							}
							log.Infof(ctx, "  %s: type=%s, major=%d, minor=%d", entry.Name(), deviceType, major, minor)
						}
					}
				}
				log.Infof(ctx, "=== End of checkpoint /dev directory contents ===")
			} else {
				log.Warnf(ctx, "Failed to read checkpoint /dev directory: %v", readErr)
			}
		}

		// Store the GPU device rename mapping in annotation for post-CDI processing
		// This mapping will be applied AFTER CDI injection to rename device paths
		if len(gpuDeviceRenameMapping) > 0 {
			mappingJSON, err := json.Marshal(gpuDeviceRenameMapping)
			if err != nil {
				log.Warnf(ctx, "Failed to marshal GPU device mapping: %v", err)
			} else {
				if containerConfig.Annotations == nil {
					containerConfig.Annotations = make(map[string]string)
				}
				containerConfig.Annotations[annotations.CheckpointAnnotationGPUDeviceMapping] = string(mappingJSON)
				log.Infof(ctx, "Stored GPU device rename mapping in annotation: %s", string(mappingJSON))
			}
		}

		// Create CUDA device map for GPU migration (requires NVIDIA driver 580+)
		// This creates a UUID-based mapping that will be passed to the CRIU cuda plugin
		// via the CUDA_DEVICE_MAP environment variable for cuda-checkpoint --device-map
		if len(cdiGPUHostPaths) > 0 && len(checkpointGPUDevices) > 0 {
			// Only create mapping if checkpoint and target GPUs are different
			needsMapping := false
			for i, cdiPath := range cdiGPUHostPaths {
				if i < len(checkpointGPUDevices) && cdiPath != checkpointGPUDevices[i] {
					needsMapping = true
					break
				}
			}

			if needsMapping {
				cudaDeviceMap, err := createCUDADeviceMap(ctx, checkpointGPUDevices, cdiGPUHostPaths)
				if err != nil {
					log.Warnf(ctx, "Failed to create CUDA device map (GPU migration may not work): %v", err)
					log.Warnf(ctx, "Note: GPU migration requires NVIDIA driver 580+ and CUDA 13.0+")
				} else {
					if containerConfig.Annotations == nil {
						containerConfig.Annotations = make(map[string]string)
					}
					containerConfig.Annotations[annotations.CheckpointAnnotationCUDADeviceMap] = cudaDeviceMap
					log.Infof(ctx, "Stored CUDA device map in annotation for GPU migration: %s", cudaDeviceMap)
				}
			} else {
				log.Infof(ctx, "Checkpoint and target GPUs are the same, no CUDA device map needed")
			}
		}

		// Also add devices from checkpoint for non-GPU devices
		// GPU devices will be created by CDI and renamed via annotation
		if dumpSpec.Linux.Devices != nil {
			for _, d := range dumpSpec.Linux.Devices {
				// Skip NVIDIA GPU index devices - CDI will create them and we'll rename
				if isNVIDIAGPUIndexDevice(d.Path) {
					log.Debugf(ctx, "Skipping NVIDIA GPU device %s - will be created by CDI and renamed", d.Path)
					continue
				}
				// Add non-GPU devices
				device := &types.Device{
					ContainerPath: d.Path,
					HostPath:      d.Path,
					Permissions:   "rw",
				}
				containerConfig.Devices = append(containerConfig.Devices, device)
			}
		}
	}

	// Debug: Log final device configuration
	log.Infof(ctx, "Final containerConfig.Devices count: %d", len(containerConfig.Devices))
	for _, d := range containerConfig.Devices {
		log.Debugf(ctx, "  Device: ContainerPath=%s, HostPath=%s", d.GetContainerPath(), d.GetHostPath())
	}
	log.Infof(ctx, "Final containerConfig.CDIDevices count: %d", len(containerConfig.CDIDevices))
	for _, d := range containerConfig.CDIDevices {
		log.Debugf(ctx, "  CDI Device: %s", d.GetName())
	}

	ignoreMounts := map[string]bool{
		"/proc":              true,
		"/dev":               true,
		"/dev/pts":           true,
		"/dev/mqueue":        true,
		"/sys":               true,
		"/sys/fs/cgroup":     true,
		"/dev/shm":           true,
		"/etc/resolv.conf":   true,
		"/etc/hostname":      true,
		"/run/secrets":       true,
		"/run/.containerenv": true,
	}

	// Detect available NVIDIA drivers on the current node for mount mapping
	nvidiaDriverInfo, err := detectNVIDIADrivers(ctx)
	if err != nil {
		log.Warnf(ctx, "Failed to detect NVIDIA drivers: %v", err)
		nvidiaDriverInfo = &NVIDIADriverInfo{
			LibraryPaths: make(map[string]string),
			BinaryPaths:  make(map[string]string),
		}
	}

	if len(nvidiaDriverInfo.LibraryPaths) > 0 || len(nvidiaDriverInfo.BinaryPaths) > 0 {
		log.Infof(ctx, "Detected NVIDIA drivers on restore node - version: %s, libraries: %d, binaries: %d",
			nvidiaDriverInfo.DriverVersion, len(nvidiaDriverInfo.LibraryPaths), len(nvidiaDriverInfo.BinaryPaths))
	}

	// It is necessary to ensure that all bind mounts in the checkpoint archive are defined
	// in the create container requested coming in via the CRI. If this check would not
	// be here it would be possible to create a checkpoint archive that mounts some random
	// file/directory on the host with the user knowing as it will happen without specifying
	// it in the container definition.
	missingMount := []string{}
	nvidiaAutoMounts := []spec.Mount{}
	nvidiaMapping := make(map[string]string) // checkpoint path -> node path mapping

	for _, m := range dumpSpec.Mounts {
		// Following mounts are ignored as they might point to the
		// wrong location and if ignored the mounts will correctly
		// be setup to point to the new location.
		if ignoreMounts[m.Destination] {
			continue
		}

		// Check if this is an NVIDIA mount and handle it specially
		if IsNVIDIAMount(m.Destination) {
			log.Debugf(ctx, "Detected NVIDIA mount from checkpoint: %s -> %s", m.Source, m.Destination)

			// Check driver compatibility before mapping
			checkDriverCompatibility(ctx, m.Source, nvidiaDriverInfo.DriverVersion)

			// Try to map the checkpoint NVIDIA path to the current node's equivalent
			nodePath, mapped := mapNVIDIAMountPath(ctx, m.Source, nvidiaDriverInfo)
			if !mapped {
				// If mapping failed, check if the original path exists (same driver version case)
				if _, err := os.Stat(m.Source); err == nil {
					nodePath = m.Source
					log.Debugf(ctx, "Using original NVIDIA path as-is: %s", m.Source)
				} else {
					log.Warnf(ctx, "Could not map NVIDIA mount %s to current node, skipping (error: %v)", m.Source, err)
					continue
				}
			}

			// Verify that the mapped source exists on the host
			if stat, err := os.Stat(nodePath); err == nil {
				// Additional validation for bind mounts
				if m.Type == "bind" || m.Type == "" { // Default type is bind
					// Ensure source and destination types match (file vs directory)
					if stat.IsDir() {
						log.Debugf(ctx, "NVIDIA mount source %s is a directory", nodePath)
					} else {
						log.Debugf(ctx, "NVIDIA mount source %s is a file", nodePath)
					}
				}

				// Create a modified mount with the mapped path
				mappedMount := m
				mappedMount.Source = nodePath
				nvidiaAutoMounts = append(nvidiaAutoMounts, mappedMount)
				nvidiaMapping[m.Source] = nodePath

				// Create the mount and add it directly
				nvidiaMount := createNVIDIAMount(mappedMount)
				containerConfig.Mounts = append(containerConfig.Mounts, nvidiaMount)
				continue
			} else {
				log.Warnf(ctx, "Mapped NVIDIA mount source %s does not exist on host (error: %v), skipping", nodePath, err)
				continue
			}
		}

		mount := &types.Mount{
			ContainerPath: m.Destination,
		}

		bindMountFound := false

		for _, createMount := range createMounts {
			if createMount.GetContainerPath() != m.Destination {
				continue
			}

			bindMountFound = true
			mount.HostPath = createMount.GetHostPath()
			mount.Readonly = createMount.GetReadonly()
			mount.RecursiveReadOnly = createMount.GetRecursiveReadOnly()
			mount.Propagation = createMount.GetPropagation()

			break
		}

		if !bindMountFound {
			missingMount = append(missingMount, m.Destination)
			// If one mount is missing we can skip over any further code as we have
			// to abort the restore process anyway. Not using break to get all missing
			// mountpoints in one error message.
			continue
		}

		log.Debugf(ctx, "Adding mounts %#v", mount)
		containerConfig.Mounts = append(containerConfig.Mounts, mount)
	}

	if len(missingMount) > 0 {
		// Filter out system paths that are safe to skip
		unsafeMounts := []string{}
		for _, mount := range missingMount {
			// Allow skipping NVIDIA-related system paths
			if isNVIDIASystemPath(mount) {
				log.Debugf(ctx, "Skipping NVIDIA system mount: %s", mount)
				continue
			}
			// Add other known safe system paths here as needed
			unsafeMounts = append(unsafeMounts, mount)
		}

		if len(unsafeMounts) > 0 {
			// return "", fmt.Errorf(
			// 	"restoring %q expects following bind mounts defined (%s)",
			// 	inputImage,
			// 	strings.Join(unsafeMounts, ","),
			// )
		} else {
			log.Infof(ctx, "Skipped %d system mount paths during restore", len(missingMount))
		}
	}

	// Log information about NVIDIA mounts that were auto-detected and mounted
	if len(nvidiaAutoMounts) > 0 {
		log.Infof(ctx, "Auto-detected and mounted %d NVIDIA paths during restore:", len(nvidiaAutoMounts))

		successfulMounts := 0
		for _, mount := range nvidiaAutoMounts {
			if _, wasMapped := func() (string, bool) {
				for orig, mapped := range nvidiaMapping {
					if mapped == mount.Source {
						return orig, true
					}
				}
				return "", false
			}(); wasMapped {
				successfulMounts++
			} else {
				successfulMounts++
			}
		}

		// Log driver version information if available
		if nvidiaDriverInfo.DriverVersion != "" {
			log.Infof(ctx, "NVIDIA driver version on restore node: %s", nvidiaDriverInfo.DriverVersion)
		}

		// Log any unmapped paths for troubleshooting
		// if len(nvidiaMapping) > 0 {
		// 	log.Debugf(ctx, "NVIDIA path mappings applied:")
		// 	for orig, mapped := range nvidiaMapping {
		// 		log.Debugf(ctx, "  %s -> %s", orig, mapped)
		// 	}
		// }

		// Provide guidance if some NVIDIA mounts failed
		if successfulMounts < len(nvidiaAutoMounts) {
			log.Warnf(ctx, "Some NVIDIA mounts could not be processed. Container may have reduced GPU functionality.")
			log.Infof(ctx, "To troubleshoot NVIDIA mount issues:")
			log.Infof(ctx, "  1. Verify NVIDIA drivers are installed on the restore node")
			log.Infof(ctx, "  2. Check that NVIDIA libraries exist in standard locations")
			log.Infof(ctx, "  3. Ensure driver versions are compatible between checkpoint and restore nodes")
		} else {
			log.Infof(ctx, "All NVIDIA mounts processed successfully - GPU functionality should be preserved")
		}
	}

	sandboxConfig := &types.PodSandboxConfig{
		Metadata: &types.PodSandboxMetadata{
			Name:      sb.Metadata().GetName(),
			Uid:       sb.Metadata().GetUid(),
			Namespace: sb.Metadata().GetNamespace(),
			Attempt:   sb.Metadata().GetAttempt(),
		},
		Linux: &types.LinuxPodSandboxConfig{},
	}

	if err := ctr.SetConfig(containerConfig, sandboxConfig); err != nil {
		return "", fmt.Errorf("setting container config: %w", err)
	}

	if err := ctr.SetNameAndID(""); err != nil {
		return "", fmt.Errorf("setting container name and ID: %w", err)
	}

	if _, err = s.ReserveContainerName(ctr.ID(), ctr.Name()); err != nil {
		return "", fmt.Errorf("kubelet may be retrying requests that are timing out in CRI-O due to system load: %w", err)
	}

	defer func() {
		if retErr != nil {
			log.Infof(ctx, "RestoreCtr: releasing container name %s", ctr.Name())
			s.ReleaseContainerName(ctx, ctr.Name())
		}
	}()

	ctr.SetRestore(true)

	newContainer, err := s.createSandboxContainer(ctx, ctr, sb)
	if err != nil {
		return "", err
	}

	defer func() {
		if retErr != nil {
			log.Infof(ctx, "RestoreCtr: deleting container %s from storage", ctr.ID())

			err2 := s.ContainerServer.StorageRuntimeServer().DeleteContainer(ctx, ctr.ID())
			if err2 != nil {
				log.Warnf(ctx, "Failed to cleanup container directory: %v", err2)
			}
		}
	}()

	s.addContainer(ctx, newContainer)

	defer func() {
		if retErr != nil {
			log.Infof(ctx, "RestoreCtr: removing container %s", newContainer.ID())
			s.removeContainer(ctx, newContainer)
		}
	}()

	if err := s.ContainerServer.CtrIDIndex().Add(ctr.ID()); err != nil {
		return "", err
	}

	defer func() {
		if retErr != nil {
			log.Infof(ctx, "RestoreCtr: deleting container ID %s from idIndex", ctr.ID())

			if err := s.ContainerServer.CtrIDIndex().Delete(ctr.ID()); err != nil {
				log.Warnf(ctx, "Couldn't delete ctr id %s from idIndex", ctr.ID())
			}
		}
	}()

	newContainer.SetCreated()
	newContainer.SetRestore(true)
	newContainer.SetRestoreArchivePath(restoreArchivePath)
	newContainer.SetRestoreStorageImageID(restoreStorageImageID)
	newContainer.SetCheckpointedAt(config.CheckpointedAt)

	if isContextError(ctx.Err()) {
		log.Infof(ctx, "RestoreCtr: context was either canceled or the deadline was exceeded: %v", ctx.Err())

		return "", ctx.Err()
	}

	return ctr.ID(), nil
}
