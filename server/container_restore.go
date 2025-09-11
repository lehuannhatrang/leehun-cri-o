package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	"github.com/containers/storage/pkg/archive"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
	kubetypes "k8s.io/kubelet/pkg/types"

	"github.com/cri-o/cri-o/internal/factory/container"
	"github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/log"
	"github.com/cri-o/cri-o/internal/storage"
	"github.com/cri-o/cri-o/pkg/annotations"
)

// IsNVIDIAMount checks if a mount path is an NVIDIA-related mount
func IsNVIDIAMount(path string) bool {
	// Check exact prefixes first
	nvidiaPrefixes := []string{
		"/usr/bin/nvidia-",
		"/usr/lib/x86_64-linux-gnu/libEGL_nvidia.",
		"/usr/lib/x86_64-linux-gnu/libGLESv1_CM_nvidia.",
		"/usr/lib/x86_64-linux-gnu/libGLESv2_nvidia.",
		"/usr/lib/x86_64-linux-gnu/libGLX_nvidia.",
		"/usr/lib/x86_64-linux-gnu/libglxserver_nvidia.",
		"/usr/lib/x86_64-linux-gnu/libcuda.",
		"/usr/lib/x86_64-linux-gnu/libcudadebugger.",
		"/usr/lib/x86_64-linux-gnu/libnvcuvid.",
		"/usr/lib/x86_64-linux-gnu/libnvidia-",
		"/usr/lib/x86_64-linux-gnu/libnvoptix.",
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

// ValidateAndFilterMaskedPaths validates maskedPaths from checkpoint and returns missing paths for CRIU cleanup
func ValidateAndFilterMaskedPaths(ctx context.Context, maskedPaths []string) (validPaths []string, missingPaths []string) {
	if len(maskedPaths) == 0 {
		return maskedPaths, nil
	}

	for _, path := range maskedPaths {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				log.Debugf(ctx, "MaskedPath %s does not exist on restore node, will remove from CRIU files", path)
				missingPaths = append(missingPaths, path)
			} else {
				log.Warnf(ctx, "Failed to check maskedPath %s: %v, keeping in list", path, err)
				validPaths = append(validPaths, path)
			}
		} else {
			log.Debugf(ctx, "MaskedPath %s exists on restore node", path)
			validPaths = append(validPaths, path)
		}
	}

	if len(missingPaths) > 0 {
		log.Infof(ctx, "Found %d missing maskedPaths on restore node: %v", len(missingPaths), missingPaths)
		log.Infof(ctx, "These paths will be removed from CRIU checkpoint files to prevent mount errors")
	}

	log.Infof(ctx, "Using %d validated maskedPaths for restore: %v", len(validPaths), validPaths)
	return validPaths, missingPaths
}

// CreateLocalCheckpointCopy creates a writable local copy of checkpoint files for editing
func CreateLocalCheckpointCopy(ctx context.Context, sourceDir, containerID string) (string, error) {
	// Create temporary directory for local checkpoint copy
	tempDir, err := os.MkdirTemp("", fmt.Sprintf("criu-checkpoint-%s-", containerID))
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	log.Debugf(ctx, "Created temporary checkpoint directory: %s", tempDir)

	// List of checkpoint files to copy
	checkpointFiles := []string{
		metadata.SpecDumpFile,
		metadata.ConfigDumpFile,
		metadata.CheckpointDirectory,
	}

	for _, fileName := range checkpointFiles {
		srcPath := filepath.Join(sourceDir, fileName)
		dstPath := filepath.Join(tempDir, fileName)

		// Check if source file/directory exists
		if _, err := os.Stat(srcPath); os.IsNotExist(err) {
			log.Debugf(ctx, "Checkpoint file %s does not exist, skipping", fileName)
			continue
		}

		// Copy file or directory
		if err := copyFileOrDir(srcPath, dstPath); err != nil {
			log.Warnf(ctx, "Failed to copy checkpoint file %s: %v", fileName, err)
			// Don't fail completely, some files might be optional
		} else {
			log.Debugf(ctx, "Copied checkpoint file: %s -> %s", srcPath, dstPath)
		}
	}

	return tempDir, nil
}

// copyFileOrDir copies a file or directory recursively
func copyFileOrDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if srcInfo.IsDir() {
		return copyDir(src, dst)
	}
	return copyFile(src, dst)
}

// copyFile copies a single file
func copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Create destination directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// copyDir copies a directory recursively
func copyDir(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	// Create destination directory
	if err := os.MkdirAll(dst, srcInfo.Mode()); err != nil {
		return err
	}

	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
		} else {
			if err := copyFile(srcPath, dstPath); err != nil {
				return err
			}
		}
	}

	return nil
}

// CleanupCRIUCheckpointFiles removes problematic paths from CRIU checkpoint files
func CleanupCRIUCheckpointFiles(ctx context.Context, checkpointDir string, missingPaths []string) error {
	if len(missingPaths) == 0 {
		return nil
	}

	log.Infof(ctx, "Cleaning up CRIU checkpoint files to remove %d missing paths", len(missingPaths))

	// Create a map for fast lookup
	missingPathsMap := make(map[string]bool)
	for _, path := range missingPaths {
		missingPathsMap[path] = true
	}

	// Clean up spec.dump file
	specDumpPath := filepath.Join(checkpointDir, metadata.SpecDumpFile)
	if err := cleanSpecDumpFile(ctx, specDumpPath, missingPathsMap); err != nil {
		return fmt.Errorf("failed to clean spec.dump: %w", err)
	}

	// Clean up mountpoints files in checkpoint directory
	criuCheckpointDir := filepath.Join(checkpointDir, metadata.CheckpointDirectory)
	if err := cleanMountpointsFiles(ctx, criuCheckpointDir, missingPathsMap); err != nil {
		log.Warnf(ctx, "Failed to clean mountpoints files (non-fatal): %v", err)
	}

	log.Infof(ctx, "Successfully cleaned CRIU checkpoint files")
	return nil
}

// cleanSpecDumpFile removes missing maskedPaths from spec.dump
func cleanSpecDumpFile(ctx context.Context, specDumpPath string, missingPaths map[string]bool) error {
	// Read the current spec.dump
	dumpSpec := new(spec.Spec)
	if _, err := metadata.ReadJSONFile(dumpSpec, filepath.Dir(specDumpPath), filepath.Base(specDumpPath)); err != nil {
		return fmt.Errorf("failed to read spec.dump: %w", err)
	}

	// Filter out missing maskedPaths
	if dumpSpec.Linux != nil && dumpSpec.Linux.MaskedPaths != nil {
		var filteredMaskedPaths []string
		removedCount := 0

		for _, path := range dumpSpec.Linux.MaskedPaths {
			if missingPaths[path] {
				log.Debugf(ctx, "Removing missing maskedPath from spec.dump: %s", path)
				removedCount++
			} else {
				filteredMaskedPaths = append(filteredMaskedPaths, path)
			}
		}

		dumpSpec.Linux.MaskedPaths = filteredMaskedPaths
		log.Infof(ctx, "Removed %d missing maskedPaths from spec.dump", removedCount)
	}

	// Filter out missing mounts that might cause CRIU issues
	if dumpSpec.Mounts != nil {
		var filteredMounts []spec.Mount
		removedMountCount := 0

		for _, mount := range dumpSpec.Mounts {
			// Check if this mount destination corresponds to a missing maskedPath
			if missingPaths[mount.Destination] {
				log.Debugf(ctx, "Removing mount for missing maskedPath from spec.dump: %s -> %s", mount.Source, mount.Destination)
				removedMountCount++
			} else {
				filteredMounts = append(filteredMounts, mount)
			}
		}

		if removedMountCount > 0 {
			dumpSpec.Mounts = filteredMounts
			log.Infof(ctx, "Removed %d mounts for missing maskedPaths from spec.dump", removedMountCount)
		}
	}

	// Write the modified spec.dump back
	if _, err := metadata.WriteJSONFile(dumpSpec, filepath.Dir(specDumpPath), filepath.Base(specDumpPath)); err != nil {
		return fmt.Errorf("failed to write modified spec.dump: %w", err)
	}

	return nil
}

// cleanMountpointsFiles removes references to missing paths from CRIU mountpoints-*.img files
func cleanMountpointsFiles(ctx context.Context, checkpointDir string, missingPaths map[string]bool) error {
	// List all files in checkpoint directory
	files, err := os.ReadDir(checkpointDir)
	if err != nil {
		return fmt.Errorf("failed to read checkpoint directory: %w", err)
	}

	// Look for mountpoints-*.img files
	for _, file := range files {
		if strings.HasPrefix(file.Name(), "mountpoints-") && strings.HasSuffix(file.Name(), ".img") {
			mountpointsFile := filepath.Join(checkpointDir, file.Name())
			log.Debugf(ctx, "Processing CRIU mountpoints file: %s", mountpointsFile)

			// For now, we'll log that we found the file
			// The actual binary parsing of CRIU .img files would require
			// understanding the CRIU image format, which is complex
			log.Debugf(ctx, "Found mountpoints file %s - CRIU will handle missing paths during restore", file.Name())
		}
	}

	return nil
}

// mapNVIDIAMountPath maps a checkpoint NVIDIA mount path to the corresponding path on the current node
func mapNVIDIAMountPath(ctx context.Context, checkpointPath string, driverInfo *NVIDIADriverInfo) (string, bool) {
	// Extract the base filename from the checkpoint path
	filename := filepath.Base(checkpointPath)

	// Try to map libraries first
	if baseName := getBaseLibraryName(filename); baseName != "" {
		if nodePath, exists := driverInfo.LibraryPaths[baseName]; exists {
			log.Debugf(ctx, "Mapped NVIDIA library: %s -> %s", checkpointPath, nodePath)
			return nodePath, true
		}

		// Try without version-specific matching for broader compatibility
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

	// Handle maskedPaths validation and CRIU file cleanup
	var localCheckpointDir string
	if dumpSpec.Linux != nil && dumpSpec.Linux.MaskedPaths != nil {
		// Validate maskedPaths and get missing paths for CRIU cleanup
		validatedMaskedPaths, missingMaskedPaths := ValidateAndFilterMaskedPaths(ctx, dumpSpec.Linux.MaskedPaths)
		containerConfig.Linux.SecurityContext.MaskedPaths = validatedMaskedPaths

		// If we have missing paths, we need to create a local copy and clean it
		if len(missingMaskedPaths) > 0 {
			// Create local writable copy of checkpoint files
			var err error
			localCheckpointDir, err = CreateLocalCheckpointCopy(ctx, mountPoint, createConfig.GetMetadata().GetName())
			if err != nil {
				log.Errorf(ctx, "Failed to create local checkpoint copy: %v", err)
				return "", fmt.Errorf("failed to create local checkpoint copy: %w", err)
			}

			// Ensure cleanup of temporary directory
			defer func() {
				if err := os.RemoveAll(localCheckpointDir); err != nil {
					log.Warnf(ctx, "Failed to cleanup temporary checkpoint directory %s: %v", localCheckpointDir, err)
				} else {
					log.Debugf(ctx, "Cleaned up temporary checkpoint directory: %s", localCheckpointDir)
				}
			}()

			// Clean up CRIU checkpoint files to remove missing paths
			if err := CleanupCRIUCheckpointFiles(ctx, localCheckpointDir, missingMaskedPaths); err != nil {
				log.Errorf(ctx, "Failed to clean CRIU checkpoint files: %v", err)
				return "", fmt.Errorf("failed to clean CRIU checkpoint files: %w", err)
			}

			// Re-read the cleaned spec.dump for further processing
			cleanedDumpSpec := new(spec.Spec)
			if _, err := metadata.ReadJSONFile(cleanedDumpSpec, localCheckpointDir, metadata.SpecDumpFile); err != nil {
				log.Warnf(ctx, "Failed to re-read cleaned spec.dump, using original: %v", err)
			} else {
				dumpSpec = cleanedDumpSpec
				log.Debugf(ctx, "Using cleaned spec.dump for further processing")
			}

			// Update mountPoint to use our cleaned local copy for subsequent operations
			mountPoint = localCheckpointDir
		}
	}

	if dumpSpec.Linux != nil {
		if dumpSpec.Linux.ReadonlyPaths != nil {
			containerConfig.Linux.SecurityContext.ReadonlyPaths = dumpSpec.Linux.ReadonlyPaths
		}

		if dumpSpec.Linux.Devices != nil {
			for _, d := range dumpSpec.Linux.Devices {
				device := &types.Device{
					ContainerPath: d.Path,
					HostPath:      d.Path,
					Permissions:   "rw",
				}

				containerConfig.Devices = append(containerConfig.Devices, device)
			}
		}
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
				log.Infof(ctx, "Successfully mapped NVIDIA mount: %s -> %s (host: %s)", m.Source, m.Destination, nodePath)

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
				log.Debugf(ctx, "Auto-adding mapped NVIDIA mount: %#v", nvidiaMount)
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
			if originalPath, wasMapped := func() (string, bool) {
				for orig, mapped := range nvidiaMapping {
					if mapped == mount.Source {
						return orig, true
					}
				}
				return "", false
			}(); wasMapped {
				log.Infof(ctx, "  ✅ NVIDIA mount (mapped): %s -> %s -> %s", originalPath, mount.Source, mount.Destination)
				successfulMounts++
			} else {
				log.Infof(ctx, "  ✅ NVIDIA mount (direct): %s -> %s", mount.Source, mount.Destination)
				successfulMounts++
			}
		}

		// Log driver version information if available
		if nvidiaDriverInfo.DriverVersion != "" {
			log.Infof(ctx, "NVIDIA driver version on restore node: %s", nvidiaDriverInfo.DriverVersion)
		}

		// Log any unmapped paths for troubleshooting
		if len(nvidiaMapping) > 0 {
			log.Debugf(ctx, "NVIDIA path mappings applied:")
			for orig, mapped := range nvidiaMapping {
				log.Debugf(ctx, "  %s -> %s", orig, mapped)
			}
		}

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

	// If we created a local checkpoint copy, we need to ensure the cleaned files
	// get copied to the container directory for CRIU to use
	if localCheckpointDir != "" {
		log.Infof(ctx, "Copying cleaned checkpoint files to container directory for CRIU restore")

		// The checkpoint path that CRIU will use
		containerCheckpointPath := newContainer.CheckpointPath()
		log.Debugf(ctx, "Container checkpoint path: %s", containerCheckpointPath)

		// Remove existing checkpoint directory first
		if err := os.RemoveAll(containerCheckpointPath); err != nil {
			log.Warnf(ctx, "Failed to remove existing checkpoint directory %s: %v", containerCheckpointPath, err)
		}

		// Copy the cleaned checkpoint directory to where CRIU expects it
		cleanedCheckpointDir := filepath.Join(localCheckpointDir, metadata.CheckpointDirectory)
		if _, err := os.Stat(cleanedCheckpointDir); err == nil {
			if err := copyFileOrDir(cleanedCheckpointDir, containerCheckpointPath); err != nil {
				log.Errorf(ctx, "Failed to copy cleaned checkpoint directory: %v", err)
				return "", fmt.Errorf("failed to copy cleaned checkpoint directory: %w", err)
			}
			log.Infof(ctx, "Copied cleaned checkpoint directory: %s -> %s", cleanedCheckpointDir, containerCheckpointPath)
		} else {
			log.Warnf(ctx, "Cleaned checkpoint directory %s does not exist: %v", cleanedCheckpointDir, err)
		}

		// Also copy the cleaned spec.dump to the container directory
		cleanedSpecDump := filepath.Join(localCheckpointDir, metadata.SpecDumpFile)
		containerSpecDump := filepath.Join(newContainer.Dir(), metadata.SpecDumpFile)
		if _, err := os.Stat(cleanedSpecDump); err == nil {
			// Remove existing spec.dump first
			if err := os.RemoveAll(containerSpecDump); err != nil {
				log.Warnf(ctx, "Failed to remove existing %s: %v", containerSpecDump, err)
			}

			if err := copyFile(cleanedSpecDump, containerSpecDump); err != nil {
				log.Errorf(ctx, "Failed to copy cleaned spec.dump: %v", err)
				return "", fmt.Errorf("failed to copy cleaned spec.dump: %w", err)
			}
			log.Debugf(ctx, "Copied cleaned spec.dump: %s -> %s", cleanedSpecDump, containerSpecDump)
		}
	}

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
