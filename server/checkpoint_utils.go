package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"go.podman.io/storage/pkg/archive"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"
	kubetypes "k8s.io/kubelet/pkg/types"

	"github.com/cri-o/cri-o/internal/log"
	"github.com/cri-o/cri-o/internal/annotations"
)

// RemoteStorageType represents the type of remote storage for checkpoint files
type RemoteStorageType string

const (
	// StorageTypeLocal represents a local file path
	StorageTypeLocal RemoteStorageType = "local"
	// StorageTypeS3 represents an S3 or S3-compatible (MinIO) storage URL
	StorageTypeS3 RemoteStorageType = "s3"
	// StorageTypeMinio represents a MinIO storage URL with custom alias (minio://<alias>/bucket/path)
	StorageTypeMinio RemoteStorageType = "minio"
	// StorageTypeGCS represents a Google Cloud Storage URL
	StorageTypeGCS RemoteStorageType = "gs"
	// StorageTypeHTTP represents an HTTP URL
	StorageTypeHTTP RemoteStorageType = "http"
	// StorageTypeHTTPS represents an HTTPS URL
	StorageTypeHTTPS RemoteStorageType = "https"

	// checkpointDownloadDir is the directory where downloaded checkpoints are stored
	checkpointDownloadDir = "/var/lib/crio/checkpoint-downloads"

	// checkpointDownloadTimeout is the maximum time allowed for downloading a checkpoint
	checkpointDownloadTimeout = 10 * time.Minute
)

// DetectStorageType determines the storage type from the checkpoint path
func DetectStorageType(checkpointPath string) RemoteStorageType {
	lowerPath := strings.ToLower(checkpointPath)

	if strings.HasPrefix(lowerPath, "s3://") {
		return StorageTypeS3
	}
	// minio://<alias>/bucket/path format for MinIO with custom mc alias
	if strings.HasPrefix(lowerPath, "minio://") {
		return StorageTypeMinio
	}
	if strings.HasPrefix(lowerPath, "gs://") {
		return StorageTypeGCS
	}
	if strings.HasPrefix(lowerPath, "https://") {
		return StorageTypeHTTPS
	}
	if strings.HasPrefix(lowerPath, "http://") {
		return StorageTypeHTTP
	}

	return StorageTypeLocal
}

// IsRemoteStorage checks if the checkpoint path is a remote storage URL
func IsRemoteStorage(checkpointPath string) bool {
	return DetectStorageType(checkpointPath) != StorageTypeLocal
}

// DownloadCheckpointFromRemote downloads a checkpoint file from remote storage to a local file
// Returns the path to the downloaded file
// If the file already exists locally (cached), it will be reused without downloading
// The caller is responsible for cleaning up the downloaded file after use
func DownloadCheckpointFromRemote(ctx context.Context, checkpointPath string, uniqueID string) (localPath string, err error) {
	storageType := DetectStorageType(checkpointPath)

	// Create a checkpoint download directory if it doesn't exist
	if err := os.MkdirAll(checkpointDownloadDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create checkpoint download directory: %w", err)
	}

	// Extract the original filename from the remote path to enable caching
	// This allows reusing previously downloaded checkpoints
	originalFilename := filepath.Base(checkpointPath)
	// Sanitize filename to remove any URL query parameters
	if idx := strings.Index(originalFilename, "?"); idx != -1 {
		originalFilename = originalFilename[:idx]
	}
	localFilePath := filepath.Join(checkpointDownloadDir, originalFilename)

	// Check if file already exists (cached)
	if info, err := os.Stat(localFilePath); err == nil && info.Size() > 0 {
		log.Infof(ctx, "Checkpoint file already exists locally (cached): %s (%d bytes), skipping download",
			localFilePath, info.Size())
		return localFilePath, nil
	}

	log.Infof(ctx, "Downloading checkpoint from %s (storage type: %s) to %s", checkpointPath, storageType, localFilePath)

	var downloadErr error
	switch storageType {
	case StorageTypeS3:
		downloadErr = downloadFromS3(ctx, checkpointPath, localFilePath)
	case StorageTypeMinio:
		downloadErr = downloadFromMinio(ctx, checkpointPath, localFilePath)
	case StorageTypeGCS:
		downloadErr = downloadFromGCS(ctx, checkpointPath, localFilePath)
	case StorageTypeHTTP, StorageTypeHTTPS:
		downloadErr = downloadFromHTTP(ctx, checkpointPath, localFilePath)
	default:
		return "", fmt.Errorf("unsupported storage type for checkpoint path: %s", checkpointPath)
	}

	if downloadErr != nil {
		// Clean up partial download
		os.Remove(localFilePath)
		return "", fmt.Errorf("failed to download checkpoint from %s: %w", checkpointPath, downloadErr)
	}

	// Verify the downloaded file exists and has content
	info, err := os.Stat(localFilePath)
	if err != nil {
		return "", fmt.Errorf("downloaded checkpoint file not found: %w", err)
	}
	if info.Size() == 0 {
		os.Remove(localFilePath)
		return "", fmt.Errorf("downloaded checkpoint file is empty")
	}

	log.Infof(ctx, "Successfully downloaded checkpoint (%d bytes) to %s", info.Size(), localFilePath)
	return localFilePath, nil
}

// CleanupDownloadedCheckpoint removes a downloaded checkpoint file
func CleanupDownloadedCheckpoint(ctx context.Context, localPath string) {
	if localPath == "" {
		return
	}

	// Only cleanup files in the checkpoint download directory
	if !strings.HasPrefix(localPath, checkpointDownloadDir) {
		return
	}

	if err := os.Remove(localPath); err != nil && !os.IsNotExist(err) {
		log.Warnf(ctx, "Failed to cleanup downloaded checkpoint file %s: %v", localPath, err)
	} else {
		log.Debugf(ctx, "Cleaned up downloaded checkpoint file %s", localPath)
	}
}

// downloadFromS3 downloads a file from S3 or S3-compatible storage (like MinIO)
// Uses the AWS CLI or compatible tools which respect AWS_* environment variables
// For MinIO, set the following environment variables:
//   - AWS_ENDPOINT_URL: MinIO server URL (e.g., http://minio.example.com:9000)
//   - AWS_ACCESS_KEY_ID: MinIO access key
//   - AWS_SECRET_ACCESS_KEY: MinIO secret key
//
// Alternatively, for mc (MinIO client):
//   - MC_HOST_s3: MinIO connection string (e.g., http://ACCESS_KEY:SECRET_KEY@minio.example.com:9000)
func downloadFromS3(ctx context.Context, s3Path, destPath string) error {
	// Try using aws s3 cp command which handles credentials via environment or config
	// This also works with MinIO when AWS_ENDPOINT_URL is set
	cmdCtx, cancel := context.WithTimeout(ctx, checkpointDownloadTimeout)
	defer cancel()

	// First try aws cli
	cmd := exec.CommandContext(cmdCtx, "aws", "s3", "cp", s3Path, destPath)
	cmd.Env = os.Environ() // Inherit environment for AWS credentials

	output, err := cmd.CombinedOutput()
	if err == nil {
		log.Infof(ctx, "Successfully downloaded from S3 using aws cli")
		return nil
	}
	log.Warnf(ctx, "aws s3 cp failed: %v, output: %s", err, string(output))

	// Try mc (MinIO client) as fallback
	// mc uses different path format: alias/bucket/path instead of s3://bucket/path
	// Convert s3://bucket/path to s3/bucket/path for mc
	mcPath := strings.TrimPrefix(s3Path, "s3://")
	mcPath = "s3/" + mcPath

	cmd = exec.CommandContext(cmdCtx, "mc", "cp", mcPath, destPath)
	cmd.Env = os.Environ()

	output, err = cmd.CombinedOutput()
	if err == nil {
		log.Infof(ctx, "Successfully downloaded from S3/MinIO using mc client")
		return nil
	}
	log.Warnf(ctx, "mc cp failed: %v, output: %s", err, string(output))

	return fmt.Errorf("failed to download from S3 (tried aws cli and mc): path=%s, last error: %w. "+
		"For MinIO, ensure AWS_ENDPOINT_URL, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY are set", s3Path, err)
}

// downloadFromMinio downloads a file from MinIO using mc client with a custom alias
// Path format: minio://<alias>/bucket/path
// Example: minio://myminio/checkpoints-archive/checkpoint.tar
//
// Prerequisites: Configure mc alias on the node:
//
//	mc alias set <alias> http://<minio-server>:<port> <access-key> <secret-key>
func downloadFromMinio(ctx context.Context, minioPath, destPath string) error {
	cmdCtx, cancel := context.WithTimeout(ctx, checkpointDownloadTimeout)
	defer cancel()

	// Convert minio://<alias>/bucket/path to <alias>/bucket/path for mc
	mcPath := strings.TrimPrefix(minioPath, "minio://")

	log.Infof(ctx, "Downloading from MinIO using mc: %s -> %s", mcPath, destPath)

	cmd := exec.CommandContext(cmdCtx, "mc", "cp", mcPath, destPath)
	cmd.Env = os.Environ()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mc cp failed: %w, output: %s. "+
			"Ensure mc alias is configured: mc alias set <alias> <minio-url> <access-key> <secret-key>",
			err, string(output))
	}

	log.Infof(ctx, "Successfully downloaded from MinIO using mc client")
	return nil
}

// downloadFromGCS downloads a file from Google Cloud Storage
// Uses gsutil which handles authentication via GOOGLE_APPLICATION_CREDENTIALS or gcloud auth
func downloadFromGCS(ctx context.Context, gcsPath, destPath string) error {
	cmdCtx, cancel := context.WithTimeout(ctx, checkpointDownloadTimeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, "gsutil", "cp", gcsPath, destPath)
	cmd.Env = os.Environ() // Inherit environment for GCP credentials

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("gsutil cp failed: %w, output: %s", err, string(output))
	}

	log.Debugf(ctx, "Successfully downloaded from GCS using gsutil")
	return nil
}

// downloadFromHTTP downloads a file from an HTTP/HTTPS URL
func downloadFromHTTP(ctx context.Context, httpURL, destPath string) error {
	// Validate URL
	parsedURL, err := url.Parse(httpURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: checkpointDownloadTimeout,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request failed with status: %s", resp.Status)
	}

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	// Copy response body to file
	written, err := io.Copy(destFile, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to write response to file: %w", err)
	}

	log.Debugf(ctx, "Successfully downloaded %d bytes from HTTP/HTTPS", written)
	return nil
}

// =============================================================================
// Restore Helper Functions
// =============================================================================

// restoreConfig holds parsed checkpoint configuration
type restoreConfig struct {
	dumpSpec            *spec.Spec
	containerConfig     *metadata.ContainerConfig
	originalAnnotations map[string]string
	mountPoint          string
}

// ignoredMounts contains mount paths to ignore during restore
var ignoredMounts = map[string]bool{
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

// tarExcludePatterns defines files to exclude when extracting checkpoint metadata
var tarExcludePatterns = []string{
	"artifacts",
	"ctr.log",
	metadata.RootFsDiffTar,
	metadata.NetworkStatusFile,
	metadata.DeletedFilesFile,
	metadata.CheckpointDirectory,
}

// parseCheckpointMetadata loads checkpoint metadata from a mount point
func parseCheckpointMetadata(ctx context.Context, mountPoint string) (*restoreConfig, error) {
	dumpSpec := new(spec.Spec)
	if _, err := metadata.ReadJSONFile(dumpSpec, mountPoint, metadata.SpecDumpFile); err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", metadata.SpecDumpFile, err)
	}

	config := new(metadata.ContainerConfig)
	if _, err := metadata.ReadJSONFile(config, mountPoint, metadata.ConfigDumpFile); err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", metadata.ConfigDumpFile, err)
	}

	originalAnnotations := make(map[string]string)
	if dumpSpec.Annotations != nil {
		if annotationsJSON, ok := dumpSpec.Annotations[annotations.Annotations]; ok && annotationsJSON != "" {
			if err := json.Unmarshal([]byte(annotationsJSON), &originalAnnotations); err != nil {
				return nil, fmt.Errorf("failed to parse annotations: %w", err)
			}
		}
	}

	return &restoreConfig{
		dumpSpec:            dumpSpec,
		containerConfig:     config,
		originalAnnotations: originalAnnotations,
		mountPoint:          mountPoint,
	}, nil
}

// updateAnnotations updates original annotations with sandbox UID and container hash
func updateAnnotations(originalAnnotations map[string]string, sandboxUID string, createAnnotations map[string]string) {
	if sandboxUID != "" {
		if _, ok := originalAnnotations[kubetypes.KubernetesPodUIDLabel]; ok {
			originalAnnotations[kubetypes.KubernetesPodUIDLabel] = sandboxUID
		}
	}

	if createAnnotations != nil {
		_, ok1 := createAnnotations["io.kubernetes.container.hash"]
		_, ok2 := originalAnnotations["io.kubernetes.container.hash"]
		if ok1 && ok2 {
			originalAnnotations["io.kubernetes.container.hash"] = createAnnotations["io.kubernetes.container.hash"]
		}
	}
}

// buildContainerConfig creates a container config for restore
func buildContainerConfig(
	createConfig *types.ContainerConfig,
	dumpSpec *spec.Spec,
	originalAnnotations map[string]string,
	rootFSImage string,
) *types.ContainerConfig {
	containerConfig := &types.ContainerConfig{
		Metadata: &types.ContainerMetadata{
			Name:    createConfig.GetMetadata().GetName(),
			Attempt: createConfig.GetMetadata().GetAttempt(),
		},
		Image: &types.ImageSpec{
			Image:              rootFSImage,
			UserSpecifiedImage: createConfig.GetImage().GetUserSpecifiedImage(),
		},
		Linux: &types.LinuxContainerConfig{
			Resources:       &types.LinuxContainerResources{},
			SecurityContext: &types.LinuxContainerSecurityContext{},
		},
		Envs:        createConfig.GetEnvs(),
		Annotations: originalAnnotations,
		Labels:      createConfig.GetLabels(),
	}

	// Reuse CDI devices
	if len(createConfig.GetCDIDevices()) > 0 {
		containerConfig.CDIDevices = createConfig.GetCDIDevices()
	}

	// Copy Linux config
	if createConfig.GetLinux() != nil {
		if createConfig.GetLinux().GetResources() != nil {
			containerConfig.Linux.Resources = createConfig.GetLinux().GetResources()
		}
		if createConfig.GetLinux().GetSecurityContext() != nil {
			containerConfig.Linux.SecurityContext = createConfig.GetLinux().GetSecurityContext()
		}
	}

	// Apply dumpSpec Linux settings
	if dumpSpec.Linux != nil {
		if dumpSpec.Linux.MaskedPaths != nil {
			containerConfig.Linux.SecurityContext.MaskedPaths = dumpSpec.Linux.MaskedPaths
		}
		if dumpSpec.Linux.ReadonlyPaths != nil {
			containerConfig.Linux.SecurityContext.ReadonlyPaths = dumpSpec.Linux.ReadonlyPaths
		}
		// Add devices (skip NVIDIA devices - handled by CDI)
		for _, d := range dumpSpec.Linux.Devices {
			if strings.HasPrefix(d.Path, "/dev/nvidia") {
				continue
			}
			containerConfig.Devices = append(containerConfig.Devices, &types.Device{
				ContainerPath: d.Path,
				HostPath:      d.Path,
				Permissions:   "rw",
			})
		}
	}

	return containerConfig
}

// processMounts processes checkpoint mounts and returns container mounts + missing mounts
func processMounts(
	ctx context.Context,
	dumpSpec *spec.Spec,
	createMounts []*types.Mount,
	nvidiaDriverInfo *NVIDIADriverInfo,
) ([]*types.Mount, []string) {
	var mounts []*types.Mount
	var missingMounts []string

	for _, m := range dumpSpec.Mounts {
		if ignoredMounts[m.Destination] {
			continue
		}

		// Handle NVIDIA mounts
		if IsNVIDIAMount(m.Destination) {
			if mount := processNVIDIAMount(ctx, m, nvidiaDriverInfo); mount != nil {
				mounts = append(mounts, mount)
			}
			continue
		}

		// Process regular mount
		if mount := findMatchingMount(m.Destination, createMounts); mount != nil {
			log.Debugf(ctx, "Adding mount %#v", mount)
			mounts = append(mounts, mount)
		} else {
			missingMounts = append(missingMounts, m.Destination)
		}
	}

	return mounts, missingMounts
}

// processNVIDIAMount handles NVIDIA-specific mount mapping
func processNVIDIAMount(ctx context.Context, m spec.Mount, nvidiaDriverInfo *NVIDIADriverInfo) *types.Mount {
	log.Debugf(ctx, "Detected NVIDIA mount from checkpoint: %s -> %s", m.Source, m.Destination)
	checkDriverCompatibility(ctx, m.Source, nvidiaDriverInfo.DriverVersion)

	nodePath, mapped := mapNVIDIAMountPath(ctx, m.Source, nvidiaDriverInfo)
	if !mapped {
		if fileExists(m.Source) {
			nodePath = m.Source
			log.Debugf(ctx, "Using original NVIDIA path as-is: %s", m.Source)
		} else {
			log.Warnf(ctx, "Could not map NVIDIA mount %s to current node, skipping", m.Source)
			return nil
		}
	}

	if !fileExists(nodePath) {
		log.Warnf(ctx, "Mapped NVIDIA mount source %s does not exist on host, skipping", nodePath)
		return nil
	}

	log.Infof(ctx, "Successfully mapped NVIDIA mount: %s -> %s (host: %s)", m.Source, m.Destination, nodePath)
	mappedMount := m
	mappedMount.Source = nodePath
	return createNVIDIAMount(mappedMount)
}

// findMatchingMount finds a matching mount from create request
func findMatchingMount(destination string, createMounts []*types.Mount) *types.Mount {
	for _, createMount := range createMounts {
		if createMount.GetContainerPath() == destination {
			return &types.Mount{
				ContainerPath:     destination,
				HostPath:          createMount.GetHostPath(),
				Readonly:          createMount.GetReadonly(),
				RecursiveReadOnly: createMount.GetRecursiveReadOnly(),
				Propagation:       createMount.GetPropagation(),
			}
		}
	}
	return nil
}

// filterMissingMounts filters out safe-to-skip mount paths
func filterMissingMounts(ctx context.Context, missingMounts []string) []string {
	var unsafeMounts []string
	for _, mount := range missingMounts {
		if IsNVIDIAMount(mount) {
			log.Debugf(ctx, "Skipping NVIDIA system mount: %s", mount)
			continue
		}
		unsafeMounts = append(unsafeMounts, mount)
	}
	return unsafeMounts
}

// extractCheckpointArchive extracts a checkpoint tar archive to a temp directory
func extractCheckpointArchive(ctx context.Context, archivePath string) (mountPoint string, cleanup func(), err error) {
	archiveFile, err := os.Open(archivePath)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open checkpoint archive %s for import: %w", archivePath, err)
	}

	mountPoint, err = os.MkdirTemp("", "checkpoint")
	if err != nil {
		archiveFile.Close()
		return "", nil, err
	}

	cleanup = func() {
		archiveFile.Close()
		if err := os.RemoveAll(mountPoint); err != nil {
			log.Errorf(ctx, "Could not recursively remove %s: %q", mountPoint, err)
		}
	}

	options := &archive.TarOptions{ExcludePatterns: tarExcludePatterns}
	if err := archive.Untar(archiveFile, mountPoint, options); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("unpacking of checkpoint archive %s failed: %w", archivePath, err)
	}

	log.Debugf(ctx, "Unpacked checkpoint in %s", mountPoint)
	return mountPoint, cleanup, nil
}

// getNVIDIADriversWithFallback detects NVIDIA drivers with fallback to empty info
func getNVIDIADriversWithFallback(ctx context.Context) *NVIDIADriverInfo {
	info, err := detectNVIDIADrivers(ctx)
	if err != nil {
		log.Warnf(ctx, "Failed to detect NVIDIA drivers: %v", err)
		return &NVIDIADriverInfo{
			LibraryPaths: make(map[string]string),
			BinaryPaths:  make(map[string]string),
		}
	}

	if len(info.LibraryPaths) > 0 || len(info.BinaryPaths) > 0 {
		log.Infof(ctx, "Detected NVIDIA drivers - version: %s, libraries: %d, binaries: %d",
			info.DriverVersion, len(info.LibraryPaths), len(info.BinaryPaths))
	}

	return info
}
