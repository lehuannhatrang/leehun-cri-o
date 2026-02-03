package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	metadata "github.com/checkpoint-restore/checkpointctl/lib"
	types "k8s.io/cri-api/pkg/apis/runtime/v1"

	"github.com/cri-o/cri-o/internal/factory/container"
	"github.com/cri-o/cri-o/internal/lib/sandbox"
	"github.com/cri-o/cri-o/internal/log"
	"github.com/cri-o/cri-o/internal/storage"
	"github.com/cri-o/cri-o/pkg/annotations"
)

// checkIfCheckpointOCIImage checks if the input refers to a checkpoint image.
// Returns the StorageImageID if found, nil otherwise.
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

	if ann, ok := status.Annotations[annotations.CheckpointAnnotationName]; ok {
		log.Debugf(ctx, "Found checkpoint of container %v in %v", ann, input)
		return &status.ID, nil
	}

	return nil, nil
}

// CRImportCheckpoint restores a container from a checkpoint image.
func (s *Server) CRImportCheckpoint(
	ctx context.Context,
	createConfig *types.ContainerConfig,
	sb *sandbox.Sandbox,
	sandboxUID string,
) (ctrID string, retErr error) {
	// Validate input
	if err := validateRestoreInput(createConfig); err != nil {
		return "", err
	}

	inputImage := createConfig.GetImage().GetImage()

	// Check if this is a checkpoint OCI image
	restoreStorageImageID, err := s.checkIfCheckpointOCIImage(ctx, inputImage)
	if err != nil {
		return "", err
	}

	// Get checkpoint mount point and restore archive path
	var mountPoint, restoreArchivePath string
	var cleanupFunc func()

	if restoreStorageImageID != nil {
		mountPoint, cleanupFunc, err = s.mountCheckpointImage(ctx, sb, restoreStorageImageID)
		if err != nil {
			return "", err
		}
		defer cleanupFunc()
	} else {
		mountPoint, cleanupFunc, err = extractCheckpointArchive(ctx, inputImage)
		if err != nil {
			return "", err
		}
		defer cleanupFunc()
		restoreArchivePath = inputImage
	}

	// Parse checkpoint metadata
	restoreCfg, err := parseCheckpointMetadata(ctx, mountPoint)
	if err != nil {
		return "", err
	}

	// Update annotations
	updateAnnotations(restoreCfg.originalAnnotations, sandboxUID, createConfig.GetAnnotations())

	// Check sandbox state
	if err := checkSandboxState(sb); err != nil {
		return "", err
	}

	// Determine rootfs image from checkpoint
	rootFSImage := s.determineRootFSImage(restoreCfg.containerConfig)

	// Build container config
	containerConfig := buildContainerConfig(createConfig, restoreCfg.dumpSpec, restoreCfg.originalAnnotations, rootFSImage)

	// Detect NVIDIA drivers and process mounts
	nvidiaDriverInfo := getNVIDIADriversWithFallback(ctx)
	mounts, missingMounts := processMounts(ctx, restoreCfg.dumpSpec, createConfig.GetMounts(), nvidiaDriverInfo)
	containerConfig.Mounts = mounts

	// Handle missing mounts
	handleMissingMounts(ctx, missingMounts, inputImage)

	// Create and setup container
	ctr, err := s.createRestoreContainer(ctx, containerConfig, sb)
	if err != nil {
		return "", err
	}

	// Register container and setup cleanup
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

	// Create sandbox container
	newContainer, err := s.createSandboxContainer(ctx, ctr, sb)
	if err != nil {
		return "", err
	}

	defer func() {
		if retErr != nil {
			log.Infof(ctx, "RestoreCtr: deleting container %s from storage", ctr.ID())
			if err2 := s.ContainerServer.StorageRuntimeServer().DeleteContainer(ctx, ctr.ID()); err2 != nil {
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

	// Finalize container state
	newContainer.SetCreated()
	newContainer.SetRestore(true)
	newContainer.SetRestoreArchivePath(restoreArchivePath)
	newContainer.SetRestoreStorageImageID(restoreStorageImageID)
	newContainer.SetCheckpointedAt(restoreCfg.containerConfig.CheckpointedAt)

	if isContextError(ctx.Err()) {
		log.Infof(ctx, "RestoreCtr: context was either canceled or the deadline was exceeded: %v", ctx.Err())
		return "", ctx.Err()
	}

	return ctr.ID(), nil
}

// CRImportCheckpointFromPath restores a container from a checkpoint tar file path.
// Supports local paths and remote URLs (S3, MinIO, GCS, HTTP/HTTPS).
func (s *Server) CRImportCheckpointFromPath(
	ctx context.Context,
	createConfig *types.ContainerConfig,
	sb *sandbox.Sandbox,
	sandboxUID string,
	checkpointPath string,
) (ctrID string, retErr error) {
	// Validate input
	if err := validateRestoreInput(createConfig); err != nil {
		return "", err
	}

	rootFSImage := createConfig.GetImage().GetImage()
	log.Infof(ctx, "Restoring container from checkpoint path %s with rootfs image %s", checkpointPath, rootFSImage)

	// Download from remote storage if needed
	actualCheckpointPath, err := s.resolveCheckpointPath(ctx, checkpointPath, createConfig, sb)
	if err != nil {
		return "", err
	}

	// Extract checkpoint archive
	mountPoint, cleanup, err := extractCheckpointArchive(ctx, actualCheckpointPath)
	if err != nil {
		return "", err
	}
	defer cleanup()

	// Parse checkpoint metadata
	restoreCfg, err := parseCheckpointMetadata(ctx, mountPoint)
	if err != nil {
		return "", err
	}

	// Update annotations
	updateAnnotations(restoreCfg.originalAnnotations, sandboxUID, createConfig.GetAnnotations())

	// Check sandbox state
	if err := checkSandboxState(sb); err != nil {
		return "", err
	}

	// Build container config using provided rootfs image
	containerConfig := buildContainerConfig(createConfig, restoreCfg.dumpSpec, restoreCfg.originalAnnotations, rootFSImage)

	// Detect NVIDIA drivers and process mounts
	nvidiaDriverInfo := getNVIDIADriversWithFallback(ctx)
	mounts, missingMounts := processMounts(ctx, restoreCfg.dumpSpec, createConfig.GetMounts(), nvidiaDriverInfo)
	containerConfig.Mounts = mounts

	// Log missing mounts (don't fail for path-based restore)
	logMissingMounts(ctx, missingMounts)

	// Create and setup container
	ctr, err := s.createRestoreContainer(ctx, containerConfig, sb)
	if err != nil {
		return "", err
	}

	// Register container and setup cleanup
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

	// Create sandbox container
	newContainer, err := s.createSandboxContainer(ctx, ctr, sb)
	if err != nil {
		return "", err
	}

	defer func() {
		if retErr != nil {
			log.Infof(ctx, "RestoreCtr: deleting container %s from storage", ctr.ID())
			if err2 := s.ContainerServer.StorageRuntimeServer().DeleteContainer(ctx, ctr.ID()); err2 != nil {
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

	// Finalize container state
	newContainer.SetCreated()
	newContainer.SetRestore(true)
	newContainer.SetRestoreArchivePath(actualCheckpointPath)
	newContainer.SetRestoreStorageImageID(nil)
	newContainer.SetCheckpointedAt(restoreCfg.containerConfig.CheckpointedAt)

	log.Infof(ctx, "Successfully prepared container %s for restore from checkpoint path %s", ctr.ID(), checkpointPath)

	if isContextError(ctx.Err()) {
		log.Infof(ctx, "RestoreCtr: context was either canceled or the deadline was exceeded: %v", ctx.Err())
		return "", ctx.Err()
	}

	return ctr.ID(), nil
}

// Helper functions

// validateRestoreInput validates the container creation config for restore
func validateRestoreInput(createConfig *types.ContainerConfig) error {
	if createConfig.GetImage() == nil || createConfig.GetImage().GetImage() == "" {
		return errors.New(`attribute "image" missing from container definition`)
	}
	if createConfig.GetMetadata() == nil || createConfig.GetMetadata().GetName() == "" {
		return errors.New(`attribute "metadata" missing from container definition`)
	}
	return nil
}

// checkSandboxState checks if the sandbox is still running
func checkSandboxState(sb *sandbox.Sandbox) error {
	stopMutex := sb.StopMutex()
	stopMutex.RLock()
	defer stopMutex.RUnlock()

	if sb.Stopped() {
		return fmt.Errorf("CreateContainer failed as the sandbox was stopped: %s", sb.ID())
	}
	return nil
}

// mountCheckpointImage mounts a checkpoint OCI image
func (s *Server) mountCheckpointImage(ctx context.Context, sb *sandbox.Sandbox, imageID *storage.StorageImageID) (string, func(), error) {
	systemCtx, err := s.contextForNamespace(sb.Metadata().GetNamespace())
	if err != nil {
		return "", nil, fmt.Errorf("get context for namespace: %w", err)
	}

	if systemCtx.SignaturePolicyPath != "" {
		return "", nil, fmt.Errorf("namespaced signature policy %s defined for pods in namespace %s; signature validation is not supported for container restore",
			systemCtx.SignaturePolicyPath, sb.Metadata().GetNamespace())
	}

	log.Debugf(ctx, "Restoring from oci image %s", imageID)

	mountPoint, err := s.ContainerServer.StorageImageServer().GetStore().MountImage(imageID.IDStringForOutOfProcessConsumptionOnly(), nil, "")
	if err != nil {
		return "", nil, err
	}

	log.Debugf(ctx, "Checkpoint image %s mounted at %v", imageID, mountPoint)

	cleanup := func() {
		if _, err := s.ContainerServer.StorageImageServer().GetStore().UnmountImage(imageID.IDStringForOutOfProcessConsumptionOnly(), true); err != nil {
			log.Errorf(ctx, "Could not unmount checkpoint image %s: %q", imageID, err)
		}
	}

	return mountPoint, cleanup, nil
}

// determineRootFSImage determines the rootfs image from checkpoint config
func (s *Server) determineRootFSImage(config *metadata.ContainerConfig) string {
	rootFSImage := config.RootfsImageName

	if config.RootfsImageRef != "" {
		id, err := storage.ParseStorageImageIDFromOutOfProcessData(config.RootfsImageRef)
		if err != nil {
			log.Warnf(context.Background(), "invalid RootfsImageRef %q: %v, using RootfsImageName", config.RootfsImageRef, err)
		} else {
			rootFSImage = id.IDStringForOutOfProcessConsumptionOnly()
		}
	}

	return rootFSImage
}

// resolveCheckpointPath resolves checkpoint path, downloading from remote if needed
func (s *Server) resolveCheckpointPath(ctx context.Context, checkpointPath string, createConfig *types.ContainerConfig, sb *sandbox.Sandbox) (string, error) {
	if !IsRemoteStorage(checkpointPath) {
		return checkpointPath, nil
	}

	log.Infof(ctx, "Checkpoint path is remote storage, downloading...")
	containerName := createConfig.GetMetadata().GetName()
	uniqueID := fmt.Sprintf("%s-%s", sb.ID()[:12], containerName)

	downloadedPath, err := DownloadCheckpointFromRemote(ctx, checkpointPath, uniqueID)
	if err != nil {
		return "", fmt.Errorf("failed to download checkpoint from remote storage: %w", err)
	}

	log.Infof(ctx, "Using downloaded checkpoint at %s", downloadedPath)
	return downloadedPath, nil
}

// createRestoreContainer creates a container for restore
func (s *Server) createRestoreContainer(ctx context.Context, containerConfig *types.ContainerConfig, sb *sandbox.Sandbox) (container.Container, error) {
	ctr, err := container.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
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
		return nil, fmt.Errorf("setting container config: %w", err)
	}

	if err := ctr.SetNameAndID(""); err != nil {
		return nil, fmt.Errorf("setting container name and ID: %w", err)
	}

	return ctr, nil
}

// handleMissingMounts handles missing mounts during restore
func handleMissingMounts(ctx context.Context, missingMounts []string, inputImage string) {
	if len(missingMounts) == 0 {
		return
	}

	unsafeMounts := filterMissingMounts(ctx, missingMounts)
	if len(unsafeMounts) > 0 {
		log.Warnf(ctx, "Restoring %q has missing bind mounts: %s", inputImage, strings.Join(unsafeMounts, ","))
	} else {
		log.Infof(ctx, "Skipped %d system mount paths during restore", len(missingMounts))
	}
}

// logMissingMounts logs missing mounts without failing
func logMissingMounts(ctx context.Context, missingMounts []string) {
	if len(missingMounts) == 0 {
		return
	}

	unsafeMounts := filterMissingMounts(ctx, missingMounts)
	if len(unsafeMounts) > 0 {
		log.Warnf(ctx, "Missing bind mounts during restore from path: %s", strings.Join(unsafeMounts, ","))
	} else {
		log.Infof(ctx, "Skipped %d system mount paths during restore from path", len(missingMounts))
	}
}
