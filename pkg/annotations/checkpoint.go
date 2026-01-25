package annotations

const (
	// CheckpointAnnotationName is used by Container Checkpoint when creating a checkpoint image to specify the
	// original human-readable name for the container.
	CheckpointAnnotationName = "io.kubernetes.cri-o.annotations.checkpoint.name"

	// CheckpointAnnotationRawImageName is used by Container Checkpoint when
	// creating a checkpoint image to specify the original unprocessed name of
	// the image used to create the container (as specified by the user).
	CheckpointAnnotationRawImageName = "io.kubernetes.cri-o.annotations.checkpoint.rawImageName"

	// CheckpointAnnotationRootfsImageID is used by Container Checkpoint when
	// creating a checkpoint image to specify the original ID of the image used
	// to create the container.
	CheckpointAnnotationRootfsImageID = "io.kubernetes.cri-o.annotations.checkpoint.rootfsImageID"

	// CheckpointAnnotationRootfsImageName is used by Container Checkpoint when
	// creating a checkpoint image to specify the original image name used to
	// create the container.
	CheckpointAnnotationRootfsImageName = "io.kubernetes.cri-o.annotations.checkpoint.rootfsImageName"

	// CheckpointAnnotationCRIOVersion is used by Container Checkpoint when
	// creating a checkpoint image to specify the version of CRI-O used on the
	// host where the checkpoint was created.
	CheckpointAnnotationCRIOVersion = "io.kubernetes.cri-o.annotations.checkpoint.cri-o.version"

	// CheckpointAnnotationCriuVersion is used by Container Checkpoint when
	// creating a checkpoint image to specify the version of CRIU used on the
	// host where the checkpoint was created.
	CheckpointAnnotationCriuVersion = "io.kubernetes.cri-o.annotations.checkpoint.criu.version"

	// CheckpointAnnotationGPUDeviceMapping is used during restore to specify
	// GPU device path mappings for GPU migration scenarios. Format is a JSON
	// object mapping CDI device paths to checkpoint device paths, e.g.,
	// {"/dev/nvidia0": "/dev/nvidia1"} means rename /dev/nvidia0 to /dev/nvidia1.
	CheckpointAnnotationGPUDeviceMapping = "io.kubernetes.cri-o.annotations.checkpoint.gpu-device-mapping"
)
