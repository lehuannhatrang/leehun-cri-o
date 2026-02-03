package annotations

const (
	// CheckpointRestoreFromPathAnnotation is the pod annotation prefix that specifies a path to a checkpoint
	// tar file to restore a container from. The path can be:
	//   - A local file path on the node (e.g., /var/lib/kubelet/checkpoints/checkpoint.tar)
	//   - An S3/MinIO URL (e.g., s3://bucket/path/checkpoint.tar) - requires aws cli or mc client
	//   - A Google Cloud Storage URL (e.g., gs://bucket/path/checkpoint.tar) - requires gsutil
	//   - An HTTP/HTTPS URL (e.g., https://storage.example.com/checkpoint.tar)
	CheckpointRestoreFromPathAnnotation = "checkpoint-restore.crio.io"

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
)
