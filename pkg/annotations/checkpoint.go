package annotations

const (
	// CheckpointRestoreFromPathAnnotation is the pod annotation prefix that specifies a path to a checkpoint
	// tar file to restore a container from. The path can be:
	//   - A local file path on the node (e.g., /var/lib/kubelet/checkpoints/checkpoint.tar)
	//   - An S3/MinIO URL (e.g., s3://bucket/path/checkpoint.tar) - requires aws cli or mc client
	//   - A Google Cloud Storage URL (e.g., gs://bucket/path/checkpoint.tar) - requires gsutil
	//   - An HTTP/HTTPS URL (e.g., https://storage.example.com/checkpoint.tar)
	//
	// When this annotation is present, the container will be restored from the checkpoint file while using
	// the container's image as the rootfs (instead of using a checkpoint image that contains both).
	// The annotation should be specified per container with the container name as suffix:
	//   checkpoint-restore.crio.io/<container-name>: "/path/to/checkpoint.tar"
	//
	// Examples:
	//   Local file:
	//     checkpoint-restore.crio.io/trainer: "/var/lib/kubelet/checkpoints/checkpoint.tar"
	//   S3/MinIO:
	//     checkpoint-restore.crio.io/trainer: "s3://my-bucket/checkpoints/checkpoint.tar"
	//   Google Cloud Storage:
	//     checkpoint-restore.crio.io/trainer: "gs://my-bucket/checkpoints/checkpoint.tar"
	//   HTTP/HTTPS:
	//     checkpoint-restore.crio.io/trainer: "https://storage.example.com/checkpoint.tar"
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
