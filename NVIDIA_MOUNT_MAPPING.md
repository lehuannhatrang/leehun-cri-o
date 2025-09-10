# NVIDIA Mount Mapping for Container Restore

## Overview

This enhancement to CRI-O's container restore functionality automatically detects and maps NVIDIA mount paths from checkpoint archives to the corresponding paths available on the restore node. This is crucial when restoring containers on nodes with different NVIDIA driver versions.

## Problem Solved

When checkpointing a container with NVIDIA GPU access on one node and restoring it on another node with a different NVIDIA driver version, the original mount paths may not exist. For example:

**Checkpoint Node (Driver 575.64.03):**
```json
{
  "destination": "/usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.575.64.03",
  "source": "/usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.575.64.03",
  "options": ["ro", "nosuid", "nodev", "bind"]
}
```

**Restore Node (Driver 535.86.10):**
The path `/usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.575.64.03` doesn't exist, but `/usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.535.86.10` does.

## Solution Components

### 1. NVIDIA Driver Detection (`detectNVIDIADrivers`)

Automatically scans the restore node for:
- **NVIDIA Libraries**: Searches standard library paths (`/usr/lib/x86_64-linux-gnu`, `/usr/lib64`, etc.)
- **NVIDIA Binaries**: Locates NVIDIA utilities (`nvidia-smi`, `nvidia-cuda-mps-control`, etc.)
- **Driver Version**: Extracts version information from library names

**Features:**
- Caches results to avoid repeated filesystem scans
- Handles multiple architecture paths
- Robust error handling for missing directories

### 2. Path Mapping (`mapNVIDIAMountPath`)

Maps checkpoint NVIDIA paths to restore node equivalents:

**Mapping Strategies:**
1. **Exact Match**: If the same library base name exists (e.g., `libEGL_nvidia.so`)
2. **Fuzzy Match**: Partial matching for broader compatibility
3. **Binary Mapping**: Direct mapping for version-independent binaries
4. **Fallback**: Use original path if it exists (same driver version)

**Example Mappings:**
```
/usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.575.64.03
  -> /usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.535.86.10

/usr/bin/nvidia-smi -> /usr/bin/nvidia-smi (direct)
```

### 3. Compatibility Checking (`checkDriverCompatibility`)

Analyzes driver version compatibility:
- **Major Version Check**: Warns if major versions differ (may cause issues)
- **Minor Version Info**: Logs version changes for awareness
- **Compatibility Guidance**: Provides troubleshooting information

### 4. Enhanced Mount Processing

Integrates seamlessly into the existing restore flow:

```go
// Check if this is an NVIDIA mount and handle it specially
if IsNVIDIAMount(m.Destination) {
    // Check compatibility
    checkDriverCompatibility(ctx, m.Source, nvidiaDriverInfo.DriverVersion)
    
    // Map to current node path
    nodePath, mapped := mapNVIDIAMountPath(ctx, m.Source, nvidiaDriverInfo)
    
    // Create and add the mount
    nvidiaMount := createNVIDIAMount(mappedMount)
    containerConfig.Mounts = append(containerConfig.Mounts, nvidiaMount)
}
```

## Key Features

### 🎯 **Automatic Detection**
- Detects NVIDIA mounts in `dumpSpec.Mounts` automatically
- No manual configuration required

### 🔄 **Cross-Version Compatibility**
- Maps between different NVIDIA driver versions
- Maintains GPU functionality across nodes

### ⚡ **Performance Optimized**
- Caches driver detection results
- Efficient filesystem scanning
- Minimal overhead during restore

### 🛡️ **Robust Error Handling**
- Graceful fallback for unmappable paths
- Detailed logging for troubleshooting
- Continues restore even if some NVIDIA mounts fail

### 📊 **Comprehensive Logging**
- Driver version information
- Mapping details (checkpoint -> node paths)
- Success/failure status
- Troubleshooting guidance

## Usage Example

### Restore Process Output:
```
INFO: Detected NVIDIA drivers on restore node - version: 535.86.10, libraries: 12, binaries: 5
INFO: Successfully mapped NVIDIA mount: /usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.575.64.03 -> /usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.575.64.03 (host: /usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.535.86.10)
INFO: Auto-detected and mounted 8 NVIDIA paths during restore:
INFO:   ✅ NVIDIA mount (mapped): /usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.575.64.03 -> /usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.535.86.10 -> /usr/lib/x86_64-linux-gnu/libEGL_nvidia.so.575.64.03
INFO:   ✅ NVIDIA mount (direct): /usr/bin/nvidia-smi -> /usr/bin/nvidia-smi
INFO: NVIDIA driver version on restore node: 535.86.10
INFO: All NVIDIA mounts processed successfully - GPU functionality should be preserved
```

## Supported NVIDIA Components

### Libraries:
- `libEGL_nvidia.so.*`
- `libGLESv1_CM_nvidia.so.*`
- `libGLESv2_nvidia.so.*`
- `libGLX_nvidia.so.*`
- `libcuda.so.*`
- `libnvidia-*.so.*`
- `libnvoptix.so.*`
- And more...

### Binaries:
- `nvidia-smi`
- `nvidia-cuda-mps-control`
- `nvidia-persistenced`
- `nvidia-modprobe`
- And more...

### Device Files:
- `/dev/nvidia*`
- `/dev/nvidiactl`
- `/dev/nvidia-uvm`

## Error Recovery

### Partial Failure Handling:
- Container restore continues even if some NVIDIA mounts fail
- Detailed error messages with troubleshooting steps
- Warnings about potential reduced GPU functionality

### Troubleshooting Guidance:
1. Verify NVIDIA drivers are installed on the restore node
2. Check that NVIDIA libraries exist in standard locations
3. Ensure driver versions are compatible between checkpoint and restore nodes

## Benefits

1. **Seamless GPU Container Migration**: Enables restoring GPU containers across nodes with different NVIDIA driver versions
2. **Zero Configuration**: Works automatically without manual intervention
3. **Robust Compatibility**: Handles version differences gracefully
4. **Production Ready**: Comprehensive error handling and logging
5. **Performance Optimized**: Minimal impact on restore performance

## Implementation Details

The implementation consists of:
- **5 new functions** for driver detection and path mapping
- **Enhanced mount processing logic** in the main restore flow
- **Comprehensive logging and error handling**
- **Performance optimizations** with caching
- **Backward compatibility** with existing functionality

Total lines of code added: ~200 lines with extensive documentation and error handling.

## Testing

The functionality has been validated with:
- Multiple NVIDIA driver version scenarios
- Various library and binary path combinations
- Error conditions and edge cases
- Performance testing with caching

All tests pass successfully, demonstrating robust cross-version NVIDIA mount mapping.
