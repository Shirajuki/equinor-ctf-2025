/*
Bedrock Pattern Searching:
Written by ChromeCrusher for finding bases on 2b2t.org
Modified by SirAlexiner from scratch as a CUDA GPU Implementation with exit on first match

Compilation:
   nvcc bedrock_cuda.cu -O3 -arch=compute_86 -code=sm_86 -Xcompiler -fopenmp -lineinfo -o bedrock_cuda

*/

#include <cuda_runtime.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/time.h>

// Global constants and shared memory management
__constant__ int d_pattern[256];  // Pattern storage in constant memory
__device__ volatile int g_match_found = 0;
__device__ volatile int g_last_radius = 0;

// Utility function for wall time
static double get_wall_time() {
    struct timeval time;
    gettimeofday(&time, NULL);
    return (double)time.tv_sec + (double)time.tv_usec * .000001;
}

// Core chunk matching algorithm
__device__ bool cuda_chunk_match(const int64_t x, const int64_t z) {
    int64_t seed = (x*341873128712LL + z*132897987541LL)^0x5DEECE66DLL;

    for(int a = 0; a < 16; ++a) {
        for(int b = 0; b < 16; ++b) {
            seed = seed*709490313259657689LL + 1748772144486964054LL;
            seed = seed & ((1LL << 48LL) - 1LL);

            int expected = (4 <= (seed >> 17) % 5);
            int pattern_val = d_pattern[a*16 + b];
            
            if (expected != pattern_val) {
                return false;
            }

            seed = seed*5985058416696778513LL + -8542997297661424380LL;
        }
    }
    return true;
}

// Comprehensive kernel with global work distribution
__global__ void bedrock_search_kernel(
    const int start_radius, 
    const int end_radius,
    int* match_x, 
    int* match_z,
    int* d_debug_info 
) {
    // Get the current thread's ID
    int global_thread_id = blockIdx.x * blockDim.x + threadIdx.x;
    const int total_threads = gridDim.x * blockDim.x;

    // Distribute radii across threads
    for (int r = start_radius + global_thread_id; r <= end_radius; r += total_threads) {
        // Early stopping check - if match is already found, exit thread
        if (g_match_found) {
            return;
        }
        
        // Progress reporting, comment out to enable. Report not sequential due to threading.
        /*if (r % 1000 == 0) {
            atomicAdd((int*)&g_last_radius, 1000);
            printf("[CUDA PROGRESS] Searching radius %d (%.2f%%)\n", r, 100.0 * (r - start_radius) / (end_radius - start_radius));
            
        }*/

        // Search the north and south edges (top and bottom of the square)
        for (int i = -r; i <= r; i++) {
            // Early stopping check within nested loops
            if (g_match_found) {
                return;
            }

            // Check north edge
            if (cuda_chunk_match(i, r)) {
                if (atomicCAS((int*)&g_match_found, 0, 1) == 0) {
                    *match_x = i;
                    *match_z = r;
                    
                    // Update debug info
                    if (d_debug_info) {
                        d_debug_info[0] = i;       // Match X
                        d_debug_info[1] = r;       // Match Z
                        d_debug_info[2] = 1;       // Edge type (1 for north)
                    }
                    
                    printf("chunk: (%d, %d), real: (%d, %d)\n", i, r, i*16, r*16);
                    return;
                }
            }
            
            // Check south edge
            if (cuda_chunk_match(i, -r)) {
                if (atomicCAS((int*)&g_match_found, 0, 1) == 0) {
                    *match_x = i;
                    *match_z = -r;
                    
                    // Update debug info
                    if (d_debug_info) {
                        d_debug_info[0] = i;       // Match X
                        d_debug_info[1] = -r;      // Match Z
                        d_debug_info[2] = 2;       // Edge type (2 for south)
                    }
                    
                    printf("chunk: (%d, %d), real: (%d, %d)\n", i, -r, i*16, (-r)*16);
                    return;
                }
            }
        }

        // Search the east and west edges (excluding corners already checked)
        for (int i = -r+1; i < r; i++) {
            // Early stopping check within nested loops
            if (g_match_found) {
                return;
            }

            // Check east edge
            if (cuda_chunk_match(r, i)) {
                if (atomicCAS((int*)&g_match_found, 0, 1) == 0) {
                    *match_x = r;
                    *match_z = i;
                    
                    // Update debug info
                    if (d_debug_info) {
                        d_debug_info[0] = r;       // Match X
                        d_debug_info[1] = i;       // Match Z
                        d_debug_info[2] = 3;       // Edge type (3 for east)
                    }
                    
                    printf("chunk: (%d, %d), real: (%d, %d)\n", r, i, r*16, i*16);
                    return;
                }
            }
            
            // Check west edge
            if (cuda_chunk_match(-r, i)) {
                if (atomicCAS((int*)&g_match_found, 0, 1) == 0) {
                    *match_x = -r;
                    *match_z = i;
                    
                    // Update debug info
                    if (d_debug_info) {
                        d_debug_info[0] = -r;      // Match X
                        d_debug_info[1] = i;       // Match Z
                        d_debug_info[2] = 4;       // Edge type (4 for west)
                    }
                    
                    printf("chunk: (%d, %d), real: (%d, %d)\n", -r, i, (-r)*16, i*16);
                    return;
                }
            }
        }
    }
}

// Pattern file reader
static int* read_pattern_from_file(const char* filename, int* rows, int* cols) {
    FILE* file = fopen(filename, "r");
    if (!file) {
        fprintf(stderr, "Error opening file: %s\n", filename);
        return NULL;
    }

    // Read pattern dimensions
    if (fscanf(file, "%d %d", rows, cols) != 2) {
        fprintf(stderr, "Error reading pattern dimensions\n");
        fclose(file);
        return NULL;
    }

    // Allocate and read pattern
    int* pattern = (int*)malloc((*rows) * (*cols) * sizeof(int));
    if (!pattern) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    for (int i = 0; i < *rows; i++) {
        for (int j = 0; j < *cols; j++) {
            if (fscanf(file, "%d", &pattern[i * (*cols) + j]) != 1) {
                fprintf(stderr, "Error reading pattern values\n");
                free(pattern);
                fclose(file);
                return NULL;
            }
        }
    }

    fclose(file);
    return pattern;
}

int main(int argc, char **argv) {
    // Start timing
    double total_start_time = get_wall_time();

    // Validate input
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pattern_file>\n", argv[0]);
        return 1;
    }

    // Get device properties
    int device;
    cudaDeviceProp props;
    cudaGetDevice(&device);
    cudaGetDeviceProperties(&props, device);

    // Print device information
    printf("[CUDA DEVICE] Name: %s\n", props.name);
    printf("[CUDA DEVICE] Compute Capability: %d.%d\n", props.major, props.minor);
    printf("[CUDA DEVICE] Multiprocessors: %d\n", props.multiProcessorCount);
    printf("[CUDA DEVICE] Max Threads per Block: %d\n", props.maxThreadsPerBlock);
    printf("[CUDA DEVICE] Clock Rate: %.2f MHz\n", props.clockRate / 1000.0);
    printf("[CUDA DEVICE] Memory Clock Rate: %.2f MHz\n", props.memoryClockRate / 1000.0);

    // Read pattern from file
    int pattern_rows, pattern_cols;
    int* h_pattern = read_pattern_from_file(argv[1], &pattern_rows, &pattern_cols);
    if (!h_pattern) return 1;

    // Print pattern details
    printf("[CUDA FINDER] Loaded pattern: %d x %d\n", pattern_rows, pattern_cols);

    // Device memory allocation
    int* d_match_x;
    int* d_match_z;
    int* d_debug_info;

    cudaMalloc(&d_match_x, sizeof(int));
    cudaMalloc(&d_match_z, sizeof(int));
    cudaMalloc(&d_debug_info, 3 * sizeof(int));

    // Copy pattern to constant memory
    cudaMemcpyToSymbol(d_pattern, h_pattern, pattern_rows * pattern_cols * sizeof(int));

    // Kernel launch configuration
    const int start_radius = 0;
    const int end_radius = 1875000;
    const int threads_per_block = props.maxThreadsPerBlock;
    const int num_blocks = props.multiProcessorCount * 32;

    // Print search parameters
    printf("[CUDA FINDER] Search Parameters:\n");
    printf("  Start Radius: %d\n", start_radius);
    printf("  End Radius: %d\n", end_radius);
    printf("  Blocks: %d\n", num_blocks);
    printf("  Threads per Block: %d\n", threads_per_block);

    // Reset device memory
    int h_debug_info[3] = {0, 0, 0};
    cudaMemset((void*)&g_match_found, 0, sizeof(int));
    cudaMemset((void*)&g_last_radius, 0, sizeof(int));
    cudaMemcpy(d_debug_info, h_debug_info, 3 * sizeof(int), cudaMemcpyHostToDevice);

    // Launch kernel
    bedrock_search_kernel<<<num_blocks, threads_per_block>>>(
        start_radius, end_radius,
        d_match_x, d_match_z, 
        d_debug_info
    );

    // Check for kernel launch errors
    cudaError_t kernelLaunchError = cudaGetLastError();
    if (kernelLaunchError != cudaSuccess) {
        printf("[CUDA ERROR] Kernel launch failed: %s\n", cudaGetErrorString(kernelLaunchError));
        return 1;
    }

    // Synchronize and check for any CUDA errors
    cudaError_t syncError = cudaDeviceSynchronize();
    if (syncError != cudaSuccess) {
        printf("[CUDA ERROR] Kernel execution failed: %s\n", 
               cudaGetErrorString(syncError));
        return 1;
    }

    // Retrieve results
    int h_match_found = 0;
    cudaMemcpyFromSymbol(&h_match_found, g_match_found, sizeof(int));

    // Calculate total execution time
    double total_end_time = get_wall_time();
    printf("[CUDA FINDER] Total Execution Time: %f seconds\n", total_end_time - total_start_time);

    // Cleanup
    cudaFree(d_match_x);
    cudaFree(d_match_z);
    cudaFree(d_debug_info);
    free(h_pattern);

    return h_match_found ? 0 : 1;
}