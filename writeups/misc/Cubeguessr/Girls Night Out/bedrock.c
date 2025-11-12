/*
Bedrock Pattern Searching:
Written by ChromeCrusher for finding bases on 2b2t.org
Modified by SirAlexiner to use OpenMP for parallel processing and exit on first match

Compilation:
   gcc bedrock.c -O3 -fopenmp -o bedrock

*/

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <omp.h>

// Global variables to manage match finding
volatile int global_match_x = 0;
volatile int global_match_z = 0;
volatile int match_found = 0;

// Function to read pattern from file
int* read_pattern_from_file(const char* filename, int* rows, int* cols) {
  FILE* file = fopen(filename, "r");
  if (!file) {
      fprintf(stderr, "Error opening file: %s\n", filename);
      return NULL;
  }

  // Read dimensions
  if (fscanf(file, "%d %d", rows, cols) != 2) {
      fprintf(stderr, "Error reading pattern dimensions\n");
      fclose(file);
      return NULL;
  }

  // Allocate memory for pattern
  int* pattern = malloc((*rows) * (*cols) * sizeof(int));
  if (!pattern) {
      fprintf(stderr, "Memory allocation failed\n");
      fclose(file);
      return NULL;
  }

  // Read pattern values
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

// chunk_match function remains unchanged
int chunk_match(int * c, int64_t x, int64_t z) {
  int64_t seed = (x*341873128712LL + z*132897987541LL)^0x5DEECE66DLL;

  for(int a = 0; a < 16; ++a) {
    for(int b = 0; b < 16; ++b) {
      seed = seed*709490313259657689LL + 1748772144486964054LL;

      seed = seed & ((1LL << 48LL) - 1LL);

#ifdef WILDCARD
      if(c[a*16+b] != WILDCARD)
#endif
      if(4 <= (seed >> 17) % 5) {
        if(c[a*16+b] != 1)
          return 0;
      } else {
        if(c[a*16+b] != 0)
          return 0;
      }

      seed = seed*5985058416696778513LL + -8542997297661424380LL;
    }
  }
  return 1;
}

// Parallelized bedrock finder function
int bedrock_finder_fullpattern(int * pattern, int step, int start, int end) {
  double start_time = omp_get_wtime();

  // Use a reduction to manage the match condition
  #pragma omp parallel
  {
    #pragma omp for schedule(dynamic) nowait
    for(int r = start; r <= end; r += step) {
      // Skip if match already found
      if (match_found) continue;

      // Each thread gets its own local debugging clock
      double local_start = omp_get_wtime();

      // Search along the outer ring of the current radius
      for(int i = -r; i <= r; i++) {
        if (match_found) break;

        // Check the north and south edges
        if(chunk_match(pattern, i, r)) {
          #pragma omp critical
          {
            if (!match_found) {
              match_found = 1;
              global_match_x = i;
              global_match_z = r;
              printf("chunk: (%d, %d), real: (%d, %d)\n", i, r, i*16, r*16);
            }
          }
        }
        if(!match_found && chunk_match(pattern, i, -r)) {
          #pragma omp critical
          {
            if (!match_found) {
              match_found = 1;
              global_match_x = i;
              global_match_z = -r;
              printf("chunk: (%d, %d), real: (%d, %d)\n", i, -r, i*16, (-r)*16);
            }
          }
        }
      }

      // Search along the east and west edges (excluding already checked corners)
      for(int i = -r+1; i < r; i++) {
        if (match_found) break;

        // Check the east and west edges
        if(chunk_match(pattern, r, i)) {
          #pragma omp critical
          {
            if (!match_found) {
              match_found = 1;
              global_match_x = r;
              global_match_z = i;
              printf("chunk: (%d, %d), real: (%d, %d)\n", r, i, r*16, i*16);
            }
          }
        }
        if(!match_found && chunk_match(pattern, -r, i)) {
          #pragma omp critical
          {
            if (!match_found) {
              match_found = 1;
              global_match_x = -r;
              global_match_z = i;
              printf("chunk: (%d, %d), real: (%d, %d)\n", -r, i, (-r)*16, i*16);
            }
          }
        }
      }
      // Debug timing for each radius
      /*#pragma omp critical
      {
        printf("[CPU PROGRESS] Searching radius %d (%.2f%%)\n", r, 100.0 * (r - start) / (end - start));
      }*/
    }
  }

  printf("[CPU FINDER] Total execution time: %f seconds\n", omp_get_wtime() - start_time);

  return match_found ? 0 : 1;
}

int main(int argc, char **argv) {
  int num_threads = omp_get_max_threads();
  omp_set_num_threads(num_threads);
  printf("[CPU DEVICE] Using %d parallel threads for processing\n", num_threads);

  // defaults
  int step = 1;
  int start = 0;
  int end = 1875000;

  printf("[CPU FINDER] Search Parameters:\n");
  printf("  Start Radius: %d\n", start);
  printf("  End Radius: %d\n", end);

  // Check if pattern file is provided
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <pattern_file>\n", argv[0]);
    return 1;
  }

  // Read pattern from file
  int pattern_rows, pattern_cols;
  int* pattern = read_pattern_from_file(argv[1], &pattern_rows, &pattern_cols);

  if (!pattern) {
      fprintf(stderr, "Failed to read pattern from file\n");
      return 1;
  }

  // Verify pattern dimensions
  printf("[CPU FINDER] Loaded pattern: %d x %d\n", pattern_rows, pattern_cols);

  // Run the search and return its result
  int result = bedrock_finder_fullpattern(pattern, step, start, end);

  // Free allocated memory
  free(pattern);

  return result;
}

