import json
import numpy as np
import os

class MinecraftChunkParser:
    @staticmethod
    def unpack_long_values(block_data, bits_per_value, total_blocks):
        """
        Custom bit-unpacking for Minecraft 1.12 chunk data
        This method is specific to the observed data format
        """
        values = []
        value_mask = (1 << bits_per_value) - 1
        
        # Filter out zero values
        block_data = [x for x in block_data if x != 0]
        
        # Bitwise unpacking with custom logic
        for long_val in block_data:
            for shift in range(0, 64, bits_per_value):
                idx = (long_val >> shift) & value_mask
                if idx != 0:
                    values.append(idx)
                    
                if len(values) >= total_blocks:
                    break
            
            if len(values) >= total_blocks:
                break
        
        # Pad or truncate to match total blocks
        values = values[:total_blocks] + [0] * max(0, total_blocks - len(values))
        
        return values

    @classmethod
    def parse_chunk_data(cls, log_entry):
        """
        Parse chunk data from different log formats
        
        :param log_entry: A log entry from the file
        :return: Tuple of (chunk_x, chunk_z, chunk_data) or None if parsing fails
        """
        try:
            # Check if it's a WebSocket log format with event and payload
            if isinstance(log_entry, list) and len(log_entry) >= 2 and log_entry[0] == "loadChunk":
                chunk_x = log_entry[1]["x"]
                chunk_z = log_entry[1]["z"]
                chunk_str = log_entry[1]["chunk"]
            # Check if it's a direct JSONL format
            elif isinstance(log_entry, dict) and "x" in log_entry and "z" in log_entry and "chunk" in log_entry:
                chunk_x = log_entry["x"]
                chunk_z = log_entry["z"]
                chunk_str = log_entry["chunk"]
            else:
                return None

            # Parse the chunk string (which is a nested JSON string)
            chunk_data = json.loads(chunk_str)
            
            return chunk_x, chunk_z, chunk_data
        
        except (json.JSONDecodeError, KeyError, IndexError) as e:
            print(f"Error parsing chunk data: {e}")
            return None

    @classmethod
    def generate_pattern_file(cls, log_file, target_block_id=112, layer_y=4, output_dir="./"):
        """
        Generate a pattern file for the chunk in the log file
        
        :param log_file: Path to the log file with chunk data
        :param target_block_id: Block ID to use for pattern generation (default 112)
        :param layer_y: Y-level to extract pattern from (default 4)
        :param output_dir: Directory to save pattern files
        :return: Path to the generated pattern file
        """
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Load and parse the log file
        with open(log_file, "r") as f:
            # Try to detect the file format
            sample_line = f.readline().strip()
            f.seek(0)  # Reset file pointer

            # Determine parsing method based on first line
            try:
                if sample_line.startswith('[') or sample_line.startswith('["loadChunk"'):
                    # Looks like a JSON log with WebSocket format
                    log_entry = json.loads(sample_line)
                else:
                    # Assume JSONL format
                    log_entry = json.loads(sample_line)
            except json.JSONDecodeError:
                print("Error parsing log file")
                return None

        # Parse chunk data
        parsed_chunk = cls.parse_chunk_data(log_entry)
        
        if not parsed_chunk:
            return None

        chunk_x, chunk_z, chunk_data = parsed_chunk

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        sections = chunk_data.get("sections", [])
        section_mask = chunk_data.get('sectionMask', 0)
        
        if not sections:
            return None

        # Determine section bit positions
        section_bit_positions = [i for i in range(16) if (section_mask >> i) & 1]

        # Prepare full chunk array
        max_section_index = 15
        full_height = (max_section_index + 1) * 16
        chunk_array = np.zeros((full_height, 16, 16), dtype=int)

        # Process each section
        for section_index, section_str in enumerate(sections):
            if section_str is None:
                continue  # skip empty sections

            # Handle nested JSON strings (may have double escaping)
            if isinstance(section_str, str):
                try:
                    section = json.loads(section_str)
                except json.JSONDecodeError:
                    # Try unescaping first
                    try:
                        section = json.loads(section_str.replace('\\"', '"'))
                    except:
                        print(f"Could not parse section {section_index}")
                        continue
            else:
                section = section_str

            # Safely get section data with fallback
            section_data_str = section.get('data', '{}')
            if isinstance(section_data_str, str):
                try:
                    section_data = json.loads(section_data_str)
                except json.JSONDecodeError:
                    # Try unescaping
                    try:
                        section_data = json.loads(section_data_str.replace('\\"', '"'))
                    except:
                        print(f"Could not parse section data for section {section_index}")
                        continue
            else:
                section_data = section_data_str

            bits_per_value = section_data.get('bitsPerValue', 4)
            block_data = section_data.get('data', [])
            palette = section.get('palette', [])

            # Unpack block values
            total_blocks = 16 * 16 * 16
            values = cls.unpack_long_values(block_data, bits_per_value, total_blocks)

            # Map palette indices to block IDs
            if palette:
                blocks = [palette[v] if v < len(palette) else palette[0] for v in values]
            else:
                blocks = values

            # Reshape to 16x16x16
            section_array = np.array(blocks).reshape(16, 16, 16)

            # Place the section in the full chunk array
            if section_index < len(section_bit_positions):
                y_offset = section_bit_positions[section_index] * 16
                chunk_array[y_offset:y_offset+16, :, :] = section_array

        # Extract specified layer
        layer = chunk_array[layer_y, :, :]

        # Create pattern for target block ID
        pattern = [[1 if b == target_block_id else 0 for b in row] for row in layer]

        # Save pattern to file
        output_filename = os.path.join(output_dir, f"pattern_chunk_{chunk_x}_{chunk_z}.txt")
        with open(output_filename, 'w') as f:
            # Write dimensions first
            f.write(f"{len(pattern)} {len(pattern[0])}\n")
            
            # Write pattern values
            for row in pattern:
                f.write(" ".join(str(v) for v in row) + "\n")

        print(f"\nChunk ({chunk_x},{chunk_z}) layer y={layer_y} pattern saved to {output_filename}")
        print("Pattern:")
        for row in pattern:
            print(",".join(str(v) for v in row))

        return output_filename