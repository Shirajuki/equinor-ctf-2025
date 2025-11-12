import math
import socketio
import json
import subprocess
import os
import time
import threading
import re
import logging

from minecraft_chunk_parser import MinecraftChunkParser

# Configure logging
logging.basicConfig(
    level=logging.DEBUG, 
    format='%(asctime)s - %(levelname)s: %(message)s',
    handlers=[
        logging.FileHandler('coordinate_finder_debug.log'),
        logging.StreamHandler()
    ]
)
# Define Server URL and Bedrock Search Variant
# Also Define Log and JSONL file names
SERVER = "https://girlsnightout-REDACTED-web.ept.gg"
OUTFILE = "chunk_data.jsonl"
BEDROCK_PATH = "./bedrock_cuda" #Change between GPU (CUDA) or CPU
FLAG_FILE = "flag.txt"
DEBUG_OUTPUT_FILE = "bedrock_debug_output.json"

# Custom Chunk Coordinate Finder
# Made to solve the CubeGuessr Challenge at EPT CTF 2025
class ChunkCoordinateFinder:
    def __init__(self, use_bedrock_for_all_rounds=False):
        self.sio = socketio.Client()
        self.setup_socket_events()
        
        # Bedrock pattern search configuration
        self.use_bedrock_for_all_rounds = use_bedrock_for_all_rounds
        self.processing_chunk = False
        
        # Exploit tracking
        self.round = 0
        self.previous_correct_x = None
        self.previous_correct_z = None
        self.position_offset_x = None
        self.position_offset_z = None
        self.first_position_after_submit = True
        
        # Debugging tracking
        self.bedrock_match_data = None
        self.last_position_data = None
        
        # Coordinate tracking
        self.base_coords = None
        self.in_chunk_coords = None
        self.position_received_event = threading.Event()

    def manual_guess_confirmation(self, x, z, bedrock_match_data=None, position_data=None):
        """
        Provides an interactive terminal confirmation for submitting coordinates
        """
        print("\n[*] COORDINATE SUBMISSION CONFIRMATION [*]")
        print(f"Proposed Coordinates: X = {x}, Z = {z}")
        print(f"Radius from (0, 0): {math.sqrt(x**2 + z**2):,.0f}")
        
        # Display Bedrock Match Data if available
        if bedrock_match_data:
            print("\n[*] Bedrock Match Details:")
            print(json.dumps(bedrock_match_data, indent=2))
        
        # Display Last Position Data if available
        if position_data:
            print("\n[*] Last Position Data:")
            print(json.dumps(position_data, indent=2))
        
        # Prompt for confirmation
        while True:
            confirm = input("\nConfirm submission? (y/n/edit): ").lower().strip()
            
            if confirm == 'y':
                # Submit the guess as originally planned
                guess_data = {"x": math.floor(x), "z": math.floor(z)}
                print(f"[*] Submitting guess: {guess_data}")
                self.sio.emit('submit', guess_data)
                break
            
            elif confirm == 'n':
                print("[!] Guess submission cancelled.")
                break
            
            elif confirm == 'edit':
                try:
                    new_x = float(input("Enter new X coordinate: "))
                    new_z = float(input("Enter new Z coordinate: "))
                    x, z = new_x, new_z
                    print(f"[*] Updated coordinates: X = {x}, Z = {z}")
                except ValueError:
                    print("[!] Invalid coordinate input. Please enter numeric values.")
            
            else:
                print("[!] Invalid input. Please enter 'y', 'n', or 'edit'.")

    def parse_bedrock_output(self, stdout):
        """
        Parse output from bedrock finder executable
        """
        logging.debug("Parsing Bedrock output")
        
        # Regex pattern for match found line
        match_pattern = re.compile(r'chunk: \((-?\d+), (-?\d+)\), real: \((-?\d+), (-?\d+)\)')
        
        match_data = {
            'chunk_coords': None,
            'world_coords': None,
        }

        # Extract coordinates
        match_found = match_pattern.search(stdout)
        if match_found:
            chunk_x, chunk_z, world_x, world_z = map(int, match_found.groups())
            match_data['chunk_coords'] = (chunk_x, chunk_z)
            match_data['world_coords'] = (world_x, world_z)
            
        # Store match data for potential manual review
        self.bedrock_match_data = match_data

        # Log debug information
        logging.debug(f"Parsed Bedrock Match Data: {json.dumps(match_data, indent=2)}")
        
        # Save full debug output for potential later analysis
        with open(DEBUG_OUTPUT_FILE, 'w') as f:
            json.dump(match_data, f, indent=2)

        # Return coordinates if found
        if match_data['world_coords']:
            logging.info(f"Found coordinates: {match_data['world_coords']}")
            return match_data['world_coords'][0], match_data['world_coords'][1]
        
        logging.warning("No coordinates found in Bedrock output")
        return None, None

    def setup_socket_events(self):
        @self.sio.event
        def connect():
            print("[*] Connected to server")
            
        @self.sio.on("position")
        def on_position(data):
            try:
                pos = data.get('pos', {})
                x = pos.get('x')
                z = pos.get('z')
                
                # Store last position data for manual review
                self.last_position_data = data
                
                # Check if the position is within chunk coordinates (0-16) and the we do not have an in chunk position stored
                if x is not None and z is not None and 0 <= x <= 16 and 0 <= z <= 16 and self.in_chunk_coords is None:
                    self.in_chunk_coords = (x, z)
                    print("[*] Stored New In-Chunk Position:")
                    print(f"    In-Chunk Position: X = {x}, Z = {z}")
                    
                    # If we have stored base coordinates from bedrock search, 
                    # now we can complete the guess confirmation
                    if self.base_coords is not None:
                        x, z = self.base_coords
                        self.manual_guess_confirmation(
                            x + self.in_chunk_coords[0], 
                            z + self.in_chunk_coords[1], 
                            self.bedrock_match_data, 
                            None
                        )
                        # Reset base_coords and in_chunk coords after using
                        self.base_coords = None
                        self.in_chunk_coords = None
                    
                    return
                
                # Determine which method to use based on configuration
                if (not self.use_bedrock_for_all_rounds):
                    # Use offset method for subsequent rounds if not using bedrock for all rounds
                    if self.first_position_after_submit and self.round > 0:
                        print("[*] Subsequent Rounds - Calculating Offset:")
                        print(f"    Previous Correct X: {self.previous_correct_x}")
                        print(f"    Previous Correct Z: {self.previous_correct_z}")
                        print(f"    Position Offset X: {x}")
                        print(f"    Position Offset Z: {z}")
                        
                        # Calculate next round coordinates
                        next_x = self.previous_correct_x + x
                        next_z = self.previous_correct_z + z
                        
                        print(f"    Next Round Coordinates: X = {next_x}, Z = {next_z}")
                        
                        # Manually confirm guess with additional context
                        self.manual_guess_confirmation(
                            next_x, 
                            next_z, 
                            None, 
                            self.last_position_data
                        )
                        
                        # Reset flag to ignore subsequent positions
                        self.first_position_after_submit = False
            
            except Exception as e:
                print(f"[!] Error processing position data: {e}")

        @self.sio.on("loadChunk")
        def on_loadChunk(data):            
            # If we haven't processed this chunk before, try to process it
            # if round is above 0 (Round 1) and we are not using the Bedrock Pattern search every round, do not process it
            if self.processing_chunk or self.round > 0 and not self.use_bedrock_for_all_rounds:
                return
            
            # Prevent any new loadChunk data received from being processed
            self.processing_chunk = True
            try:
                # Save chunk data to file
                with open(OUTFILE, "w") as f:
                    f.write(json.dumps(data) + "\n")
                print(f"[*] Captured chunk x={data['x']} z={data['z']}")
                
                # Process chunk and generate pattern file
                pattern_file = MinecraftChunkParser.generate_pattern_file(
                    OUTFILE,
                    target_block_id=112,
                    layer_y=4,
                    output_dir="./"
                )

                # Run bedrock finder
                if pattern_file:
                    print(f"[*] Running Bedrock Finder: {BEDROCK_PATH}...")
                    
                    cmd = [
                        BEDROCK_PATH,  # Executable name
                        pattern_file   # Pattern file path (relative)
                    ]
                    
                    # Run the process and capture output
                    process = subprocess.Popen(
                        cmd, 
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        universal_newlines=True
                    )
                    
                    stdout_output = []
                    while True:
                        output = process.stdout.readline()
                        if output == '' and process.poll() is not None:
                            break
                        if output:
                            print(output.strip())
                            stdout_output.append(output.strip())
                    
                    full_stdout = '\n'.join(stdout_output)
                    
                    # Parse output for coordinates
                    x, z = self.parse_bedrock_output(full_stdout)
                    
                    # Store bedrock coordinates
                    self.base_coords = (x, z)
                    
                    # Wait for in-chunk position, if it hasn't been received yet
                    if x is not None and z is not None:
                        # If in_chunk_coords is None, we'll defer the guess confirmation
                        # Store the base coordinates for later use
                        if self.in_chunk_coords is None:
                            print("[*] Waiting for in-chunk position...")
                            # Store the base coordinates to be used when in_chunk_coords is received
                            self.base_coords = (x, z)
                        else:
                            # Prompt for guess with bedrock coordinates and current in-chunk position
                            self.manual_guess_confirmation(
                                x + self.in_chunk_coords[0], 
                                z + self.in_chunk_coords[1], 
                                self.bedrock_match_data, 
                                None
                            )
                            # Reset base_coords and in_chunk_coords for next Bedrock Pattern search (This does not affect Offset method)
                            self.base_coords = None
                            self.in_chunk_coords = None
                
                # Reset processing state to allow next chunk
                self.processing_chunk = False
            
            except Exception as e:
                print(f"[!] Error processing chunk: {e}")
                import traceback
                traceback.print_exc()
                self.processing_chunk = False

        @self.sio.on("submitResponse")
        def on_submit_response(data):
            print("[*] Submit Response:", data)
            
            # Reset first position flag for next round
            self.first_position_after_submit = True
            
            # Track coordinates for exploit
            if 'correct' in data:
                correct_coords = data['correct']
                self.previous_correct_x = correct_coords.get('x')
                self.previous_correct_z = correct_coords.get('z')
                
                # Increment round counter
                self.round += 1
                
                print(f"[*] Completed Round {self.round}")
            
            # Check for flag if found print and save to file
            if 'flag' in data and 'EPT{' in data['flag']:
                print(f"[+] FLAG FOUND! -- {data['flag']}")
                print(f"[+] Flag written to {FLAG_FILE}")
                with open(FLAG_FILE, 'w') as f:
                    f.write(data['flag'])
                self.stop()

        @self.sio.event
        def disconnect():
            print("[*] Disconnected")

    def connect(self):        
        while True:
            try:
                # Clear previous chunk log
                if os.path.exists(OUTFILE):
                    os.remove(OUTFILE)
                
                # Reset processing state
                self.processing_chunk = False
                self.last_position = None
                self.round = 0
                self.previous_correct_x = None
                self.previous_correct_z = None
                self.position_offset_x = None
                self.position_offset_z = None
                self.first_position_after_submit = True
                
                # Reset coordinate tracking
                self.base_coords = None
                self.in_chunk_coords = None
                
                # Connect to server
                self.sio.connect(SERVER)
                
                # Inner loop to keep connection alive
                while True:
                    self.sio.sleep(0.1)
            
            except (socketio.exceptions.ConnectionError, Exception) as e:
                print(f"[!] Connection error: {e}")
                print("[*] Attempting to reconnect in 5 seconds...")
                time.sleep(5)
            
            except KeyboardInterrupt:
                print("[*] Stopping...")
                break
            
            finally:
                self.stop()

    def stop(self):
        try:
            self.sio.disconnect()
        except:
            pass

if __name__ == "__main__":
    # Example usage: Set to True to use bedrock pattern search for all rounds
    # Recommended: False (Faster), does only need to do Bedrock Pattern search once
    # This Offset method will not be spot on, but close enough for 5000 points
    # The Bedrock Pattern Search would be spot-on (5001 points) resulting in 25005 points
    # But this is very based on luck as the executable needs to find the chunk 5 times 
    finder = ChunkCoordinateFinder(use_bedrock_for_all_rounds=False)
    finder.connect()