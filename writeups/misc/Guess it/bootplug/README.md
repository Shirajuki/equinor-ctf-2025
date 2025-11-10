# Writeup: Guess it
## Team: bootplug
**Author:** TGC

## Challenge 

### Challenge Text

```
May the luck be with you!
```

### The challenge

The challenge is guessing the correct random element in 5 levels to get the flag.
The vulnerability is a timing attack, where we can calculate what every element is based on the response.

## Process

Looking at the handout we know that the answers are rotated each minute `ANSWER_ROTATION_INTERVAL = 60  # Rotate answers every x seconds` with the function `rotate_answers`.
Having only one minute per guess, we need cocurrency to maximize our efforts.

Lookin at the answer evaluation we seee that each attempt takes at least half a second.
```python
def eval_guess(guess, correct_guess, sleep_seconds=0.5):
    sleep(sleep_seconds)
    print (guess, correct_guess)
    return guess != correct_guess
```

This is where multi threading comes in handy. The server can handle 25 connections at a time.
Given 180 possible elements we have to guess through, it will take 90 seconds if we only have incorrect guesses (not accounting for network jitter), not enough time.
So with multi-threading we can do 10 at a time, leaving us to enough space to devide the time by 10, equaling to 9 seconds if it's only incorrect guesses (not accounting for network jitter).

With that, we vibecode a script that will guess each element and loop through all possible answers while updating known good answers. At the end, print the flag.
The solve script is located [here](./solve.py).

Here is the AI bloated output

```
    m: 0.557s - Wrong guess. Game over.
    n: 0.558s - Wrong guess. Game over.
    o: 0.557s - Wrong guess. Game over.
    q: 0.557s - Wrong guess. Game over.
    r: 0.557s - Wrong guess. Game over.
    p: 0.559s - Congratulations! You won the game! FLAG:EPT{e1d2a7

[+] Level 5: Alphanumeric + ! answer found: p (different response received)
============================================================
Submitting all answers to get the flag...
============================================================
Welcome to the Guessing Game!
1. Start Game
2. Exit
Choose an option:

Level 1: Level 1. Guess a number between 0-9:
Sending: 4

Level 2: Level 2. Guess a letter between A-Z:
Sending: M

Level 3: Level 3. Guess an emoji (😊 ❤️ ⭐ 🔥 🌈 🎉 🎈 🌟 🍀 🍕 🎂 🌍 🚀 💎 🎵 🐾 🌻 🦄 ⚡ 🌙):
Sending: 🔥

Level 4: Level 4. Guess an emoji (😄 💖 🌊 🍉 🌺 🥳 🍔 🦋 🍂 🏆 🥇 🌼 🌈 🍦 🐉 🌴 🧩 🎤 🌌 🧙‍♂️):
Sending: 🌴

Level 5: Level 5. Guess a letter (0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!):
Sending: p

============================================================
FLAG RECEIVED!
============================================================
Congratulations! You won the game! FLAG:EPT{e1d2a75d-3510-418c-8b45-ee06ea507197}
```

`EPT{e1d2a75d-3510-418c-8b45-ee06ea507197}`