# 🔥 Even moar pixel perfect 
## Team: Iku-toppene 🐮
**Author:** jole

## Solution
There is a wall in the contest area which you can upload "videos" to, and for
this challenge a new feature is added where you can upload a python script which
has access to a `FLAG` environment variable, which you can use to produce a
light show to leak the flag.

We simply flashed a starting sequence to give us some time to start recording,
and then flashed the binary of each letter one by one, with a empty frame
inbetween to more easily space them.

```py
import os, json

flag = os.getenv("FLAG")

red = [255, 0, 0]
green = [0, 255, 0]
trans = [0, 0, 0]
white = [255, 255, 255]

empty = [[trans] * 55, [trans]*55, [trans]*55, [trans]*55]

# start with flashing the middle two rows red and green alternating
arr = [
        [[trans] * 55, [red]*55, [green]*55, [trans]*55],
        [[trans] * 55, [green]*55, [red]*55, [trans]*55],
        [[trans] * 55, [red]*55, [green]*55, [trans]*55],
        [[trans] * 55, [green]*55, [red]*55, [trans]*55],
        [[trans] * 55, [red]*55, [green]*55, [trans]*55],
        [[trans] * 55, [green]*55, [red]*55, [trans]*55],
        [[trans] * 55, [red]*55, [green]*55, [trans]*55],
        [[trans] * 55, [green]*55, [red]*55, [trans]*55],
]

for c in flag:
    nr = ord(c)
    b = bin(nr)[2:] # string of binary digits

    line = []
    for _ in range(17): # offset to about our approximate X coordinate in the room (off by 1 sadly)
        line.append(trans)
    
    for digit in b:
        if digit == "0":
            line.append(red) # red = 1
        else:
            line.append(green) # green = 0
    
    while len(line) < 55: # fill up the rest of the line with transparent
        line.append(trans)

    # now append the finalized frame, where the middle 2 rows contain the encoded character
    arr.append(
        [[white] * 55, line, line, [white]*55],
    )

    arr.append(empty)
    

frames = { "frames": arr }

print(json.dumps(frames))
```

After this just record it (and spend like 45 minutes trying to decode it
properly while thinking someone is going to snipe it from you) :)

Since we didn't print any leading zeros, cyberchef gave the wrong output so i just wrote this script:
```py
raw = """
GRGRRRR
GRGRGRR
GGGGRGG
GGGRRG
GGRRRGR
GGRGGR
GGRGRG
GGRGGR
GGRGGG
GGRRRG
GGRRRRG
GGRRGRR
GGRGGR
GRGGGGG
GRGGGR
GRGGGGG
GRRRRGG
GGRRRR
GGRGGRR
GRRGGGG
GGGRGRG
GGGRRGR
GRGRRGG


GRGRRGG
GRGRRGG
GRGRRGG
GRGRRGG
GRGRRGG


GGRGGR
GGRGGG
GGRRRG
GGRRRRG
GGRRGRR
GGRGGR
GRGGGGG
GRGGGR
GRGGGGG
GRRRRGG
GGRRRR
GGRGGRR
GRRGGGG
GGGRGRG
GGGRRGR
GRGRRGG





GRRRGRG
GRGRRRR
GRGRGRR
GGGGRGG
GGGRRG

GGRGGR
GGRGGG
GGRRRG
GGRRRRG
GGRRGRR
GGRGGR
GRGGGGG
GRGGGR
GRGGGGG
GRRRRGG
GGRRRR

GRRRRGG
GGRRRR
GGRGGRR
GRRGGGG
GGGRGRG
GGGRRGR
GRGRRGG
GRGGGGG
GRGGGR
GRGGGGG
GGRGRR
GGRGGGR
GRRRGRR
GRGGGGG
GRGGGR
GRGGGGG
GRRGGRR
GGRRRG
GGRRGGG
GRRGRRR
GGGRGRR
GRRGRR
GRGGGGG
GRGGGR
GRGGGGG
GGRRGGR
GGRRRGG
GGRRGGR
GGRGGG
GGRRRGR
GGRRRR
GGRRGR
GGRGGG
GGRRRG
GGRRRGR
GGGGGRG
"""

for line in raw.split():
    # print(line)
    b = line.replace("R", "0").replace("G", "1")
    n = int(b, 2)
    c = chr(n)
    # print(n, c)
    print(c, end="")
```

## Flag
``` sh
$ python3 dec2.py
EPT{9b65671ad6_._C0lOurS_._4nD_._L1gHt$_._fcf7b0271b}
```

## Bilde (encodet `O`)
![bilde](image-vegg.png)