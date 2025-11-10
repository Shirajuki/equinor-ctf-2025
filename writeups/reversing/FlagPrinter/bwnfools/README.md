---
authors:
  - surprior
tags:
  - reversing
---
## Challenge description
```
Flags are usually **strings** in files, matching the pattern "EPT{...}" where "..." is some text.

Here's an executable that prints the flag for you. Can you find the flag?

(For security reasons, we encrypt the flag before printing)
```

## Solution

This was a really simple challenge where all that was required was to run strings on the file

![flagprinter.gif](flagprinter.gif)


`EPT{FOOLEDYOUONCELOL}`