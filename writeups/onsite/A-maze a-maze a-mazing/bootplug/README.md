# Writeup: A maze a maze a mazing
## Team: bootplug
**Author:** TGC

## Challenge


### Challenge Text

```
Let's get physical to solve a maze. Come to the IQ room to set your skills to the test.
```

## Process

The mazepuzzle looks like this 3D model: https://makerworld.com/en/models/30385-russian-random-maze-puzzle-gift-box#profileId-26851

Looking at it, it has two notches and restricts your movement. 
The best solution is to pay attention to the notches and find out where it can and can't go by looking down the barrel.
Instead of bruteforcing, see what you can control and analyze where you can go further down.
This might include goihng back up, but you can see the notches and therefore can control the maze.

Trial and error, keep an eye on the notches, and you are good to go.
Solve all three puzzles.

You get the flag `EPT{4r3_yOu_4m4z3d?}`