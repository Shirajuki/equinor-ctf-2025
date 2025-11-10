# Writeup: The Claw
## Team: bootplug
**Author:** TGC

## Challenge

### Challenge Text

```
We had some issues with kids winning way to many plushies, so we decided to adjust the maximum grip force from 255 to 10. Just like a real arcade!

[https://theclaw.ept.gg](https://theclaw.ept.gg/)
```

#### RTFM

The most important part of this challenge is to READ THE DOCS.
It explains and shows a sample of the code as shown below.

| Command| Description | Example |
|----------|----------|----------|
| G0 | Linear Move: Moves the claw. F sets speed. | G0 X100 Y50 Z200 F3000 or G0 X100 F3000 to only move X axis |
| G4 | Dwell (Pause): Pauses for P milliseconds. | G4 P1000 (1 sec pause) |
| M106 | Claw Control: S255 closes, S0 opens. | M106 S255 (Close claw) |

There is a warning at _https://theclaw.ept.gg/_ that says `WARNING: Sequences exceeding parameters will be auto-corrected or terminated.`
This is referring to the security protocols highlighted below:

#### Security Protocols

The system enforces the following security constraints:

- **MAX_SPEED**: `F5000` - Maximum feedrate limit
- **GRIP_FORCE**: `10/255` - Restricted claw force level
- **AUTHORIZED_COMMANDS_ONLY** - Only whitelisted G-code commands accepted
- **FILE_SIZE**: `1MB_LIMIT` - Maximum upload size restriction
- **SYNTAX_VERIFICATION** - All commands validated before execution
- **MAX_RUNTIME**: `60S` - Maximum execution time per sequence

If we seet a value out side of these allowed values, it will just be autocorrected.
This is where the challenge is, when the claw will not close properly as it is stuck at 10/255. 

So we need to create code that finds a suitable teddy bear, move the claw to said teddy bear, lower and grab with full force (This is the actual exploit).
Then move the teddy bear back to start and release.
When a teddy bear has been won, the challenge will be auto solved.


## Process

Armed with the information above, we start by going to the correct place with a guesstimate/trial and error of a teddybear at approximately Y = 450 and X = 40, `G0 Y450 F3000` and `G0 X40 F3000`.
Then we lower the crane to an appropriate height (found through trial and error and state of the teddys) `G0 Z130 F3000`.
After popular request, please add `F3000` so we don't use all day.
Wait ever so slightly just to be sure `G4 P490`, and then the claw is ready to grab.
However, the claw will not grab due to the safety features.
The safety features are stuck at S10.

The Gcode interpreter would not allow us to set variables with `#101=255` and later assigning it, nor would it allow us to set the claw to the same value as a different register like Y `G0 Y255 F3000, M106 SY`.
Therefore we are stuck trying to fool the M106 value directly.
Given that the accepteable ranges are from 0-255, we attempt to assign it to a negative number `-1` and cause the claw to go out of bounds and loop back to the first acceptable number, which is 255.
After that we wait for the claw to close and return to start position before releasing.

With the gcode and exploit in place, upload it to _https://theclaw.ept.gg/_, stage the code and run it through scanning your badge.
With some RNG, we get a teddy and the flag!


### The code

Here is the final code
```gcode
; Go to Y 450 and X40
G0 Y450 F3000
G0 X40 F3000
; Lower to Z=130
G0 Z130 F3000
; Wait a moment for positioning
G4 P490
; Grab
;M106 set to 255 through a integer overflow. (The exploit)
M106 S-1
; Wait for claw to close
G4 P3000
; Lift up with grabbed object (while clamping)
G0 Z500 F3000
; Go back to start position (while clamping)
G0 X0 F3000
G0 Y0 F3000
; Release claw
M106 S0
```