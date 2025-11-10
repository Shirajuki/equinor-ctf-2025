# Writeup: EPTBoy
## Team: bootplug
**Author:** TGC

## Challenge

### Challenge Text

```
Can you defeat the imperialistic oil polluters and bring back the new republic?

Find a way to win the game, show off your skills in the gaming area and get the real flag.
```

## Process

First we attempted to play the game, it was apparent that it was intentionally hard and we also have the source code so playing it wasn't an option.
We checked the code and found two variables called `VAR_CHEATCOUNTER` and `VAR_INVINCIBLE`.

Enumerating it further we saw that the file `/src/src/script_input_0.s` had a check to see if the cheat counter was set to 10. If so, then we were invincible.

```
GBVM$script_input_0$a5e6e712_f41d_4f24_8a9a_0c6c0c056545$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script = .
.globl GBVM$script_input_0$a5e6e712_f41d_4f24_8a9a_0c6c0c056545$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script
        ; If
        ; -- Calculate value
        VM_RPN
            .R_REF      VAR_CHEATCOUNTER ;<--- Get the counter 
            .R_INT16    10 ;<--- Value 10
            .R_OPERATOR .EQ ;<--- EQ = Equals, so the check if counter equals 10
            .R_STOP
        ; -- If Truthy
        VM_IF_CONST             .NE, .ARG0, 0, 1$, 1 ;<--- If true, run $1
GBVM$script_input_0$c60adf64_33a0_496c_a281_115ef6753453$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script = .
.globl GBVM$script_input_0$c60adf64_33a0_496c_a281_115ef6753453$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script
        ; Variable Set To
        VM_SET_CONST            VAR_INVINCIBLE, 0

        VM_JUMP                 2$
1$: ;<--- If one the set VAR_INVINCIBLE to true
GBVM$script_input_0$c4de0029_89fc_47c4_95c0_f99b0edc7e34$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script = .
.globl GBVM$script_input_0$c4de0029_89fc_47c4_95c0_f99b0edc7e34$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script
        ; Variable Set To
        VM_SET_CONST            VAR_INVINCIBLE, 1
```

So now we know we have to set the `VAR_CHEATCOUNTER` to 10.
To do this we look at where the counter is referenced.
Luckily this is referenced at sequentional files `/src/src/script_input_0.s` - `/src/src/script_input_7.s`
In brief, depending on what button you press at what time, you access the script input and increment the cheat counter if and only if it's done in the correct sequence.
Here is an example from `/src/src/script_input_6.s`, if you press that button when the cheat counter is at 6, then it increments from 6 to 7.

```
[...]
_script_input_6::
GBVM$script_input_6$33819e36_fbaa_43a0_a0ac_33749b87652d$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script = .
.globl GBVM$script_input_6$33819e36_fbaa_43a0_a0ac_33749b87652d$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script
        ; If
        ; -- Calculate value
        VM_RPN
            .R_REF      VAR_CHEATCOUNTER ;<--- Access VAR_CHEATCOUNTER
            .R_INT16    6
            .R_OPERATOR .EQ ;<--- Check if equals to R_INT16 (6)
            .R_STOP
        ; -- If Truthy
        VM_IF_CONST             .NE, .ARG0, 0, 1$, 1 ;<--- If true, jump to $1, if not, set VAR_CHEATCOUNTER to 0
GBVM$script_input_6$612b6fde_b62d_4604_aa4e_eb912220af03$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script = .
.globl GBVM$script_input_6$612b6fde_b62d_4604_aa4e_eb912220af03$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script
        ; Variable Set To
        VM_SET_CONST            VAR_CHEATCOUNTER, 0

        VM_JUMP                 2$
1$:
GBVM$script_input_6$4a4b388a_28bd_428e_9876_56b7020adea5$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script = .
.globl GBVM$script_input_6$4a4b388a_28bd_428e_9876_56b7020adea5$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script
        ; Variable Increment By 1
        VM_RPN
            .R_REF      VAR_CHEATCOUNTER ;<--- Access VAR_CHEATCOUNTER
            .R_INT8     1 
            .R_OPERATOR .ADD ; <--- Increment counter value by the value R_INT8 (1)
            .R_REF_SET  VAR_CHEATCOUNTER ; <--- Set the new value to VAR_CHEATCOUNTER 
            .R_STOP

2$: 

GBVM_END$script_input_6$33819e36_fbaa_43a0_a0ac_33749b87652d = .
.globl GBVM_END$script_input_6$33819e36_fbaa_43a0_a0ac_33749b87652d
        ; Stop Script
        VM_STOP
```


So to access these scripts, we see that it's shown in screen init `/src/src/scene_titile_screen_init.s`.
An example to access `/src/src/script_input_6.s` is shown below.
You need to press the button 0x02 to enter and ren the script.

```
GBVM_END$scene_title_screen_init$ba6ef82d_9c47_4457_a984_1300a4c51596 = .
.globl GBVM_END$scene_title_screen_init$ba6ef82d_9c47_4457_a984_1300a4c51596
GBVM$scene_title_screen_init$6287afa7_a402_45f8_9743_6554791b0124$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script = .
.globl GBVM$scene_title_screen_init$6287afa7_a402_45f8_9743_6554791b0124$4912bee2_387a_472f_ae4f_6679b6149517$scene$4912bee2_387a_472f_ae4f_6679b6149517$script
        ; Input Script Attach
        VM_CONTEXT_PREPARE      7, ___bank_script_input_6, _script_input_6
        VM_INPUT_ATTACH         2, ^/(7 | .OVERRIDE_DEFAULT)/ ;<--- Look for button 2, then run script6
```

According to Google/AI, a button mapping is shown as below:


| Button | Hex Value | Decimal Value |
|--------|-----------|---------------|
| J_RIGHT | 0x01 | 1 |
| J_LEFT | 0x02 | 2 |
| J_UP | 0x04 | 4 |
| J_DOWN | 0x08 | 8 |
| J_A | 0x10 | 16 |
| J_B | 0x20 | 32 |
| J_SELECT | 0x40 | 64 |
| J_START | 0x80 | 128 |

Mapping the buttons to each script input, we get the correct sequence; `SELECT, B, UP, DOWN, DOWN, A, LEFT, A, B, RIGHT, START`.
Typing that in at the start screen,  we can start the game with invicibility and get the flag.

We forgot to note the flag for the writeup but c'est la vie.