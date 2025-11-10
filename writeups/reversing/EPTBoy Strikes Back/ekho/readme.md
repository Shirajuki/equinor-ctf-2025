# EPTBOY STRIKES BACK


![alt text](desc.png)



Apparently, there is more to EPTBOY than only a space shooting game. The built rom for the game only creates the space shooter, but looking at the files, there seems to be an entire rpg hidden here, with characters to interact with, and a lot of background and scene files.
Grepping for "flag" yields a lot of random lines, but one in particular seems very interesting


![](grep.png) 


One of the npcs using script `actor_20_interact.s` performs
```
.dw VAR_GAME1, VAR_GAME2, VAR_GAME3, VAR_GAME4, VAR_GAME5, VAR_GAME6, VAR_GAME7, VAR_GAME8, VAR_GAME9, VAR_GAME10, VAR_GAME11, VAR_GAME12, VAR_GAME13, VAR_GAME14, VAR_GAME15, VAR_GAME16, VAR_GAME17, VAR_GAME18, VAR_GAME19, VAR_GAME20, VAR_GAME21, VAR_GAME22, VAR_GAME23, VAR_GAME24, VAR_GAME25
        .asciz "Congratulations!\012Your flag is:\012%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\012%c%c%c%c%c%c"
```

In addition to that, `scene_17_init.s` xors each `VAR_GAMEx` with its corresponding `VAR_KEYx` before they are shown:
```
        VM_RPN
            .R_REF      VAR_GAME1
            .R_REF      VAR_KEY1
            .R_OPERATOR .B_XOR
            .R_REF_SET  VAR_GAME1
            .R_STOP
``` 
Reproducing those 50 variables reproduces the flag.

The first 25 are easy; `scene_sample_town_init.s` sets the GAME variables to these values:
`[33, 42, 61, 30, 28, 16, 6, 9, 127, 10, 13, 65, 9, 23, 30, 58, 5, 1, 60, 27, 0, 86, 3, 77, 4]`

The 25 key variables are scattered throughout the rest of the script files.

Some are hard coded
```
KEY6 -> actor_39_interact.s -> 117
KEY7 -> actor_37_interact.s -> 106
KEY9 -> actor_42_interact.s -> 32
KEY11 -> trigger_3_interact.s -> 97
KEY12 -> actor_42_interact.s -> 32
KEY13 -> trigger_0_interact.s -> 112
KEY14 -> actor_ice_block_interact.s -> 114
KEY18 -> actor_chest_interact.s -> 115
KEY19 -> actor_sign_post_0_interact.s -> 99
KEY22 -> actor_42_interact.s -> 32
KEY23 -> actor_19_interact.s -> 103
KEY25 -> actor_43_interact.s -> 121
```
and some are copies
```
KEY8 -> trigger_15_interact.s -> VAR_KEY4
KEY10 -> trigger_15_interact.s -> VAR_KEY2
KEY15 -> trigger_15_interact.s -> VAR_KEY2
KEY16 -> trigger_15_interact.s -> VAR_KEY4
KEY17 -> actor_37_interact.s -> VAR_KEY7
KEY20 -> trigger_15_interact.s -> VAR_KEY3
KEY21 -> trigger_15_interact.s -> VAR_KEY4
KEY24 -> actor_ice_block_interact.s -> VAR_KEY14
```
Because the flag format is known, I can assume that xoring `EPT{` with the first 4 GAME variables gives the values for 1 to 4.

Value 5 is missing, but the entire key row is in ascii range and says
`dzie5uje za przejscie gry`

This is polish and 5 can be inferred as k

Xoring each letter in the game list with each in the key list gives the flag.


Flag: `EPT{well_played_or_revd?}`
