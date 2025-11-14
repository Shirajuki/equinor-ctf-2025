# Veal and Car's first baby (heap) is all grown up.
Author: nordbo

Flag: `EPT{hEaPT_CtF_1s_n0t_f0r_b4b13s!}`
## Description
```
In 2023 we had an introduction to tcache poisoning challenge called ["Veal and Car's first baby"](https://github.com/ept-team/equinor-ctf-2023/blob/main/writeups/Pwn/Veal%20and%20Car's%20first%20baby%20(heap)/WackAttack/README.md).

This is the exact same challenge, the only adjustment is that we removed the -no-pie flag from the Makefile.
This means that the binary is now compiled as a PIE binary, which makes exploitation _slightly_ harder.
We've also updated the Docker base image to Ubuntu 24.04.

`{{nc}}`
```

## Provided challenge files
* [vcs_handout.tar.gz](vcs_handout.tar.gz)
