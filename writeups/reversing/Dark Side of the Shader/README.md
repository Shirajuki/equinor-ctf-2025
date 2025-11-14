# Dark Side of the Shader
Author: surprior

Flag: `EPT{kd0CtuLy77XCnlSeZP}`
## Description
```
Show me the rainbow on the Dark Side of the Moon!

The handout contains a Dockerfile with instructions, to fix possible problems with dependencies. This challenge is entirely contained in the provided elf binary and can be solved without the container.

Some hints:

* RenderDoc is a useful tool to see what is happening on your GPU when frames are rendered. 

* The function used to generate the colors is a common procedural palette generator in the shader world.

* Both Ghidra and Ida are good at finding functions, but takes some time to parse the binary. After they are done, use the name of the binary to filter out library functions and find the relevant ones. 

* One function of particular interest may decompile differently in the two tools, and you may need to use them both to understand the numbers.
```

## Provided challenge files
* [handout_dsots.zip](handout_dsots.zip)
