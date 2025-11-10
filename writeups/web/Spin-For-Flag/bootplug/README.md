# Writeup: Spin-For-Flag
## Team: bootplug
**Author:** TGC

## Challenge

### Challenge Text

```
Complete a quick survey and spin the wheel for your chance to win the flag! 
Each visitor gets exactly one spin per day... but the flag is real, and the 
odds aren't in your favor. Maybe the rules are more like guidelines? 🏴‍☠️
```

## Process

We analyzed the script and found that completing a survey allows you to spin the wheel and give you a chance to win part of a flag. The probability of this is quite low `WIN_PROBABILITY", "0.05`.
Meaning that the best way is to brute force it and keep spinning.

To get a spin you have to have a unique UUID, so we created a script that would automatically take a survey and spin the wheel. 
Looking at `main.py` we know that it will return a json blob containing either `"result": "no_flag"` or `"result": "flag"`.
This is shown here:

```python
if won:
global win_counter
flag_parts = split_flag_into_parts(FLAG)
current_part = flag_parts[win_counter % 3]
win_counter += 1

part_number = ((win_counter - 1) % 3) + 1

return {
        "result": "flag",
        "flag": current_part,
        "message": f"🎉 Congratulations! You won part {part_number}/3 of the flag!",
}
else:
return {
        "result": "no_flag",
        "message": "Better luck next time! Thanks for spinning.",
}
```

So we created a brute force script that would keep spinning until we saw anything else than `no_flag`.
The script is added [here](solve.py).
We just ran it in the background until we got all three parts `EPT{sp1n_th3_wh33l_0f_vuln3r4b1l1ty}`.

```
{
  "result": "flag",
  "flag": "EPT{sp1n_th3_w",
  "message": "\ud83c\udf89 Congratulations! You won part 1/3 of the flag!"
}
{
  "result": "flag",
  "flag": "h33l_0f_vu",
  "message": "\ud83c\udf89 Congratulations! You won part 2/3 of the flag!"
}
{
  "result": "flag",
  "flag": "ln3r4b1l1ty}",
  "message": "\ud83c\udf89 Congratulations! You won part 3/3 of the flag!"
}
```