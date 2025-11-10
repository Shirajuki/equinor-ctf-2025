# Writeup: 420BasedIt
## Team: bootplug
**Author:** TGC

## Challenge

### Challenge Text
```
I was gonna write a crypto challenge, but then I got high...

Anyway, what's cooking **chef**? #420BasedIt!
```

## Process

The challenge hints to two things base encoding and cyberchef.
We take enc.txt and unbase it through a series of base encodings.
Funnily enough, the sum of all base encoding numbers is 420.
Another hint that is easy to overlook.

The sequence of unbasing the "encrypted" text is: Base92-Base85-Base85-Base64-Base62-Base32.
92 + 85 + 85 + 64 + 62 + 32 = 420 (lol)

Use the link below and we get the flag `EPT{I5_th3_Ch3f_1n_yet?}`

https://gchq.github.io/CyberChef/#recipe=From_Base92()From_Base85('!-u',true,'z')From_Base85('!-u',true,'z')From_Base64('A-Za-z0-9%2B/%3D',true,false)From_Base62('0-9A-Za-z')From_Base32('A-Z2-7%3D',false)&input=NCdTXFd5WlBbL0g1bGIuNjNkUiMwPFxGP1NyWyosIVdBaVxIdHkzfWh2T3RsYi11PlYkRT08Nil5eW1nQFlafUs0MiMlNl1PS3ZJUlMqM3I4Ol43SV5Ze2c8Umc9IzZlRXlSIV1XY2cpMVJjVkdsdS5oJWtZNV1bXFpmXkAyRFBAPzpOWU0ydmJDRTE&oeol=FF
