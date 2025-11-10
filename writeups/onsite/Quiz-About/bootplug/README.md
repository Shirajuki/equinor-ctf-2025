# Writeup: Quizabout
## Team: bootplug
**Author:** TGC

## Challenge

### Challenge Text

```
Quiz your way to the flag: 

![QR image](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAASwAAAEsAQMAAABDsxw2AAAABlBMVEX///8AAABVwtN+AAAACXBIWXMAAA7EAAAOxAGVKw4bAAABVUlEQVRoge3Yza3DIBAEYFxBSqBUt0oJVOANeH/Asg++hYlmFT1F8N3mQZZN6V3t4lVT+khfykdKm5QtdqSQrcGqpdZYW2jSt5rUnY0MjmnuGn2XSYGnX8iA2RT9QfYfzA+1GzJYNq5o/fTdww/1001OtjgTr5lF7lpkUOxezh62yCDYHrmPL0ffaA+f+JDBsWpNlD5jL6FnO8tkQMzGEZ+B+7olHt0UGRibo7dFC/28qDMZGvNB0xT91ETJmDuR/Zzt59cRaH/aeI90/pJqkSGxSDz+Zo3cuiM9p2R4LNkl3Eqiyhg+kIGx6re0ROhyKTIoNpeunU2vbm2ePhkS2yPf6mP8ANFT3UaIZEuzaYYf6XvnPBoqMiwWucv9yVOsVSZDZfNxFm+lspABM7GRr/3s2jP2+T+EbGWmdYk+x3uHDJDFbRxXtPhEQt+wcuu4yNZm7+oLyXIaW/mKbYEAAAAASUVORK5CYII=)
```

## Process

After scanning the first QR, we solved the quiz and got the first image:

![loc0](./images/loc0.webp)

Google found it and we ran to the first location: https://maps.app.goo.gl/7QvFnphiXrBWcAYYA

At the door there was a QR code that lead to a quiz about memes: https://take.quiz-maker.com/Q3WZD7SY9
Answer the questions to the best of your knowledge and get a new image:

![loc1](./images/loc1.webp)

This is an AI generated version of the harbour Aker brygge, so we ran there.

https://www.google.com/maps/place/Aker+Brygge,+Oslo/@59.9109993,10.7350464,3a,75y,215.97h,88.61t/data=!3m7!1e1!3m5!1s6ftrRYPsLsk8CsP4zt19Qg!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com%2Fv1%2Fthumbnail%3Fcb_client%3Dmaps_sv.tactile%26w%3D900%26h%3D600%26pitch%3D1.3903545752937276%26panoid%3D6ftrRYPsLsk8CsP4zt19Qg%26yaw%3D215.9748457803667!7i16384!8i8192!4m6!3m5!1s0x46416e81bceae4f9:0xe68ffef57f364675!8m2!3d59.9099584!4d10.7258053!16s%2Fm%2F02qjqd1?entry=ttu&g_ep=EgoyMDI1MTEwNC4xIKXMDSoASAFQAw%3D%3D

The third quiz https://take.quiz-maker.com/QE6CBAJDD, was strange and we employed a trial and error tactic.
So changing one answer at a time until we got 4/4 correct.

![loc2](./images/loc2.webp)

This is another AI generated image that we didn't quite know where was.
However Google AI managed to correctly guess that this was the museeum by the old bank.

![loc2_real](./images/loc2_real.png)

Answer the third quiz https://take.quiz-maker.com/QS7VNULBI, and get the flag:
`EPT{1t_t4k35_m0r3_th4n_qu3zzw0rk}`

10/10, would run again