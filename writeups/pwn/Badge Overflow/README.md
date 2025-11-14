# Badge Overflow
Author: klarz

Flag: `EPT{b4dg3_0v3rfl0w_FTW}`
## Description
```
We printed about 600 badges for this CTF, talk about a badge overflow! 

Your badge is an NFC card (NTAG215) that you can write to with your phone.
There is an onsite Badge Decryptor that will read, decrypt, and display the first NDEF Text Record from your badge. **It will reset your badge after reading it.**

We are providing you with the badge reader (read_badges.py) and decryptor (badge-decryptor) that is used on the onsite Badge Decryptor station.

Write to your badge using NFC Tools:
[iOS](https://apps.apple.com/us/app/nfc-tools/id1252962749) | [Android](https://play.google.com/store/apps/details?id=com.wakdev.wdnfc)

**IMPORTANT:** <u>Always</u> use NDEF Text Records when writing to your badge! Writing raw data directly to memory blocks can corrupt the card structure, lock configuration bytes, or permanently brick your badge. Use the NFC Tools app to write Text Records safely as it will protect the critical memory regions automatically.

If you do not have a compatible phone, open a support ticket on Discord.
```

## Provided challenge files
* [badgeoverflow.zip](badgeoverflow.zip)
