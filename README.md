# MagicFightsLoaderC
A POC shellcode loader that searches for shellcode hidden in MP4 files.

Use the POC [MagicFights](https://github.com/nickswink/MagicFights/tree/main) to embed shellcode inside of an Mp4 file.

## What it does
* Reads a local Mp4 file (hardcoded name)
* Searches for a specific key string indicating the start of data
* Reads the size of the shellcode
* Reads the shellcode buffer from the file
* XOR decodes and executes the shellcode

## Footnote
Make of this what you want. I thought it was an interesting ideas as a way to hide malicious shellcode inside an Mp4 file or other file types that may be completely over looked by AV/EDR. 
