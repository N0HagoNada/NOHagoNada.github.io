---
layout: post
title: Cheat Engine Tutorial
date: 2023-10-08 17:04:48 
categories: [Game Funning]
tag: ["Cheat Engine", Squally, Assembler, "Low Level"]      
img_path: /assets/img/First/                                                                                                        
toc: true 
---

# Cheat Engine
This blog its about the Cheat Engine Tutorial and other basic set up. 
* First 8 challenges of the tutorial are just too much simple, refering with search for Float, Double, 4-Bytes, etc.

## Code Finder

Its a value change every time the game restart, we need to go and look up what assembly code its used to modify that address. ![Code Finder](image-9.png). Continue playing the game we see the instruction 
![Code Finder](image-10.png)
Go to source code, and change the instruction to NOPs.
![Alt text](image-11.png)

## Pointers

We need to search for a pointer because the address itself will change, the same process before we found the same code ```mov [edx], eax``` but the diferences its the square bracket, this means that the value of eax its moved to the address point by the value on edx `[edx]`, not in edx itself. 
So in order to find the address of the pointer that holds the address of the 4 Bytes with value 987, we will scan for that address.
![Find Address](image-12.png)
We found an its Green so its Static
![Static Address](image-13.png)
We add this as a Pointer on Cheat Engine using the add address Manually function
![Pointer](image-14.png)

## Code Injection 

Delete an instruction using an automated script with Code Injection Template.
![CodeInjectio](image-15.png)
Changing sub for add, we are goint to health besided receive damage. 
Remove the original code.

## Multilevel Pointers

This its where the magic begin, find each level of the pointer trace back until get the static base address. 
Like a pointer that point  to a pointer and still with 4 of depth 

-> = "points to"

* 01AC0620 = Value = 3776

* 01A99BE0 -> 01AC0608 + 0x18 = 01AC0620  
![Find base ptr1](image-16.png)
![Find Baseptr1](image-17.png)
With Find what access to this address we will find the offset and then de address 
![NoOffser](image-18.png)

* 01AB477C -> 01A99BE0 + 0 = 01A99BE0

* 01A38424 -> 01AB4768 + 0x14 = 01AB477C

* "Tutorial-i386.exe"+2566E0 -> 01A38418 + 0xC = 01A38424

![Alt text](image-19.png)
 
## Shared Code 

 This step will explain how to deal with code that is used for other object of the same type
* First its find the base address of the Player 1 object health, take in mind the offset
![BaseAddr](image-20.png)
* Open Memory View -> Tools -> Structure dissect and create Two groups with two address both. Fill it with the base address of Player Health 

![Structure](image-21.png)

Define a new Structure, and playing around with the values and the information you know form the game you can find Health, Team, Name position
![Strucutre Disas](image-22.png)

We know where Team reference its placed, so now we inyect a code with Auto assemble when player 1 get attack.
```c
alloc(newmem,2048)
label(returnhere)
label(originalcode)
label(exit)

newmem: //this is allocated memory, you have read,write,execute access
cmp [ebx+10],1
jne originalcode
fldz
jmp originalcode+5

originalcode:
mov [ebx+04],eax
fldz 

exit:
jmp returnhere

"Tutorial-i386.exe"+28E89:
jmp newmem
returnhere:
```
This code compare first if the target its on team 1, if not continue execution making damage. If its on team 1 keep the instructión ```fldz``` to keep align the stack and jump to next address after damage get executed
![Solution](image-23.png)


