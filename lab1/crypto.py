#!/usr/bin/env python3 -tt
"""
File: crypto.py
---------------
Assignment 1: Cryptography
Course: CS 41
Name: <YOUR NAME>
SUNet: <SUNet ID>

Replace this with a description of the program.
"""
import utils

# Caesar Cipher

def encrypt_caesar(plaintext):
    """Encrypt plaintext using a Caesar cipher.

    Add more implementation details here.
    """
    result = ""
    for ch in plaintext:
        if ch.isalpha():  # Check if character is an alphabet
            shift = 3
            ch = ch.upper()
            base = ord('A')
            # Perform the shift and wrap around the alphabet
            result += chr((ord(ch) - base + shift) % 26 + base)
        else:
            result += ch  # Non-alphabet characters are added unchanged
    return result


def decrypt_caesar(ciphertext):
    """Decrypt a ciphertext using a Caesar cipher.

    Add more implementation details here.
    """
    result = ""
    for ch in ciphertext:
        if ch.isalpha():  # Check if character is an alphabet
            shift = 3
            ch = ch.upper()
            base = ord('A')
            # Perform the shift and wrap around the alphabet
            result += chr((ord(ch) - base - shift) % 26 + base)
        else:
            result += ch  # Non-alphabet characters are added unchanged
    return result


# Vigenere Cipher

def encrypt_vigenere(plaintext, keyword):
    """Encrypt plaintext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    result = ""
    for i, ch in enumerate(plaintext):
        if ch.isalpha():  # Check if character is an alphabet
            shift = ord(keyword[i % len(keyword)]) - ord('A')
            ch = ch.upper()
            base = ord('A')
            # Perform the shift and wrap around the alphabet
            result += chr((ord(ch) - base + shift) % 26 + base)
        else:
            result += ch  # Non-alphabet characters are added unchanged
    return result


def decrypt_vigenere(ciphertext, keyword):
    """Decrypt ciphertext using a Vigenere cipher with a keyword.

    Add more implementation details here.
    """
    result = ""
    for i, ch in enumerate(ciphertext):
        if ch.isalpha():  # Check if character is an alphabet
            shift = ord(keyword[i % len(keyword)]) - ord('A')
            ch = ch.upper()
            base = ord('A')
            # Perform the shift and wrap around the alphabet
            result += chr((ord(ch) - base - shift) % 26 + base)
        else:
            result += ch  # Non-alphabet characters are added unchanged
    return result

def encrypt_scytale(plaintext, circumference):
    result=""
    for i in range(circumference):
        j=i
        print(j)
        while j < len(plaintext):
            result+=plaintext[j]
            j += circumference
    return result

def decrypt_scytale(ciphertext, circumference):

    result=""
    step=len(ciphertext)//circumference
    i = 0
    extra = len(ciphertext) % circumference
    while i<step:
        tmp_extra = extra
        j=i
        while j < len(ciphertext):
            result+=ciphertext[j]
            j+=step + (1 if tmp_extra > 0 else 0)
            tmp_extra-=1
        i+=1
    if(extra>0):
        j=i
        while extra>0:
            result+=ciphertext[j]
            j+=step+1
            extra-=1
    return result
