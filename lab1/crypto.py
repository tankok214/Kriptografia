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

def encrypt_railfence(plaintext, rails):
    result = [''] * rails
    rail = 0
    direction = 1

    for ch in plaintext:
        result[rail] += ch
        rail += direction

        if rail == 0 or rail == rails - 1:
            direction *= -1

    return ''.join(result)

def decrypt_railfence(ciphertext, rails):
    #peaks shows how many of these zig-zag patterns are in the cipher
    #It is calculated by checking the getting number that is lower than the cipherlength but is
    #part of the rails + 2*rails - 2 + 2*rails - 2 + ... series
    #peaks=1
    #a..
    #.a.
    #.a.
    #peaks=2
    #a...a..
    #.a.a.a.
    #..a...a

    #In this pattern the number of letters in each row can be determined
    #indifferent from the rails value,
    #in the first and last rows it is the amount of peaks
    #in the other rows it is 2*peaks+1

    #Knowing this we can rebuild the original matrix

    matrix=[''] * rails
    n=rails
    peaks=1
    while len(ciphertext) > n + 2*rails - 2:
        n+=2*rails-2
        peaks+=1

    #diff contains the difference between cipher length and the closest zigzag length
    #based on this we can handle the extra letters
    diff = len(ciphertext) - n

    tmp_ciphertext=ciphertext
    if diff <= (2 * rails - 3)//2:
        #If there is no extra peak we distribute the letters accordingly
        matrix[0]+=tmp_ciphertext[:peaks]
        tmp_ciphertext = tmp_ciphertext[peaks:]
        for r in range(1,rails-1):
            add_len=0
            if(rails - r <= diff +1):
                add_len = 1
            matrix[r]+=tmp_ciphertext[:(2*peaks-1)+add_len]
            tmp_ciphertext = tmp_ciphertext[(2*peaks-1)+add_len:]
        matrix[rails-1]=tmp_ciphertext

    else:
        #If there is an extra peak we can handle it by giving each row 1 or 2 extra letters by decrementing the diff
        matrix[0]+=tmp_ciphertext[:peaks + 1]
        diff -= 1
        tmp_ciphertext = tmp_ciphertext[peaks + 1:]
        for r in range(1,rails-1):
            add_len=0
            if(diff - 2 > 0):
                diff -= 2
                add_len = 2
            else:
                add_len = diff
            matrix[r]+=tmp_ciphertext[:(2*peaks-1)+add_len]
            tmp_ciphertext = tmp_ciphertext[(2*peaks-1)+add_len:]
        matrix[rails-1]=tmp_ciphertext

    #After the matrix is reconstructed we can read the original text from it
    result=''
    rail=0
    direction=1
    for _ in ciphertext:
        result+=matrix[rail][0]
        matrix[rail]=matrix[rail][1:]
        rail+=direction
        if rail==0 or rail==rails-1:
            direction*=-1
    return result





    # if diff == 0:
    #     result[0]+=ciphertext[:peaks+1]
    #     ciphertext = ciphertext[peaks+1:]
    #     for r in range(1,rails-1):
    #         result[r]+=ciphertext[:(2*peaks+1)]
    #         ciphertext = ciphertext[(2*peaks+1):]
    #     result[rails-1]=ciphertext
    #     print(result)
    #     return ''.join(result)
