from struct import *
#from zerocode import  *

import re

# for randomized response.
import random


""" 
Convertes the string into data for transport
into thesocket in the format that secondlife requies.
input: String
Constraints: ??
output: bytes
"""
def stringToData(inputString):
    data = b''
    
    mystring = inputString
    
    # Protect the string from illegal characters
    strDataset = set(inputString)
    for eachCharacter in strDataset:
        if not (0 <= ord(eachCharacter) <= 255):
            mystring = mystring.replace(eachCharacter, "")
    
    #The first byte is the length of the string itself.
    sizeOfString = len(mystring)
    data += pack('<H', sizeOfString)
    
    #Subsequent bytes are appended
    for eachCharacter in mystring:
        data += pack('>B',ord(eachCharacter))
        
    # The end of the data requires these bytes.
    # a byte 0x01, followed by a "long" (4 bytes) of 0x00.
    data += pack('>B', 0x01) + pack('>L',0x00)
    return data

"""
Converts a byte representation to a hex string.
Input: Bytes
Output: String (hex representation)
Constraints: 
"""
def ByteToHex( byteStr ):
        
    return ''.join( [ "%02X " % ord( chr(x) ) for x in byteStr ] ).strip()

def makepacketdict():
    dict = {}
    for line in open("message_template.msg"):
        results = re.match("^\t([^\t{}]+.+)",line)

        if results:
            aline = results.group(1)
            aline = aline.split()
 
            if aline[1] == "Fixed": 
                dict[(aline[1],aline[2])] = (aline[0],aline[3], aline[4])

            else:
                print(aline)
                dict[(aline[1],int(aline[2]))] = (aline[0],aline[3], aline[4])



    return dict

"""
No idea what this does.
"""
def zero_decode(inputbuf):
    newstring =""
    in_zero = False
    for c in inputbuf:
        if c != '\0':
            if in_zero == True:
                zero_count = ord(c)
                zero_count = zero_count -1
                while zero_count > 0 :
 
                    newstring = newstring + '\0'
                    zero_count = zero_count -1
                in_zero = False
            else:
                newstring = newstring + c
        else:
            newstring = newstring + c
            in_zero = True
    return newstring

"""
No idea what this does.
constraint: bytes as input.
returns: bytes
"""
def zero_encode(inputbuf):
    newstring =b''
    zero = False
    zero_count = b'\x00'     
    for c in inputbuf:
        #if c != '\0':  #change to compare to this..
        if c != b'\x00':
            if zero_count != 0:
                newstring = newstring + zero_count
                zero_count = 0
                zero = False
 
            newstring = newstring + int.to_bytes(c,1,'little') 
 
        else:
            if zero == False:
                newstring = newstring + int.to_bytes(c,1,'little')
                zero = True
 
            zero_count = zero_count + 1
    if zero_count != 0:
        newstring = newstring + zero_count
 
 
    return newstring
 

"""
Decodes an ID from a byte array to a decimal value with 4 characters maximum.
input: Bytes.
Constraint: Fills decimal digits from left to right.
return: The first 4 Bytes of a string (or two characters of a string.)
"""
def zero_decode_ID(inputbuf):
    newstring =""
    in_zero = False
    #print "in encode, input is", ByteToHex(inputbuf)
    for c in inputbuf:
        if c != '\0':
            if in_zero == True:
                zero_count = ord(c)
                zero_count = zero_count -1
                while zero_count>0:
 
                    newstring = newstring + '\0'
                    zero_count = zero_count -1
                in_zero = False
            else:
                newstring = newstring + str(c) #convert to string before concatenation 10.2.2021
        else:
            newstring = newstring + str(c) #convert to string before concatenation, 10.2.2021
            in_zero = True
    return newstring[:4]
    
"""
Convert a string hex byte values into a byte string.
input: A string represented in hex.
constraint:
return: A string of ascii represented characters.
"""
def HexToByte( hexStr ):

    bytes = []
 
    hexStr = ''.join( hexStr.split(" ") )
 
    for i in range(0, len(hexStr), 2):
        bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )
 
    return ''.join( bytes )
    

'''
 From http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/510399
 From http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/510399
'''
def makepacketdict():
    dict = {}
    for line in open("message_template.msg"):
        results = re.match("^\t([^\t{}]+.+)",line)
        #print(results)
        if results:
            aline = results.group(1)
            aline = aline.split()
 
            if aline[1] == "Fixed": 
                dict[(aline[1],aline[2])] = (aline[0],aline[3], aline[4])
 
                #print (aline[1],aline[2]) 
                #print (aline[1],"0x"+aline[2]), dict[(aline[1],"0x"+aline[2])] 
                #dict[(aline[1],int(aline[2][8:],16))] = (aline[0],aline[3], aline[4])
            else:
                print(aline)
                dict[(aline[1],int(aline[2]))] = (aline[0],aline[3], aline[4])
                # if( len(aline) > 2):
                    # print(aline)
                    # dict[(aline[1],int(aline[2]))] = (aline[0],aline[3], aline[4])


    return dict
    

    