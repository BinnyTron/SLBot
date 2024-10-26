import unittest

from struct import *
import sys 

from mainHelpers import *

class Test_Functions(unittest.TestCase):

    def test_Function_stringToData(self):
        self.assertEqual(stringToData("This string is now packed"), b'\x19\x00This string is now packed\x01\x00\x00\x00\x00')
        self.assertEqual(stringToData( str(12345) ), b'\x05\x0012345\x01\x00\x00\x00\x00')
        self.assertEqual(stringToData(""),    b'\x00\x00\x01\x00\x00\x00\x00')
        self.assertEqual(stringToData(" "),   b'\x01\x00 \x01\x00\x00\x00\x00')
        self.assertEqual(stringToData("  "),  b'\x02\x00  \x01\x00\x00\x00\x00')
        self.assertEqual(stringToData("   "), b'\x03\x00   \x01\x00\x00\x00\x00')
        
        
    def test_Function_ByteToHex(self):

        self.assertEqual(ByteToHex(b'HelloWorld'), '48 65 6C 6C 6F 57 6F 72 6C 64')
        self.assertEqual(ByteToHex(b'A'), '41')
        self.assertEqual(ByteToHex(b'B'), '42')
        self.assertEqual(ByteToHex(b'C'), '43')
        self.assertEqual(ByteToHex(b'R'), '52')
        self.assertEqual(ByteToHex(b'\B'), '5C 42')
        
        self.assertRaises(TypeError, lambda : ByteToHex("hello"), '5C 42')

                
    def test_Function_HexToByte(self):

        self.assertEqual(HexToByte("48 65 6C 6C 6F 57 6F 72 6C 64"), 'HelloWorld') 
        self.assertEqual(HexToByte('41'), 'A')
        self.assertEqual(HexToByte('5C 42'), '\B')
        
    def test_Function_zero_decode_ID(self):
        self.assertEqual(zero_decode_ID(b'A'), '65')
        self.assertEqual(zero_decode_ID(b'B'), '66')
        self.assertEqual(zero_decode_ID(b'C'), '67')
        self.assertEqual(zero_decode_ID(b'AB'), '6566')
        self.assertEqual(zero_decode_ID(b'ABC'), '6566')
        
        self.assertEqual(zero_decode_ID(b'\x09\x09'), '99')
        self.assertEqual(zero_decode_ID(b'\x0A'), '10')
        self.assertEqual(zero_decode_ID(b'\x1A'), '26')
        self.assertEqual(zero_decode_ID(b'\x1A\x1A'), '2626')
        
        self.assertEqual(zero_decode_ID(b'\x63\x63'), '9999')
        self.assertEqual(zero_decode_ID(b'\x64\x01'), '1001')
        self.assertEqual(zero_decode_ID(b'\x64\x09'), '1009')
        
        self.assertEqual(zero_decode_ID(b'\x64\x0A'), '1001')
        self.assertEqual(zero_decode_ID(b'\x64\xA0'), '1001')
        
        self.assertEqual(zero_decode_ID(b'\x64\x40'), '1006')
        
        self.assertEqual(zero_decode_ID(b''), '')
        
        
    def test_Function_zero_encode(self):
        self.assertEqual(zero_encode(b'A'), b'\x00A')
        self.assertEqual(zero_encode(b'AB'), b'\x00AB')
        self.assertEqual(zero_encode(b'ABCDEF'), b'\x00ABCDEF')
        self.assertEqual(zero_encode(b'ABCDEF123456789'), b'\x00ABCDEF123456789')
        self.assertEqual(zero_encode(b'!'), b'\x00!')
        self.assertEqual(zero_encode(b'\x00HelloWorld\x00\x00\x00'), b'\x00\x00HelloWorld\x00\x00\x00')
        
    def test_Function_zero_decode(self):
        self.assertEqual(zero_decode('A'), 'A')
        self.assertEqual(zero_decode('\x00'), '\x00')
        self.assertEqual(zero_decode('ABC\0'), 'ABC\x00')
        self.assertEqual(zero_decode('ABC\0123'), 'ABC\n3')
        
    def test_stringToData(self):
        str_data = stringToData("This is the thing")
        self.assertEqual(str_data, b'\x11\x00This is the thing\x01\x00\x00\x00\x00')
    
        str_data = stringToData("How much wood could a woodchuck chuck")
        self.assertEqual(str_data, b'%\x00How much wood could a woodchuck chuck\x01\x00\x00\x00\x00')
    
        str_data = stringToData("does-this-work? ")
        self.assertEqual(str_data, b'\x10\x00does-this-work? \x01\x00\x00\x00\x00')
        
    def test_stringToData_BadCharacterInjection(self):
        testString = "Try emoji 😃"
        str_data = stringToData(testString)
        self.assertEqual(str_data, b'\n\x00Try emoji \x01\x00\x00\x00\x00')
        
    '''
    Test the identification of nouns
    '''
    def test_generateResponseString0(self):
        testString = "It's been the warmest day of the year so far. 91f"
        name = "Eric"
        response, nounsList = generateResponseString(name,testString)
        self.assertEqual(nounsList,['day','year'])
        
    def test_generateResponseString1(self):
        testString = " Just mute him... he will never get better... he has the mind of a child at age 75."
        name = "Eric"
        response, nounsList = generateResponseString(name,testString)
        self.assertEqual(nounsList,['mute','mind','child','age'])
        
    def test_generateResponseString2(self):
        testString = "They must only let him use the internet on weekends in the old folks home"
        name = "Eric"
        response, nounsList = generateResponseString(name,testString)
        self.assertEqual(nounsList,['internet','weekends','folks','home'])
        
    def test_generateResponseString3(self):
        testString = "He seems more like an angry drunk"
        name = "Eric"
        response, nounsList = generateResponseString(name,testString)
        self.assertEqual(nounsList,['drunk'])
        
    '''
    Test the absence of any nouns or nounList
    '''
    def test_generateResponseString4(self):
        testString = "red running amused delighted quiet soft sweet thankful"
        name = "Eric"
        response, nounsList = generateResponseString(name,testString)
        self.assertEqual(nounsList,['running', 'sweet'])
    
if __name__ == '__main__':
    unittest.main()
    












    

