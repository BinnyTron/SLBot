from struct import *
#from zerocode import  * Commented for note.

import hashlib

import xmlrpc
import xmlrpc.client as xmlrpclib

import sys 
import re
import socket       # https://docs.python.org/3/library/socket.html
import time    
import uuid
from datetime import datetime
from mainHelpers import *
import random

from urllib.parse import parse_qsl, urljoin, urlparse
import http.client




MAC            = '2C:54:91:88:C9:E3'
username_first = "AstroTester"
username_last  = "resident" 
password       = b'p@ssw0rd'

# Response is gated here (set to true for bot to chat back.) 
RESPONSE_ENABLE = False
DEBUG_ENABLE    = False

packetdictionary = {}
outputstring = ''
ack_need_list = []
logoutputflag = False


'''
Session
->PacketProcessor:composite
    Ingress
    ->PacketReceiver:composite
        --- 
        +BUFFER_SIZE
        +receivedData 
        +receivedAddress
        --- 
        +pollSocketReceive(socket):Data,Address
        ---
    ->PacketDecoder:composite 
    
    Locus 
    ->PacketHandler:composite
        --- 
        -__parser_d
        --- 
        -__message_template_parser()
        +initializeConnection():None (temp)
        +establishAgentPresence:None (temp)

        
    Egress
    ->PacketEncoder:composite 
    ->PacketTransmitter:composite


'''


'''
Responsible for the entire session
By Composition: Packet Processor (ingress/egress)
A session has a packet processor.
1 Avatar per session instance.
'''
class Session(): 

    def __init__(self,username_first,username_last, password, MAC):
      self.username_first = username_first
      self.username_last  = username_last 
      self.password       = password 
      self.MAC            = MAC

      self.result         = {}
      self.host           = None
      self.port           = None
      self.circuit_code   = None
      
      self.packetReceiver = None 
      self.packetHandler  = None
      
      
    def __sessionLogin(self):

      hash_object = hashlib.md5(self.password)
      md5_hash = hash_object.hexdigest()
      passwd_md5 = '$1$' + md5_hash

      uri = 'https://login.agni.lindenlab.com/cgi-bin/login.cgi'
      s = xmlrpclib.ServerProxy(uri)
     
      login_details = {
        'first': self.username_first,
        'last': self.username_last,
        'passwd': passwd_md5,
        'start': 'last',
        'major': '1',
        'minor': '18',
        'patch': '5',
        'build': '3',
        'platform': 'Win',
        'mac': self.MAC,
        'options': [],
        'user-agent': 'sl.py 0.1',
        'id0': '',
        'agree_to_tos': '',
        'viewer_digest': '09d93740-8f37-c418-fbf2-2a78c7b0d1ea'
      }
      results = s.login_to_simulator(login_details)
      return results
      
    def login(self):

        self.result = self.__sessionLogin()

        if "sim_ip" not in self.result.keys():
          print("WARNING: The login information is likely not correct.")

        self.host         = self.result["sim_ip"]
        self.port         = self.result["sim_port"]
        self.circuit_code = self.result["circuit_code"]

        # Create a process supporting IPv4 and connectionless UDP frames. 
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        self.packetReceiver = PacketReceiver(sock) 
        self.packetHandler  = PacketHandler(sock, self.host, self.port, self.circuit_code, self.result)
     
        self.packetHandler.initializeConnection()
        self.packetHandler.establishAgentPresence()
        self.packetHandler.sendAgentUpdate()
        self.packetHandler.sendUUIDNameRequest()
        
        
    def mainLoop(self):

        while not self.packetHandler.logout_flag:

            self.packetHandler.checkAckRequest()

            self.packetReceiver.pollSocketReceive()
            data = self.packetReceiver.receivedData 
            addr = self.packetReceiver.receivedAddress
            
            packetDecoder = PacketDecoder(data)
            packetDecoder.decodePacket()
            
            self.packetHandler.PacketDecoder = packetDecoder
            self.packetHandler.respondToPacket()

            if not data:
                print("Client has exited!")
                break
                
        self.logout()
        
    def logout(self):

        agentUUID = uuid.UUID(self.result["agent_id"]).bytes
        sessionUUID = uuid.UUID(self.result["session_id"]).bytes

        # --- 
        # Send Logout Request
        packed_data = b''
        packed_data_message_ID = pack('>L',0xffff00fc)
        data_header = pack('>BLB', 0x00,self.packetHandler.seqnum,0x00)
        packed_data += agentUUID + sessionUUID + pack(">L",0x00)
        packed_data = data_header + packed_data_message_ID + packed_data
        sock.sendto(packed_data, (self.host, self.port))
        # --- 
        
        sock.close()
        
       ## --- 
       ## get_caps
        # _, netloc, path, _, _, _ = urlparse(self.result["seed_capability"])
        
        # params = "<llsd><array><string>"+ ["ChatSessionRequest"][0]+"</string></array></llsd>"
        # headers = {"content-type": "application/xml"}
        
        # print("netloc: {}".format(netloc))
        # print("path: {}".format(path))
        # print("params: {}".format(params))
        # print("headers: {}".format(headers))
        
       ## Notice: Certificate Issue.
       ## ssl.SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate (_ssl.c:1007)
        # conn = http.client.HTTPSConnection(netloc)
        # conn.request("POST", path, params, headers)
        # response = conn.getresponse()
        # data = response.read()
        # conn.close()
       ## --- 
        
        
'''
Responsible for packet traffic
By Composition: PacketReceiver, PacketDecoder, PacketHandler.
1 PacketProcessor per Session
'''
class PacketProcessor():
    pass

'''
Responsible for receiving packets
1 Packet Receiver per PacketProcessor
'''
class PacketReceiver():

    def __init__(self, sock): 
        self.BUFFER_SIZE        = 4096
        self.receivedData       = None
        self.receivedAddress    = None
        self.sock               = sock

    def pollSocketReceive(self):
        self.receivedData,self.receivedAddress = self.sock.recvfrom(self.BUFFER_SIZE)
    
'''
Responsible for decoding packets
1 Packet Decoder per PacketProcessor
'''
class PacketDecoder():

    def __init__(self,data):
        self.data = data
        
        self.ID       = None
        
        # Message Priorities (as high, medium, and low in message template.) 
        self.cond_0   = False
        self.cond_1   = False 
        self.cond_2   = False
        
        # Message type field (the first dictionary entry in messages_template.msg)
        self.messageType     = None
        self.messageTypeName = ""
    
    '''
    If bit 7 is set, then use zero decode (returns string) otherwise returns integer
    '''
    def decodePacket(self):
        self.ID = self.data[6:12]
        if ord(chr(self.data[0]))&0x80:  
          self.ID = zero_decode_ID(self.data[6:12])

        #print("Decoded as: {}".format(type(self.ID)))
        self.cond_0   = False
        self.cond_1   = False 
        self.cond_2   = False
        
        if self.ID[0] == ord(b'\xFF'):      # Not-High
          self.cond_0 = True
          if self.ID[1] == ord(b'\xFF'):    # Not-Medium
            self.cond_1 = True
            if self.ID[2] == ord(b'\xFF'):  # Low, Fixed 
              self.cond_2 = True
              self.messageType     = packetdictionary[("Fixed" , "0x"+ByteToHex(self.ID[0:4]).replace(' ', ''))]
            else:                           # Low, Non-Fixed
              self.messageType     = packetdictionary[("Low",int(ByteToHex(self.ID[2:4]).replace(' ', ''),16))]
              self.messageTypeName = self.messageType[0]
        else:
          self.messageType = packetdictionary[("High", int(self.ID[0]))]
          self.messageTypeName = self.messageType[0]    
              
              
              
    def debugID(self):

        print("packetDecoder ID: [2]d'{} {} [1]d'{} {} [0]d'{} {}".format( self.ID[2]  , type(self.ID[2]), 
                                                                           self.ID[1]  , type(self.ID[1]), 
                                                                           self.ID[0]  , type(self.ID[0])
                                                           ) 
                                                        )
                                                        
                                                        


'''
Responsible for Handling incoming packets and generating a response.
1 Packet Handler per PacketProcessor
'''
class PacketHandler():

    def __init__(self, sock, host, port, circuit_code,result):
    
        # Aggregates
        self.sock                  = sock
        self.host                  = host 
        self.port                  = port 
        self.circuit_code          = circuit_code
        
        # Stateful
        self.connectionInitialized = False
        self.presenceEstablished   = False
        self.agentUpdated          = False 
        self.nameRequested         = False
        self.aUUID                 = None
        
        self.PacketDecoder         = None
        self.data                  = None
        
        # default ack settings
        self.lastPingSent          = 0        # Default to 0 
        self.seqnum                = 5        # Default to 5, due to login sequence.
        self.logout_flag           = False
        self.ack_need_list_changed = False
        self.ack_need_list         = []
        # Stub
        self.result                = result
        
        
    def packacks(self):
        acksequence = b''
        for msgnum in self.ack_need_list:
            acksequence += pack("<L", msgnum)

        return acksequence
        
        
    def scheduleacknowledgemessage(self):

        if not ord(chr(self.data[0]))&0x40:
            print("Error: Got asked to ack a message that shouldn't be acked")
        else:
            tmpID = self.data[1:5]

            if (ord(chr(self.data[0]))&0x40) & 0x80: 
              tmpID = zero_decode_ID(tmpId)
              
            self.ack_need_list.append(unpack(">L",tmpID)[0])
        
    '''
    SRP: Initialize connection to the sim
    '''
    def initializeConnection(self):
      # archived note: "Sending packet UseCircuitCode <-- Inits the connection to the sim."
      data = pack('>BLBL',0x00,0x01,00,0xffff0003) + pack('<L',self.circuit_code) + uuid.UUID(self.result["session_id"]).bytes+uuid.UUID(self.result["agent_id"]).bytes
      self.sock.sendto(data, (self.host, self.port))
      
      self.connectionInitialized = True

    
    '''
    SRP: Establish sim presence
    '''
    def establishAgentPresence(self):
      # archived note: "ISending packet CompleteAgentMovement <-- establishes the agent's presence"
      data = pack('>BLBL',0x00,0x02,00,0xffff00f9) + uuid.UUID(self.result["agent_id"]).bytes + uuid.UUID(self.result["session_id"]).bytes + pack('<L', self.circuit_code)
      self.sock.sendto(data, (self.host, self.port))
      
      self.presenceEstablished = True 
    
    '''
    SRP: Send agent update
    '''
    def sendAgentUpdate(self):
        CURRENT_SEQ = 3
        tempacks = self.packacks()
        del self.ack_need_list[:]
        if tempacks == "": 
            flags = 0x00
        else:
            flags = 0x10
     
        # Refactoring needed? Too many lines going on here. "Long Method"
        # Use Extract Method.
        data_header = pack('>BLB', flags,CURRENT_SEQ,0x00)
        packed_data_message_ID = pack('>B',0x04)
        packed_data_ID = uuid.UUID(self.result["agent_id"]).bytes + uuid.UUID(self.result["session_id"]).bytes
        packed_data_QuatRots = pack('<ffff', 0.0,0.0,0.0,0.0)+pack('<ffff', 0.0,0.0,0.0,0.0)  
        packed_data_State = pack('<B', 0x00)
        packed_data_Camera = pack('<fff', 0.0,0.0,0.0)+pack('<fff', 0.0,0.0,0.0)+pack('<fff', 0.0,0.0,0.0)+pack('<fff', 0.0,0.0,0.0)
        packed_data_Flags = pack('<fLB', 0.0,0x00,0x00)
     
        encoded_packed_data = zero_encode(packed_data_message_ID+packed_data_ID+packed_data_QuatRots+packed_data_State+packed_data_Camera+packed_data_Flags)
     
        #these two are bad: (Not sure what this comment refers to.) 
        print(type(encoded_packed_data))
        print(type(tempacks))
        packed_data = data_header + encoded_packed_data + tempacks

        self.sock.sendto(packed_data, (self.host, self.port))
        self.aUUID = [self.result["agent_id"]]
       
       
    '''
    SRP: Send a UUID name request
    '''    
    def sendUUIDNameRequest(self):
        CURRENT_SEQ = 4
        packed_data = b''
        fix_ID = int("ffff0000",16)+ 235

        data_header = pack('>BLB', 0x00,CURRENT_SEQ,0x00) 

        for x in self.aUUID:
            packed_data += uuid.UUID(x).bytes

        packed_data += pack("L",fix_ID) + pack(">B",len(self.aUUID)) + packed_data

        encoded_packed_data = str(packed_data).encode('latin-1')
     
        self.sock.sendto(encoded_packed_data, (self.host, self.port))
        
    def sendRegionHandshake(self):
        packed_data = ""
        low_ID = "ffff00%2x" % 149
        data_header = pack('>BLB', 0x00,currentsequence,0x00)
        packed_data += uuid.UUID(self.result["agent_id"]).bytes+uuid.UUID(self.result["session_id"]).bytes+ pack(">L",0x00)
        packed_data = data_header + pack(">L",int(low_ID,16))+packed_data
        self.sock.sendto(packed_data, (self.host, self.port)) 
        self.seqnum += 1 
        
    def handleChatFromSimulator(self):

        newString = ""

        nameSizeHex = self.data[10]                     # The 11th byte is the size of the name.
        nameSizeInt = nameSizeHex                       # Converted namesize to an integer
        
        name = ByteToHex(self.data[11:nameSizeInt+11])  # Grab the name
        name = name.split()                             # split the name update
        for eachLetter in name:                         # convert to a string.
            newString += chr(int(eachLetter,16))
            
        name = newString

        newString = ""

        messageSizeField = 11 + nameSizeInt + 49
        
        # Byte 17 of the messageSizeField (will return a 1 in this field if agent is typing on the keyboard.
        chatType         = self.data[messageSizeField-17:messageSizeField - 17 +  1] #  from an agent=1
        sourceType       = self.data[messageSizeField-16:messageSizeField - 16 +  1] #  whisper=0, normal=1, shout=2, unknown=3, 4 and 5 may have to do with typing?
        audibleType      = self.data[messageSizeField-15:messageSizeField - 15 +  1] #  from an agent = 1
        
        # Grab everything from the messageSizeField up to the end of the string.
        receivedChat = ByteToHex(self.data[messageSizeField:]) 
        receivedChatList = receivedChat.split()
        for eachletter in receivedChatList:
          newString += chr(int(eachletter,16))
        
        if (ord(sourceType) == 1) and (ord(chatType) == 1):          # excludes the type of messages from agenst that are 4's and 5's (which don't have information)
            print("Got Chat from simulator! Type {} {} {}     {} : {}".format(ord(chatType), ord(sourceType), ord(audibleType),name, newString ))
            
            # Response hook:
            text = newString
            response = "This is my response hook, please hook in a string."

            nameAsList = name.split()
            name = nameAsList[0]
            responseString = name + ", " + response
            print("Sending response from generateResponseString: {}".format(responseString) )

            tmpData = pack('>BLBL',0x40,self.seqnum,0x00,0xffff0050) + uuid.UUID(self.result["agent_id"]).bytes + uuid.UUID(self.result["session_id"]).bytes +  stringToData(responseString)
            
            if RESPONSE_ENABLE == True:
                sock.sendto(tmpData, (self.host, self.port))

        # logout on command (logout softly, when typed in chat.)
        if newString.find("secretLogoutCode") != -1:
            self.logout_flag = True
    '''
    SRP: general response
         ToDo: Implement Polymorphism. Pull from message template.
    '''
    def respondToPacket(self):

        self.data = self.PacketDecoder.data


        # Debug ID fields
        #self.PacketDecoder.debugID()

        if ord(chr(self.data[0]))&0x40:
            self.scheduleacknowledgemessage(); 
            self.ack_need_list_changed = True
        
        if self.PacketDecoder.cond_0 == True:
            if self.PacketDecoder.cond_1 == True:
                if self.PacketDecoder.cond_2 == True:
                    pass
                else:
                    if self.PacketDecoder.messageTypeName == "RegionHandshake":
                        self.sendRegionHandshake()
                        
                    if self.PacketDecoder.messageTypeName == "ChatFromSimulator":
                        self.handleChatFromSimulator()
        else:
            if int(self.PacketDecoder.ID[0]) >= 1 and int(self.PacketDecoder.ID[0]) <=30:
                if self.PacketDecoder.messageTypeName == "StartPingCheck": 
                    print("Starting Ping Check... {}".format(self.lastPingSent))
                    
                    # -----
                    # sendCompletePingCheck
                    data_header = pack('>BLB', 0x00,self.seqnum,0x00)
                    packed_data_message_ID = pack('>B',0x02)
                    packed_data = data_header + packed_data_message_ID+pack('>B', self.lastPingSent)
                    self.sock.sendto(packed_data, (self.host, self.port))
                    self.lastPingSent += 1
                    # -----
                    self.seqnum += 1

                    if self.lastPingSent > 255: 
                        self.lastPingSent = 0
 
    def sendPacketAck(self):
        currentsequence = self.seqnum
        tempacks = self.packacks()
        templen = len(self.ack_need_list)
        del self.ack_need_list[:]
        data_header = pack('>BLB',0x00,currentsequence,0x00) 
        packed_data_message_ID = pack('>L',0xFFFFFFFB)
        packed_ack_len = pack('>B',templen)
     
        packed_data = data_header + packed_data_message_ID + packed_ack_len + tempacks

        self.sock.sendto(packed_data, (self.host, self.port)) 
        
        
    def checkAckRequest(self):
        if self.ack_need_list_changed:
            self.ack_need_list_changed = False
            self.seqnum += 1
            self.sendPacketAck()
            self.seqnum += 1
        


#********
#  Main
#********
packetdictionary = makepacketdict()
session = Session(username_first,username_last, password, MAC)
session.login()
session.mainLoop()



'''
Refer to message_template.msg
'''
 
'''
Data Types:
'''
# Null - no data, 0 bytes wide
# Fixed - byte array, interpreted depending on packet type, width determined in message definition
# Variable 1 - first byte determines number of bytes that follow (U8)
# Variable 2 - first two bytes determine number of bytes that follow (U16, big-endian in UDP Packet Layouts)
# U8 - unsigned byte, 1 byte wide
# U16 - unsigned short, 2 bytes wide (little-endian in UDP packet layouts)
# U32 - unsigned int, 4 bytes wide (little-endian in UDP packet layouts)
# U64 - unsigned long, 8 bytes wide (little-endian in UDP packet layouts)
# S8 - signed byte, 1 byte wide
# S16 - signed short, 2 bytes wide (little-endian in UDP packet layouts)
# S32 - signed int, 4 bytes wide (little-endian in UDP packet layouts)
# S64 - signed long, 8 bytes wide (little-endian in UDP packet layouts)
# F32 - float, 4 bytes wide
# F64 - double, 8 bytes wide
# LLVector3 - triplet of floats, 12 bytes wide
# LLVector3d - triplet of doubles, 24 bytes wide
# LLVector4 - quad of floats, 16 bytes wide
# LLQuaternion - because it's always a unit quaternion, transmitted in messages as a triplet of floats, 12 bytes wide (represented in memory as a quad of floats, 16 bytes wide)
# LLUUID - Universal ID, 16 bytes wide
# BOOL - 0 or 1, 1 byte wide
# IPADDR - IP Address, one place per byte, 4 bytes wide
# IPPORT - IP Port, two bytes wide
# U16Vec3 - not used
# U16Quat - not used
# S16Array - not used