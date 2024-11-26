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

username_first = "AstroTester"
username_last = "resident" 
password = b'p@ssw0rd'

# Response is gated here (set to true for bot to chat back.) 
RESPONSE_ENABLE = False
DEBUG_ENABLE    = False

packetdictionary = {}
outputstring = ''
ack_need_list = []
logoutputflag = False

 
if logoutputflag:
    temp = sys.stdout
    sys.stdout =open('alog.txt','w')
 
def login(first, last, passwd, mac):

  text = passwd
  hash_object = hashlib.md5(password)
  md5_hash = hash_object.hexdigest()
  passwd_md5 = '$1$' + md5_hash

  uri = 'https://login.agni.lindenlab.com/cgi-bin/login.cgi'
  s = xmlrpclib.ServerProxy(uri)
 
  login_details = {
    'first': first,
    'last': last,
    'passwd': passwd_md5,
    'start': 'last',
    'major': '1',
    'minor': '18',
    'patch': '5',
    'build': '3',
    'platform': 'Win',
    'mac': mac,
    'options': [],
    'user-agent': 'sl.py 0.1',
    'id0': '',
    'agree_to_tos': '',
    'viewer_digest': '09d93740-8f37-c418-fbf2-2a78c7b0d1ea'
  }
  results = s.login_to_simulator(login_details)
  print(results)
 
  return results

def get_caps(results,cap_key, request_keys):
 
  _, netloc, path, _, _, _ = urlparse(results[cap_key])
 
  params = "<llsd><array><string>"+ request_keys[0]+"</string></array></llsd>"
  headers = {"content-type": "application/xml"}
  conn = httplib.HTTPSConnection(netloc)
 
  conn.request("POST", path, params, headers)
  response = conn.getresponse()

  data = response.read()
  conn.close()
  return data
 
def ExtractCap(cap_result):
  trim_xml = re.compile(r"<key>([a-zA-Z_]+)</key><string>([a-zA-Z_:/0-9-.]+)</string>")
  new_key = trim_xml.search(cap_result).group(1)
  new_cap = trim_xml.search(cap_result).group(2)
  return new_key, new_cap

def scheduleacknowledgemessage(data):

    if not ord(chr(data[0]))&0x40:
        print("OOOPS! Got asked to ack a message that shouldn't be acked")
    else:
        ID = data[1:5]

        if (ord(chr(data[0]))&0x40) & 0x80: ID = zero_decode_ID(ID)
        ack_need_list.append(unpack(">L",ID)[0])
 
def packacks():
    acksequence = b''
    for msgnum in ack_need_list:
        acksequence += pack("<L", msgnum)

    return acksequence
 
'''
Refer to message_template.msg
'''
def sendUUIDNameRequest(sock, port, host, currentsequence,aUUID):
 
    packed_data = b''
    fix_ID = int("ffff0000",16)+ 235
    data_header = pack('>BLB', 0x00,currentsequence,0x00) 

    for x in aUUID:
        packed_data += uuid.UUID(x).bytes

    packed_data += pack("L",fix_ID) + pack(">B",len(aUUID)) + packed_data

    encoded_packed_data = str(packed_data).encode('latin-1')
 
    sock.sendto(encoded_packed_data, (host, port))
 
def sendRegionHandshakeReply(sock, port, host, currentsequence,agentUUID,sessionUUID):
    packed_data = ""
 
    low_ID = "ffff00%2x" % 149
    data_header = pack('>BLB', 0x00,currentsequence,0x00)
    packed_data += uuid.UUID(agentUUID).bytes+uuid.UUID(sessionUUID).bytes+ pack(">L",0x00)
    packed_data = data_header + pack(">L",int(low_ID,16))+packed_data
    sock.sendto(packed_data, (host, port)) 
 
 
 
def sendAgentUpdate(sock, port, host, currentsequence, result):
 
    tempacks = packacks()
    del ack_need_list[:]
    if tempacks == "": 
        flags = 0x00
    else:
        flags = 0x10
 
    data_header = pack('>BLB', flags,currentsequence,0x00)
    packed_data_message_ID = pack('>B',0x04)
    packed_data_ID = uuid.UUID(result["agent_id"]).bytes + uuid.UUID(result["session_id"]).bytes
    packed_data_QuatRots = pack('<ffff', 0.0,0.0,0.0,0.0)+pack('<ffff', 0.0,0.0,0.0,0.0)  
    packed_data_State = pack('<B', 0x00)
    packed_data_Camera = pack('<fff', 0.0,0.0,0.0)+pack('<fff', 0.0,0.0,0.0)+pack('<fff', 0.0,0.0,0.0)+pack('<fff', 0.0,0.0,0.0)
    packed_data_Flags = pack('<fLB', 0.0,0x00,0x00)
 
    encoded_packed_data = zero_encode(packed_data_message_ID+packed_data_ID+packed_data_QuatRots+packed_data_State+packed_data_Camera+packed_data_Flags)
 
    #these two are bad: 
    print(type(encoded_packed_data))
    print(type(tempacks))
    packed_data = data_header + encoded_packed_data + tempacks

    sock.sendto(packed_data, (host, port))
 
def sendCompletePingCheck(sock, port, host, currentsequence,data,lastPingSent):
 
    data_header = pack('>BLB', 0x00,currentsequence,0x00)
    packed_data_message_ID = pack('>B',0x02)
    packed_data = data_header + packed_data_message_ID+pack('>B', lastPingSent)

    sock.sendto(packed_data, (host, port))
 
def sendPacketAck(sock, port, host,currentsequence):
 
    tempacks = packacks()
    templen = len(ack_need_list)
    del ack_need_list[:]
    data_header = pack('>BLB',0x00,currentsequence,0x00) 
    packed_data_message_ID = pack('>L',0xFFFFFFFB)
    packed_ack_len = pack('>B',templen)
 
    packed_data = data_header + packed_data_message_ID + packed_ack_len + tempacks

    sock.sendto(packed_data, (host, port))
 
def sendLogoutRequest(sock, port, host,seqnum,aUUID,sUUID):
    packed_data = b''
    packed_data_message_ID = pack('>L',0xffff00fc)
    data_header = pack('>BLB', 0x00,seqnum,0x00)
    packed_data += aUUID + sUUID+ pack(">L",0x00)
    packed_data = data_header + packed_data_message_ID + packed_data
    sock.sendto(packed_data, (host, port))
 
 
 
def display_payload(addr, seqnum, data):
    print("- "*25)
    print("Address: {} Sequence Number: {}".format(addr, seqnum))
    print("Payload:")
    print(data)
    print("- "*25) 

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
    pass 

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

    def __init__(self, sock, host, port, circuit_code):
    
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
        
        self.lastPingSent          = 0
        self.seqnum                = 0
        
        self.logout_flag           = False
        
    '''
    SRP: Initialize connection to the sim
    '''
    def initializeConnection(self):
      # archived note: "Sending packet UseCircuitCode <-- Inits the connection to the sim."
      data = pack('>BLBL',0x00,0x01,00,0xffff0003) + pack('<L',self.circuit_code) + uuid.UUID(result["session_id"]).bytes+uuid.UUID(result["agent_id"]).bytes
      self.sock.sendto(data, (self.host, self.port))
      
      self.connectionInitialized = True

    
    '''
    SRP: Establish sim presence
    '''
    def establishAgentPresence(self):
      # archived note: "ISending packet CompleteAgentMovement <-- establishes the agent's presence"
      data = pack('>BLBL',0x00,0x02,00,0xffff00f9) + uuid.UUID(result["agent_id"]).bytes + uuid.UUID(result["session_id"]).bytes + pack('<L', self.circuit_code)
      self.sock.sendto(data, (self.host, self.port))
      
      self.presenceEstablished = True 
    
    '''
    SRP: Send agent update
    '''
    def sendAgentUpdate(self):
        CURRENT_SEQ = 3
        tempacks = packacks()
        del ack_need_list[:]
        if tempacks == "": 
            flags = 0x00
        else:
            flags = 0x10
     
        # Refactoring needed? Too many lines going on here. "Long Method"
        # Use Extract Method.
        data_header = pack('>BLB', flags,CURRENT_SEQ,0x00)
        packed_data_message_ID = pack('>B',0x04)
        packed_data_ID = uuid.UUID(result["agent_id"]).bytes + uuid.UUID(result["session_id"]).bytes
        packed_data_QuatRots = pack('<ffff', 0.0,0.0,0.0,0.0)+pack('<ffff', 0.0,0.0,0.0,0.0)  
        packed_data_State = pack('<B', 0x00)
        packed_data_Camera = pack('<fff', 0.0,0.0,0.0)+pack('<fff', 0.0,0.0,0.0)+pack('<fff', 0.0,0.0,0.0)+pack('<fff', 0.0,0.0,0.0)
        packed_data_Flags = pack('<fLB', 0.0,0x00,0x00)
     
        encoded_packed_data = zero_encode(packed_data_message_ID+packed_data_ID+packed_data_QuatRots+packed_data_State+packed_data_Camera+packed_data_Flags)
     
        #these two are bad: 
        print(type(encoded_packed_data))
        print(type(tempacks))
        packed_data = data_header + encoded_packed_data + tempacks

        self.sock.sendto(packed_data, (self.host, self.port))
        self.aUUID = [result["agent_id"]]
       
       
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
        sendRegionHandshakeReply(self.sock, self.port, self.host, self.seqnum,result["agent_id"],result["session_id"])
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

            tmpData = pack('>BLBL',0x40,self.seqnum,0x00,0xffff0050) + uuid.UUID(result["agent_id"]).bytes + uuid.UUID(result["session_id"]).bytes +  stringToData(responseString)
            
            if RESPONSE_ENABLE == True:
                sock.sendto(tmpData, (self.host, self.port))

        # logout on command (logout softly, when typed in chat.)
        if newString.find("secretLogoutCode") != -1:
            self.logout_flag = True
    '''
    SRP: general response
         ToDo: Cover all cases.
    '''
    def respondToPacket(self,sequenceNumerAsMutable, lastPingSentAsMutable):
        # Mutables, pass by reference
        self.seqnum       = sequenceNumerAsMutable[0]
        self.lastPingSent = lastPingSentAsMutable[0]
        
        self.data = self.PacketDecoder.data
        
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
            pass
            
        # Mutables, out.
        sequenceNumerAsMutable[0] = self.seqnum
        lastPingSentAsMutable[0]  = self.lastPingSent
        

# Refactoring needed? Too many lines going on here. "Bloating"
# What is "Presence" and why is it needed?
def establishpresence(host, port, circuit_code):
 
    # Create a process supporting IPv4 and connectionless UDP frames. 
    # defaults socket(family=AF_Inet, type=SOCK_STREAM, proto=0, fileno=None)
    # defaults to blocking mode.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    packetReceiver = PacketReceiver(sock) 
    packetHandler  = PacketHandler(sock, host, port, circuit_code)
 
    packetHandler.initializeConnection()
    packetHandler.establishAgentPresence()
    packetHandler.sendAgentUpdate()
    packetHandler.sendUUIDNameRequest()

    ack_need_list_changed = False
    seqnum       = [5]
    lastPingSent = [0] 

    while not packetHandler.logout_flag:

        if ack_need_list_changed:
            ack_need_list_changed = False
            seqnum[0] += 1
            sendPacketAck(sock, port, host,seqnum[0])

            seqnum[0] += 1

        # Automatic garbage collection
        # objects are decomissioned when no longer needed. 
        packetReceiver.pollSocketReceive()
        data = packetReceiver.receivedData 
        addr = packetReceiver.receivedAddress
        
        packetDecoder = PacketDecoder(data)
        packetDecoder.decodePacket()
        
        packetHandler.PacketDecoder = packetDecoder
        packetHandler.respondToPacket(seqnum,lastPingSent)
        
        if DEBUG_ENABLE:
          display_payload(addr, seqnum[0], data)

        if not data:
            print("Client has exited!")
            break
            
        else:
            # Debug the condition fields
            #packetDecoder.debugID()

            if ord(chr(data[0]))&0x40:
                scheduleacknowledgemessage(data); 
                ack_need_list_changed = True

            if packetDecoder.cond_0 == True:
                if packetDecoder.cond_1 == True:
                    if packetDecoder.cond_2 == True:
                        pass
                    else:
                        pass
            else:
                if int(packetDecoder.ID[0]) >= 1 and int(packetDecoder.ID[0]) <=30:
                    if packetDecoder.messageTypeName == "StartPingCheck": 
                        print("Starting Ping Check... {}".format(lastPingSent))
                        sendCompletePingCheck(sock, port, host, seqnum[0],data,lastPingSent[0])
                        lastPingSent[0] += 1
                        seqnum[0] += 1

                        if lastPingSent[0] > 255: 
                            lastPingSent[0] = 0


    agentUUID = uuid.UUID(result["agent_id"]).bytes
    sessionUUID = uuid.UUID(result["session_id"]).bytes
    sendLogoutRequest(sock, port, host,seqnum[0],agentUUID,sessionUUID) 
    sock.close()

#********
#  Main
#********
MAC = '2C:54:91:88:C9:E3'
result = login(username_first,username_last, password, MAC)

packetdictionary = makepacketdict()
 
if "sim_ip" not in result.keys():
  print("\n\r"*3)
  print("* "*35)
  print("WARNING: The login information is likely not correct.")
  print("         username or password could be wrong.")
  print("")
  print("* "*35)
  
myhost = result["sim_ip"]
myport = result["sim_port"]
mycircuit_code = result["circuit_code"]
 
establishpresence(myhost, myport, mycircuit_code)
 
cap_out = get_caps(result,"seed_capability", ["ChatSessionRequest"])
 
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