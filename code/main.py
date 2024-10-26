from struct import *
#from zerocode import  *

import hashlib

import xmlrpc
import xmlrpc.client as xmlrpclib

import sys 
import re
import socket, sys, time
import uuid
from datetime import datetime
from mainHelpers import *
import random


username_first = "AstroTester"
username_last = "resident" 
password = b'@$590AAman'

 
mypacketdictionary = {}
outputstring = ''
ack_need_list = []
logoutputflag = False
 
if logoutputflag:
    temp = sys.stdout
    sys.stdout =open('alog.txt','w')
 
def login(first, last, passwd, mac):
  #passwd_md5 = '$1$' + md5.new(passwd).hexdigest()
  
  #convertedHash = hashlib.md5(b'@$590AAman')
  
  text = passwd
  #hash_object = hashlib.md5(text.encode())
  hash_object = hashlib.md5(password)
  md5_hash = hash_object.hexdigest()
  passwd_md5 = '$1$' + md5_hash
  
 
  uri = 'http://127.0.0.1'
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
    #if not ord(data[0])&0x40:
    if not ord(chr(data[0]))&0x40:
        print("OOOPS! Got asked to ack a message that shouldn't be acked")
 
        return
    else:
        ID = data[1:5]
        #if (ord(data[0])&0x40) & 0x80: ID = zero_decode_ID(ID) #impossible
        if (ord(chr(data[0]))&0x40) & 0x80: ID = zero_decode_ID(ID) #impossible
        ack_need_list.append(unpack(">L",ID)[0])
        #ack_need_list.append(unpack(">L",data[1:5])[0])
        #print "ack needed","insdie schedule ack_need_list", ack_need_list
 
 
    return
 
def packacks():
    acksequence = b''
    for msgnum in ack_need_list:
        acksequence += pack("<L", msgnum)
 
 
    return acksequence
 
#def sendacks():
 #   if len(ack_need_list)>0:
 
 
#===============================================================================
# {
#    UUIDNameRequest Low NotTrusted Unencoded
#    {
#        UUIDNameBlock    Variable
#        {    ID            LLUUID    }
#    }
# }
#===============================================================================
 
def sendUUIDNameRequest(sock, port, host, currentsequence,aUUID):
 
    #packed_data = ""
    packed_data = b''  #declare as empty bytes
    fix_ID = int("ffff0000",16)+ 235
    data_header = pack('>BLB', 0x00,currentsequence,0x00) 
 
 
    for x in aUUID:
        packed_data += uuid.UUID(x).bytes

    packed_data += pack("L",fix_ID) + pack(">B",len(aUUID)) + packed_data

    encoded_packed_data = str(packed_data).encode('latin-1')
 
    sock.sendto(encoded_packed_data, (host, port))
    return              
 
def sendRegionHandshakeReply(sock, port, host, currentsequence,agentUUID,sessionUUID):
    packed_data = ""
 
    low_ID = "ffff00%2x" % 149
    data_header = pack('>BLB', 0x00,currentsequence,0x00)
    packed_data += uuid.UUID(agentUUID).bytes+uuid.UUID(sessionUUID).bytes+ pack(">L",0x00)
    packed_data = data_header + pack(">L",int(low_ID,16))+packed_data
    sock.sendto(packed_data, (host, port)) 
    #print "RegionHandshakeReply", ByteToHex(packed_data)
    return
 
 
 
def sendAgentUpdate(sock, port, host, currentsequence, result):
 
    tempacks = packacks()
    del ack_need_list[:]
    if tempacks == "": 
        flags = 0x00
    else:
        flags = 0x10
 
    #print "tempacks is:", ByteToHex(tempacks)  
 
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

   # print "sending AgentUpdate to server",ByteToHex(packed_data_header+zero_decode(encoded_packed_data)+ tempacks)
 
    sock.sendto(packed_data, (host, port))
    return
 
def sendCompletePingCheck(sock, port, host, currentsequence,data,lastPingSent):
 
    data_header = pack('>BLB', 0x00,currentsequence,0x00)
    packed_data_message_ID = pack('>B',0x02)
    packed_data = data_header + packed_data_message_ID+pack('>B', lastPingSent)
    #print "CompletePingCheck packet sent:", ByteToHex(packed_data)
    sock.sendto(packed_data, (host, port))
 
    return
 
def sendPacketAck(sock, port, host,currentsequence):
 
    tempacks = packacks()
    templen = len(ack_need_list)
    del ack_need_list[:]
    data_header = pack('>BLB',0x00,currentsequence,0x00) 
    packed_data_message_ID = pack('>L',0xFFFFFFFB)
    packed_ack_len = pack('>B',templen)
 
    packed_data = data_header + packed_data_message_ID + packed_ack_len + tempacks
#===============================================================================
#    t = datetime.now()
#    t.strftime("%H:%M:%S")
#    ti = "%02d:%02d:%02d.%06d" % (t.hour,t.minute,t.second,t.microsecond)
#    print ti, "PacketAck packet sent:", ByteToHex(packed_data)
#===============================================================================
    sock.sendto(packed_data, (host, port))
    return
 
def sendLogoutRequest(sock, port, host,seqnum,aUUID,sUUID):
    packed_data = b''
    packed_data_message_ID = pack('>L',0xffff00fc)
    data_header = pack('>BLB', 0x00,seqnum,0x00)
    packed_data += aUUID + sUUID+ pack(">L",0x00)
    packed_data = data_header + packed_data_message_ID + packed_data
    sock.sendto(packed_data, (host, port))
    return
 
 
def establishpresence(host, port, circuit_code):
 
 
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#Sending packet UseCircuitCode <-- Inits the connection to the sim.
    data = pack('>BLBL',0x00,0x01,00,0xffff0003) + pack('<L',circuit_code) + uuid.UUID(result["session_id"]).bytes+uuid.UUID(result["agent_id"]).bytes
    sock.sendto(data, (host, port))
 
#ISending packet CompleteAgentMovement <-- establishes the agent's presence
    data = pack('>BLBL',0x00,0x02,00,0xffff00f9) + uuid.UUID(result["agent_id"]).bytes + uuid.UUID(result["session_id"]).bytes + pack('<L', circuit_code)
    sock.sendto(data, (host, port))
 
    sendAgentUpdate(sock, port, host, 3, result)
    aUUID = [result["agent_id"]]
    
    sendUUIDNameRequest(sock, port, host, 4,aUUID)

    #buf = 100 #This buffer is way to small, change to something larger!
    buf = 65507
    i = 0
    trusted_count = 0
    ackable = 0
    trusted_and_ackable = 0
    ack_need_list_changed = False
    seqnum = 5
    lastPingSent = 0 
    trusted = 0
    
    chatFlag = True
    chatCounter = 0
    
    CHAT_FREQUENCY = 4
    chatCount = 0

    seqnumLast = 0
    #adding variables for sending chat to the simulator 9.30.2021
    logout_flag = False
    chatFlag = True
    performGreeting = True
    
    while not logout_flag:
        if ack_need_list_changed:
            ack_need_list_changed = False
            seqnum += 1
            sendPacketAck(sock, port, host,seqnum)
            #sendAgentUpdate(sock, port, host, seqnum, result)
            seqnum += 1
        #sendacks()
        i += 1
        data,addr = sock.recvfrom(buf)
        t = datetime.now()
        t.strftime("%H:%M:%S")
 
 
 
        if not data:
            print("Client has exited!")
 
            break
        else:
            #test =  ByteToHex(data).split()
            #print("test data: {}".format(test) )
            
            ID = data[6:12]
            #print("ID ={}".format( ByteToHex(ID) ) )

            #print("data[0] is : 0x{:x}".format(data[0]))

            #if ord(data[0])&0x80: 10.2.2021
            if ord(chr(data[0]))&0x80:  
                ID = zero_decode_ID(data[6:12])
 
            #if ord(data[0])&0x40:
            if ord(chr(data[0]))&0x40:
                scheduleacknowledgemessage(data); 
                ack_need_list_changed = True
            #print "ID =", ByteToHex(ID) 
            #print "ID =", unpack(">L", ID[:4])
            if ID[0] == ord(b'\xFF'):
                if ID[1] == ord(b'\xFF'):
                    if ID[2] == ord(b'\xFF'):
                        myentry = mypacketdictionary[("Fixed" , "0x"+ByteToHex(ID[0:4]).replace(' ', ''))]
                        if myentry[1] == "Trusted":
                            trusted += 1;
                        ti = "%02d:%02d:%02d.%06d" % (t.hour,t.minute,t.second,t.microsecond)

                        #print ti, "Message (A) #", i, "trusted count is", trusted,"Flags: 0x" + test[0], myentry,  "sequence #", unpack(">L",data[1:5])
 
                        #if myentry[1] == "Trusted": trusted_count += 1;print "number of trusted messages =", trusted_count
                        #if ord(data[0])&0x40 and myentry[1] == "Trusted": trusted_and_ackable += 1; print "trusted_and_ackable =", trusted_and_ackable
                        #if ord(data[0])&0x40: ackable += 1; print "number of ackable messages = ", ackable
                    else:
               
                        myentry = mypacketdictionary[("Low",int(ByteToHex(ID[2:4]).replace(' ', ''),16))]
                        if myentry[1] == "Trusted":
                            trusted += 1;
                        ti = "%02d:%02d:%02d.%06d" % (t.hour,t.minute,t.second,t.microsecond)
                        #Muting messages (unmute this block below 9.26.2021
                        #print ti, "Message (B) #", i,"trusted count is", trusted,"Flags: 0x" + test[0], myentry,   "sequence #", unpack(">L",data[1:5])
                        if myentry[0] == "UUIDNameReply":
                            pass
                            #print ByteToHex(data)
                            #print data[:28]
                            #print data[28:36],data[38:45]
                        elif myentry[0] == "RegionHandshake":
                            sendRegionHandshakeReply(sock, port, host, seqnum,result["agent_id"],result["session_id"])
                            seqnum += 1
                          
                        #----------------------------------------------------------------------------
                        if myentry[0] == "ChatFromSimulator":

                        
                            newString = ""
                            debugString = ""
                            
                            nameSizeHex = data[10]                     #The 11th byte is the size of the name.
                            nameSizeInt = nameSizeHex                  #Converted namesize to an integer
                            
                            name = ByteToHex(data[11:nameSizeInt+11])  #Grab the name
                            name = name.split()                        #split the name update
                            for eachLetter in name:                    #convert to a string.
                                newString += chr(int(eachLetter,16))
                                
                            name = newString

                            newString = "" #reset the string
                            
                            #messageSizeField = 11 + nameSizeInt + 68 (should be byte 68 but isn't, why is that?)
                            messageSizeField = 11 + nameSizeInt + 49
                            
                            #Byte 17 of the messageSizeField (will return a 1 in this field if agent is typing on the keyboard.
                            chatType         = data[messageSizeField-17:messageSizeField - 17 +  1] #we just want one byte, not a while string here. 1 = from an agent
                            sourceType       = data[messageSizeField-16:messageSizeField - 16 +  1] #we just want one byte, not a while string here. 0 = whisper 1 = normal 2 = shout, 3 = unknown, 4 and 5 may have to do with typing?
                            audibleType      = data[messageSizeField-15:messageSizeField - 15 +  1] #we just want one byte, not a while string here. 1 = from an agent
                            
                            #Grab everything from the messageSizeField up to the end of the string.
                            receivedChat = ByteToHex(data[messageSizeField:]) 
                            receivedChatList = receivedChat.split()
                            for eachletter in receivedChatList:
                              newString += chr(int(eachletter,16))
                            
                            
                            #ord() converts the byte or string character 'a' representation into an integer number.
                            if ( (ord(sourceType) == 1) and (chatFlag == True) ):                #excludes the type of messages from agenst that are 4's and 5's (which don't have information)
                                print("Got Chat from simulator! Type {} {} {}     {} : {}".format(ord(chatType), ord(sourceType), ord(audibleType),name, newString ))
                                
                                # Rate Limit the amount of interaction
                                # So the bot doesn't spam the chat.
                                chatCount += 1
                                print("chatCount is now: {} out of {}".format(chatCount, CHAT_FREQUENCY))
                                if (chatCount > CHAT_FREQUENCY) or (performGreeting == True):
                                    chatCount = 0
                                    CHAT_FREQUENCY = random.randint(2,5)
                                    
                                    #-------------  Conversational Language Model ---------------------------
                                    text = newString
                                    response = "This is my response hook, please hook in a string."
                                    #-------------------------------------------------------------
                                    
                                    
                                    nameAsList = name.split()
                                    name = nameAsList[0]
                                    responseString = name + ", " + response
                                    print("Sending response from generateResponseString: {}".format(responseString) )
                                    
                                    if performGreeting == True:
                                        performGreeting = False
                                        responseString = "Yo, what's up my fellow SL residents?"
                                    
                                    data = pack('>BLBL',0x40,seqnum,0x00,0xffff0050) + uuid.UUID(result["agent_id"]).bytes + uuid.UUID(result["session_id"]).bytes +  stringToData(responseString)
                                    sock.sendto(data, (host, port))
                                    print("sending message to server! {}".format(responseString))
                                    chatFlag = False

                            #print("Raw data received! {}".format( receivedChat )) #for debug, but will need the whole packet, this is only partial.
                            # Something in this is incorrect because we can receive the start of a message on byte 49 and not 68
                            # Receiving chat does return different status flags (So we can know whether someone is typing, or something else.)
                            # {	FromName		Variable 1	}  (First Byte determines number of bytes that follow)
                            # {	SourceID		LLUUID		}  16 bytes wide
                            # {	OwnerID			LLUUID		}  16 bytes wide
                            # {	SourceType		U8			}  8 bits 
                            # {	ChatType		U8			}  8 bits
                            # {	Audible			U8			}  8 bit_length
                            # {	Position		LLVector3	}  12 bytes wide
                            # {	Message			Variable 2	}  (First two bytes determine number of bytes that follow)
                            #----------------------------------------------------------------------------

                            if newString.find("train") != -1:
                                print("Training now...")

                            #logout on command (logout softly.)
                            if newString.find("secretlogoutmessage") != -1:
                                logout_flag = True
                                
                            if newString.find("hi") != -1:
                              print("placeholder")
                              # data = pack('>BLBL',0x40,seqnum,0x00,0xffff0054) + uuid.UUID(result["agent_id"]).bytes + uuid.UUID(result["session_id"]).bytes +  pack('>BB',0x04,0x00) +  pack('>BBBB',0x46, 0x75, 0x64,0x0) + pack('>B', 0x01) + pack('>L',0x00)
                              # sock.sendto(data, (host, port))
                            
                              # sendLogoutRequest(sock, port, host,seqnum,uuid.UUID(result["agent_id"]).bytes,uuid.UUID(result["session_id"]).bytes) 
                            
                              # >BLBL means to pack the following parameters as "Byte, Long, Byte, Long" (and packs these into the packet
                              # UUID is self explanatory. These are 16 bytes each. (see the manifest and Data types (at end of this file.)
                              # pack('>BB',0x04,0x00) is 2 bytes of message size. followed by the messagte itself, this includes a null terminatio 0x00 or \0 
                              # After the message is the chat type, here is set to normal '1'
                              # Finally the channel as a 4 byte word, General chat is '0'
                            
                              # Note all message types are encoded "Low 80" is 0x50, see the manifest for the encodings. (This is where we get 0xFFFF_0050 from)
                                                                                                                                                                     

                            if newString.find("appearance") != -1:
                              print("not doing appearnce stuff now, this is complicated!")
                              # data = pack('>BLBL',0x40,seqnum,0x00,0xffff0054) + uuid.UUID(result["agent_id"]).bytes + uuid.UUID(result["session_id"]).bytes +  pack('>BB',0x04,0x00) +  pack('>BBBB',0x46, 0x75, 0x64,0x0) + pack('>B', 0x01) + pack('>L',0x00)
                              # sock.sendto(data, (host, port))
                            

                            
                             
                            
                        #if myentry[1] == "Trusted": trusted_count += 1;print "number of trusted messages =", trusted_count
                        #if ord(data[0])&0x40 and myentry[1] == "Trusted": trusted_and_ackable += 1; print "trusted_and_ackable =", trusted_and_ackable
                        #if ord(data[0])&0x40: ackable += 1; print "number of ackable messages = ", ackable
                else:
                    myentry = mypacketdictionary[("Medium", int(ByteToHex(ID[1:2]).replace(' ', ''),16))]
                    if myentry[1] == "Trusted":
                        trusted += 1;
                    ti = "%02d:%02d:%02d.%06d" % (t.hour,t.minute,t.second,t.microsecond)
                    #Muting messages (unmute this block below 9.26.2021
                    #print ti, "Message (C) #", i,"trusted count is", trusted,"Flags: 0x" + test[0], myentry,  "sequence #", unpack(">L",data[1:5])
 

                       
                       
                    #if myentry[1] == "Trusted": trusted_count += 1;print "number of trusted messages =", trusted_count
                    #if ord(data[0])&0x40 and myentry[1] == "Trusted": trusted_and_ackable += 1; print "trusted_and_ackable =", trusted_and_ackable
                    #if ord(data[0])&0x40: ackable += 1; print "number of ackable messages = ", ackable
            else:
   
                #print("ID[0] is a string object : {}".format(ID[0]))
                
                
                if int(ID[0]) >= 1 and int(ID[0]) <=30:
                    #myentry = mypacketdictionary[("High", int(ByteToHex(ID[0]), 16))]
                    myentry = mypacketdictionary[("High", int(ID[0]))]
                    if myentry[0] == "StartPingCheck": 
                        print("Starting Ping Check... {}".format(lastPingSent))
                        #Useful for debugging 9/26/2021
                        #print "data from StartPingCheck", test
                        sendCompletePingCheck(sock, port, host, seqnum,data,lastPingSent)
                        lastPingSent += 1
                        seqnum += 1
                        
                        chatFlag = True
                        
                        
                        if lastPingSent > 255: 
                            lastPingSent = 0
     
                    if myentry[1] == "Trusted":
                        trusted += 1;   
                    ti = "%02d:%02d:%02d.%06d" % (t.hour,t.minute,t.second,t.microsecond)
                    #Muting messages (unmute this block below 9.26.2021
                    #print ti, "Message (D) #", i,"trusted count is", trusted,"Flags: 0x" + test[0], myentry,   "sequence #", unpack(">L",data[1:5])

                    #if myentry[1] == "Trusted": trusted_count += 1;print "number of trusted messages =", trusted_count
                    #if ord(data[0])&0x40 and myentry[1] == "Trusted": trusted_and_ackable += 1; print "trusted_and_ackable =",  trusted_and_ackable
                    #if ord(data[0])&0x40: ackable += 1; print "number of ackable messages = ", ackable

 
    #sendLogoutRequest(sock, port, host,seqnum,myAgentID,mySessionID) 
    agentUUID = uuid.UUID(result["agent_id"]).bytes
    sessionUUID = uuid.UUID(result["session_id"]).bytes
    sendLogoutRequest(sock, port, host,seqnum,agentUUID,sessionUUID) 
    sock.close()
    print ("final number of trusted messages ={}".format(trusted_count) )
 
    return
 

 
 

#************************************************************************************************
#                        Main
#************************************************************************************************
 
# OOps! Tries to run the code when imported...derp!
 
MAC = '2C:54:91:88:C9:E3'
result = login(username_first,username_last, password, MAC)

 
mypacketdictionary = makepacketdict()
 
myhost = result["sim_ip"]
myport = result["sim_port"]
mycircuit_code = result["circuit_code"]
 
establishpresence(myhost, myport, mycircuit_code)
 
cap_out = get_caps(result,"seed_capability", ["ChatSessionRequest"])
 
#Data Types:
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
 
 
 
 
 
 
 
 
 