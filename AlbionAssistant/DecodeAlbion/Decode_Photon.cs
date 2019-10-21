﻿//
// AlbionAssistant
// Copyright (C) 2019 by David W. Jeske
//

#define HIDE_PARSE_ERRORS

using System;
using System.IO;
using System.Collections.Generic;
using Be.IO;

// PhotonObserver
//
// This is an observer for the "Photon Engine" network communication layer used by Albion
// https://www.photonengine.com/en-us/Photon
// https://doc.photonengine.com/en-us/realtime/current/reference/serialization-in-photon
// https://doc.photonengine.com/en-us/realtime/current/reference/binary-protocol
// 
// https://github.com/broderickhyman/photon_spectator
// https://github.com/AltspaceVR/wireshark-photon-dissector/blob/master/photon.lua
//

namespace AlbionAssistant {


    public static class ReadBytesToEndExtension {
        public static byte[] ReadBytesToEnd<BinaryReader>(this BinaryReader binaryReader) {
            var byte_acc = new List<byte>();            

            return byte_acc.ToArray();
        }
    }

    public class PhotonDecoder {

        public delegate void Delegate_PhotonEvent_Info(string info);
        public event Delegate_PhotonEvent_Info Event_Photon_Info;

        public delegate void Delegate_PhotonEvent_ReliableDatum(ReliableMessage_Response info);
        public event Delegate_PhotonEvent_ReliableDatum Event_Photon_ReliableResponse;


        public void decodeUDPPacket(BinaryReader packet) {

            const int CMD_HDR_LEN = 12;

            // read Photon Header
            packet.ReadUInt16(); // PeerID
            packet.ReadByte(); // CrcEnabled
            int cmd_count = (int)packet.ReadByte(); // Command Count
            packet.ReadUInt32(); // Timestamp
            packet.ReadInt32(); // Challenge

            Event_Photon_Info?.Invoke(String.Format("Photon Packet with ({0}) commands", cmd_count));

            for (int cmd_number = 0; cmd_number < cmd_count; cmd_number++) {
                // read photon command header
                CommandType cmd_type = (CommandType)packet.ReadByte(); // Type
                int cmd_channel_id = packet.ReadByte(); // ChannelID
                packet.ReadByte(); // Flags
                packet.ReadByte(); // ReservedByte
                int command_length_info = packet.ReadInt32(); // Length                  -- ? uint32 ?
                packet.ReadUInt32(); // reliablesequencenumber  -- ? uint32 ? 

                int data_length = command_length_info - CMD_HDR_LEN;

                Event_Photon_Info?.Invoke(
                    String.Format("  [{0}] Photon Cmd - {1}:{2}  len {3}", 
                        cmd_number, cmd_type.ToString(), (int)cmd_type, command_length_info));

                // read command data
                byte[] data = packet.ReadBytes(data_length);
                
                try { decode_PhotonPacket(cmd_type,cmd_channel_id, data); }
                #if HIDE_PARSE_ERRORS
                catch (System.IO.EndOfStreamException ex) {                    
                }
                #endif
                finally {}

            } // for loop
        }

        private void decode_PhotonPacket(CommandType cmd_type, int cmd_channel_id, byte[] data) {
            var packet = new BeBinaryReader(new MemoryStream(data, 0, data.Length));

            // decode paramaters
            switch (cmd_type) {
                case CommandType.Acknowledge:     // 8 bytes of parms
                    packet.ReadUInt32(); // RecvRelSeqNum
                    packet.ReadUInt32(); // RecvSentTime                                                               
                    break;
                case CommandType.SendUnreliable:
                    packet.ReadUInt32(); // UnRelSeqNum                                            
                    break;
                case CommandType.SendReliableFragment:   // 20 bytes of parms
                    packet.ReadUInt32(); // Frag_start_seq_num
                    packet.ReadUInt32(); // Frag_frag_count
                    packet.ReadUInt32(); // Frag_frag_num
                    packet.ReadUInt32(); // Frag_total_len
                    packet.ReadUInt32(); // Frag_frag_off                              
                    break;
                case CommandType.SendReliable:
                    int rel_msg_sig = packet.ReadByte(); // Reliable Message Signature
                    MessageTypes rel_msg_type = (MessageTypes)packet.ReadByte(); // reliable message type
                   
                    if ((int)rel_msg_type > 128) {
                        // encrypted message types not supported
                        Event_Photon_Info?.Invoke("Decode_Photon: ignoring encrypted message type: " + rel_msg_type.ToString());
                        break;
                    }

                    switch (rel_msg_type) {
                        case MessageTypes.Request:
                            packet.ReadByte(); // Operation Code
                            break;
                        case MessageTypes.EventData:
                            break;
                        case MessageTypes.Response:
                        case MessageTypes.ResponseAlt:
                            var opResponse = new ReliableMessage_Response();

                            opResponse.ChannelID = cmd_channel_id;
                            opResponse.OperationCode = packet.ReadByte(); // Operation Code
                            opResponse.OperationResponseCode = packet.ReadByte(); // Operation Response Code
                            opResponse.OperationDebugByte = packet.ReadByte(); // Operation Debug Byte                                                        
                            
                            opResponse.ParameterCount = packet.ReadUInt16(); // Parameter Count   (?? is this valid for all msg types?)

                            // decode the paramaters
                            for (int i=0;i<opResponse.ParameterCount;i++) {
                                var paramID = packet.ReadByte(); // paramID
                                PhotonParamType paramType = (PhotonParamType)packet.ReadByte(); // paramType


                                opResponse.ParamaterData = Decode_PhotonValueType.Decode(packet,paramType);                                
                            }
                            
                            Event_Photon_ReliableResponse?.Invoke(opResponse);
                            break;
                        default:
                            break;
                    }
                    
                    break;
                case CommandType.Connect:
                case CommandType.VerifyConnect:
                case CommandType.Ping:
                    break;
                default:
                    Event_Photon_Info?.Invoke("Decode_Photon: ignoring unknown command type: " + cmd_type.ToString());
                    break;
            }
            
        }

    }

    public class ReliableMessage_Response {
        public int ChannelID;

        protected byte signature;
        public MessageTypes type;

        public byte OperationCode;
        public byte OperationResponseCode;
        public byte OperationDebugByte;

        public PhotonDataAtom ParamaterData;
        
        public UInt16 ParameterCount;        
        public byte[] raw_data;


    }
    /*

    struct PhotonCommand {
        // Header
        uint8 Type,
        uint8 ChannelID,
        uint8 Flags,
        uint8 ReservedByte,
        int32 Length,
        int32 ReliableSequenceNumber,

        // Body
        byte[] Data,
    }

    struct ReliableMessage {
        // Header
        uint8 Signature,
        uint8 Type,

        // OperationRequest
        uint8 OperationCode,

        // EventData
        uint8 EventCode,

        // OperationResponse
        uint16 OperationResponseCode,
        uint8 OperationDebugByte,

        // payload
        int16 ParamaterCount,
        byte[] Data
    }

    struct ReliableFragment {
        int32 SequenceNumber,
        int32 FragmentCount,
        int32 FragmentNumber,
        int32 TotalLength,
        int32 FragmentOffset,

        Data []byte
    }

    */


    public enum CommandType {
        Acknowledge = 1,
        Connect = 2,
        VerifyConnect = 3,
        Disconnect = 4,
        Ping = 5,
        SendReliable = 6,
        SendUnreliable = 7,
        SendReliableFragment = 8,
        SendUnsequenced = 9,
        ConfigureBandwidthLimit = 10,
        ConfigureThrottling = 11,
        FetchServerTimestamp = 12,
    };


    public enum ChannelNames {
        PhotonViewInstantiation = 1,
        VoIP = 2,
        RPC = 3,
        PhotonViewSerialization = 4,
    };

    public enum MessageTypes {
        Request = 2,
        ResponseAlt = 3,
        EventData = 4,
        Response = 7,
    };

    public enum OperationNames {
        GetRegions = 220,
        GetLobbyStats = 221,
        FindFriends = 222,
        DebugGame = 223,
        CancelJoinRandomGame = 224,
        JoinRandomGame = 225,
        JoinGame = 226,
        CreateGame = 227,
        LeaveLobby = 228,
        JoinLobby = 229,
        Authenticate = 230,
        ChangeGroups = 248,
        Ping = 249,
        GetProperties = 251,
        SetProperties = 252,
        RaiseEvent = 253,
        Leave = 254,
        Join = 255,
    };

    public enum EventNames {
        AzureNodeInfo = 210,
        TypedlobbyStats = 224,
        AppStats = 226,
        Match = 227,
        QueueState = 228,
        GameListUpdate = 229,
        GameList = 230,
        PropertiesChanged = 253,
        Leave = 254,
        Join = 255,


        // PUN Events...

        RPC = 200,
        SendSerialize = 201,
        Instantiation = 202,
        CloseConnection = 203,
        Destroy = 204,
        RemoveCachedRPCs = 205,
        SendSerializeReliable = 206,
        DestroyPlayer = 207,
        AssignMaster = 208,
        OwnershipRequest = 209,
        OwnershipTransfer = 210,
        VacantViewIds = 211,

        // Altspace application-specific events
        MulticastRPC = 135,
        VoIP = 179,
    };

}
