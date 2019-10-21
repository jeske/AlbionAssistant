using System;
using Be.IO;

//
// AlbionAssistant
// Copyright (C) 2019 by David W. Jeske
//


// PhotonObserver
//
// This is an observer for the "Photon Engine" network communication layer used by Albion
// https://www.photonengine.com/en-us/Photon
// https://doc.photonengine.com/en-us/realtime/current/reference/binary-protocol
// 
// https://github.com/broderickhyman/photon_spectator
// https://github.com/AltspaceVR/wireshark-photon-dissector/blob/master/photon.lua
//


using System.IO;

namespace PhotonObserver {


    public class PhotonDecoder {

        public void decodePacket(BinaryReader packet) {

            const int CMD_HDR_LEN = 12;

            // read Photon Header
            packet.ReadUInt16(); // PeerID
            packet.ReadByte(); // CrcEnabled
            int cmd_count = (int)packet.ReadByte(); // Command Count
            packet.ReadUInt32(); // Timestamp
            packet.ReadInt32(); // Challenge

            Console.WriteLine("Photon Packet with ({0}) commands", cmd_count);

            for (int cmd_number = 0; cmd_number < cmd_count; cmd_number++) {
                // read photon command header
                CommandType cmd_type = (CommandType)packet.ReadByte(); // Type
                packet.ReadByte(); // ChannelID
                packet.ReadByte(); // Flags
                packet.ReadByte(); // ReservedByte
                int command_length_info = packet.ReadInt32(); // Length                  -- ? uint32 ?
                packet.ReadUInt32(); // reliablesequencenumber  -- ? uint32 ? 

                int data_length = command_length_info - CMD_HDR_LEN;

                Console.WriteLine("  [{0}] Photon Cmd - {1}:{2}  len {3}", 
                    cmd_number, cmd_type.ToString(), (int)cmd_type, command_length_info);

                // decode paramaters
                switch (cmd_type) {
                    case CommandType.Acknowledge:     // 8 bytes of parms
                        packet.ReadUInt32(); // RecvRelSeqNum
                        packet.ReadUInt32(); // RecvSentTime                        
                        data_length -= 8; 
                        // TODO: maybe assert data_length == 0 after this?
                        break;
                    case CommandType.SendUnreliable:
                        packet.ReadUInt32(); // UnRelSeqNum                        
                        data_length -= 4;
                        break;
                    case CommandType.SendReliableFragment:   // 20 bytes of parms
                        packet.ReadUInt32(); // Frag_start_seq_num
                        packet.ReadUInt32(); // Frag_frag_count
                        packet.ReadUInt32(); // Frag_frag_num
                        packet.ReadUInt32(); // Frag_total_len
                        packet.ReadUInt32(); // Frag_frag_off          
                        data_length -= 20;  // subtract out these paramaters
                        break;
                    case CommandType.SendReliable:
                    case CommandType.Connect:
                    case CommandType.VerifyConnect:    
                        break;
                    default:
                        break;
                }

                // read command data
                
                byte[] data = packet.ReadBytes(data_length);

                
            }
        }

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


    enum CommandType {
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


    enum ChannelNames {
        PhotonViewInstantiation = 1,
        VoIP = 2,
        RPC = 3,
        PhotonViewSerialization = 4,
    };

    enum MessageTypes {
        Request = 2,
        ResponseAlt = 3,
        EventData = 4,
        Response = 7,
    };

    enum OperationNames {
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

    enum EventNames {
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
