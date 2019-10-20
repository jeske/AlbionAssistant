//
// Albion Assistant
// Copyright (C) David W. Jeske 2019
//
// portions from MJSniffer under Code Project Open License
//  https://www.codeproject.com/Articles/17031/A-Network-Sniffer-in-C

using System.Net;
using System.Text;
using System;
using System.IO;

namespace AlbionAssistant
{
    public class UDPHeader
    {
        private static uint MAX_PACKET_SIZE = 65535;

        //UDP header fields
        private ushort usSourcePort;            //Sixteen bits for the source port number        
        private ushort usDestinationPort;       //Sixteen bits for the destination port number
        private ushort usLength;                //Length of the UDP header
        private short sChecksum;                //Sixteen bits for the checksum
                                                //(checksum can be negative so taken as short)              
        //End UDP header fields

        private byte[] byUDPData = new byte[MAX_PACKET_SIZE];  //Data carried by the UDP packet

        public UDPHeader(byte [] byBuffer, int nReceived)
        {
            MemoryStream memoryStream = new MemoryStream(byBuffer, 0, nReceived);
            BinaryReader binaryReader = new BinaryReader(memoryStream);

            //The first sixteen bits contain the source port
            usSourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //The next sixteen bits contain the destination port
            usDestinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //The next sixteen bits contain the length of the UDP packet
            usLength = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //The next sixteen bits contain the checksum
            sChecksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());            

            //Copy the data carried by the UDP packet into the data buffer
            Array.Copy(byBuffer, 
                       8,               //The UDP header is of 8 bytes so we start copying after it
                       byUDPData, 
                       0, 
                       nReceived - 8);
        }

        public string SourcePort
        {
            get
            {
                return usSourcePort.ToString();
            }
        }

        public string DestinationPort
        {
            get
            {
                return usDestinationPort.ToString();
            }
        }

        public string Length
        {
            get
            {
                return usLength.ToString ();
            }
        }

        public string Checksum
        {
            get
            {
                //Return the checksum in hexadecimal format
                return string.Format("0x{0:x2}", sChecksum);
            }
        }

        //Length of UDP header is always eight bytes so we subtract that out of the total 
        //length to find the length of the UDP payload
        private static int UDP_HEADER_LENGTH = 8;

        public int payloadLength {
            get {
                return usLength - UDP_HEADER_LENGTH;
            }
        }

        public byte[] Data
        {
            get
            {
                return byUDPData;
            }
        }
    }
}