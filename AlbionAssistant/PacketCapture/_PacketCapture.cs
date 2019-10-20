//
// Albion Assistant
// Copyright (C) David W. Jeske 2019
//
// portions from MJSniffer under Code Project Open License
//  https://www.codeproject.com/Articles/17031/A-Network-Sniffer-in-C



using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;




namespace AlbionAssistant {

    public enum Protocol {
        TCP = 6,
        UDP = 17,
        Unknown = -1
    };

    public class PacketCapture
    {
        private static uint MAX_PACKET_SIZE = 65535;

        private List<Socket> listenSockets = new List<Socket>(); //The sockets which capture all incoming packets

        private byte[] byteData = new byte[MAX_PACKET_SIZE];
        private bool bContinueCapturing = false;            //A flag to check if packets are to be captured or not

        private delegate void PacketEventDelegate(string info);
        event PacketEventDelegate PacketEvent;

        public PacketCapture() { }

        
        public struct AsyncCaptureState {
            public readonly Socket workSocket;
            public AsyncCaptureState(Socket workSocket) {
                this.workSocket = workSocket;
            }
        }

        public void StartCapture()
        {
           // try
           // {
                if (!bContinueCapturing)
                {
                    bContinueCapturing = true;

                    // start listening on every interface... so we don't have to ask the user to choose
                    // TODO: make a settings dialog to choose ANY or a specific interface?

                    IPHostEntry hostEntry = Dns.GetHostEntry((Dns.GetHostName()));
                    foreach (IPAddress ip in hostEntry.AddressList) {
                    
                        string interfaceName = ip.ToString();

                        //For sniffing the socket to capture the packets has to be a raw socket, with the
                        //address family being of type internetwork, and protocol being IP
                        
                        AddressFamily addressFamily = ip.AddressFamily;
                        ProtocolType protocolType;
                        SocketOptionLevel socketOptionLevel;

                        switch (ip.AddressFamily) {
                            case AddressFamily.InterNetwork:
                                protocolType = ProtocolType.IP;
                                socketOptionLevel = SocketOptionLevel.IP;
                                break;
                            case AddressFamily.InterNetworkV6:
                                protocolType = ProtocolType.IPv6;
                            socketOptionLevel = SocketOptionLevel.IPv6;
                            break;
                            default:
                                continue;
                        }

                        Socket mainSocket = new Socket(addressFamily, SocketType.Raw, protocolType);

                        this.listenSockets.Add(mainSocket); // it to our list of listen sockets...

                        //Bind the socket to the selected IP address
                        mainSocket.Bind(new IPEndPoint(IPAddress.Parse(interfaceName), 0));
                        
                        //Set the socket  options
                        mainSocket.SetSocketOption(socketOptionLevel,            //Applies only to IP packets
                                                   SocketOptionName.HeaderIncluded, //Set the include the header
                                                   true);                           //option to true

                        byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                        byte[] byOut = new byte[4] { 1, 0, 0, 0 }; //Capture outgoing packets

                        //Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
                        mainSocket.IOControl(IOControlCode.ReceiveAll,              //Equivalent to SIO_RCVALL constant
                                                                                    //of Winsock 2
                                             byTrue,
                                             byOut);

                        //Start receiving the packets asynchronously
                        var aState = new AsyncCaptureState(mainSocket);
                        mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                            new AsyncCallback(OnReceive), aState);                       
                    }

                    
                }
            //} catch (Exception ex) {                
            //    // something bad happened we should probably fix
            //    if (PacketEvent != null) PacketEvent("Error opening socket for packet sniffing");
            //}

        }

            private void OnReceive(IAsyncResult ar)
            {                                 
                AsyncCaptureState so = (AsyncCaptureState)ar.AsyncState;
                Socket mainSocket = so.workSocket;

                try {
                    int nReceived = mainSocket.EndReceive(ar);

                    Console.WriteLine("packet received!");

                    //Analyze the bytes received...

                    ParseData(byteData, nReceived);

                    if (bContinueCapturing)
                    {
                        byteData = new byte[MAX_PACKET_SIZE];

                        //Another call to BeginReceive so that we continue to receive the incoming
                        //packets
                        mainSocket.BeginReceive(byteData, 0, byteData.Length, SocketFlags.None,
                            new AsyncCallback(OnReceive), so);
                    }
                }
                catch (ObjectDisposedException)
                {
                }
                //catch (Exception ex)
                //{
                //    // do something with error..
                //    // MessageBox.Show(ex.Message, "MJsniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
                //    PacketEvent("ONReceive Error: " + ex.ToString());
                //}
            }

            private void ParseData(byte[] byteData, int nReceived)
            {
              
                //Since all protocol packets are encapsulated in the IP datagram
                //so we start by parsing the IP header and see what protocol data
                //is being carried by it
                IPHeader ipHeader = new IPHeader(byteData, nReceived);
           
                //Now according to the protocol being carried by the IP datagram we parse 
                //the data field of the datagram
                switch (ipHeader.ProtocolType)
                {
                    case Protocol.TCP:
                        break; // skip TCP packets.

                    case Protocol.UDP:
                        //  IPHeader.Data stores the data being carried by the IP datagram
                        UDPHeader udpHeader = 
                            new UDPHeader(ipHeader.Data,  (int)ipHeader.MessageLength);

                        //Length of UDP header is always eight bytes so we subtract that out of the total 
                        //length to find the length of the UDP payload

                        var ports = new HashSet<string> { "5055", "5056" };
                        
                        if (!(ports.Contains(udpHeader.DestinationPort) || ports.Contains(udpHeader.SourcePort)))
                        {
                            //  Albion Photon Data       
                            PacketEvent?.Invoke(String.Format("Albion UDP Packet, size={0}",byteData.Length));
                        } else if (udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53") {
                            //  If the port is equal to 53 then the underlying protocol is DNS
                            //  Note: DNS can use either TCP or UDP thats why the check is done twice               
                            PacketEvent?.Invoke(String.Format("UDP DNS Packet, size={0}", byteData.Length));
                        }                        
                        break;

                    case Protocol.Unknown:
                        break;
                }
            }

        } // class PacketCapture


    } // namespace