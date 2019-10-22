//
// Albion Assistant
// Copyright (C) David W. Jeske 2019
//


using System;
using System.IO;
using System.Windows;
using System.Threading;
using System.Security.Principal; // to check we are administrator

using System.Collections.ObjectModel;

using System.Windows.Controls;

using System.Linq;

using Be.IO;
using IPPacketCapture;

// this needs to run as administrator to sniff network packets
// https://stackoverflow.com/questions/2818179/how-do-i-force-my-net-application-to-run-as-administrator


// WPF TreeView
// https://www.codeproject.com/Articles/124644/Basic-Understanding-of-Tree-View-in-WPF



// default treeview includes it's own scroll view, but then we can't control it
// https://stackoverflow.com/questions/54311985/wpf-treeview-in-scrollview-how-to-enable-scrolling-with-mouse-over-treeview
// https://stackoverflow.com/questions/15151974/synchronized-scrolling-of-two-scrollviewers-whenever-any-one-is-scrolled-in-wpf
// https://docs.microsoft.com/en-us/previous-versions/dotnet/netframework-3.5/ms752352(v=vs.90)
// https://blogs.msdn.microsoft.com/jpricket/2007/11/05/exploring-wpf-programmatically-scrolling-a-treeview/


namespace AlbionAssistant
{

    public partial class MainWindow : Window
    {
        PacketCapture captureManager = new PacketCapture();
        PhotonDecoder photonDecoder = new PhotonDecoder();
        Decode_Albion albionDecoder = new Decode_Albion(); 

        public struct PacketStats {
            public int udp_packets;
            public int photon_packets;
            public int photon_commands;
            public int photon_reliable_response;
            public int photon_reliable_event;
            
        }
        public PacketStats packetStats;



        private void Setup_Packet_Capture() {
        
            

            // ---------------------------

            treeView.Items.Add(
                new MenuItem{ 
                    Title = String.Format(
                        "This only works with Administrator, do we have it? .. [{0}]", 
                        AppElevation.CheckForAdministrator() ? "YES" : "NO")
                });
            // TODO: if we don't have administrator, we should put up an error dialog...

            // setup info log hooks
            captureManager.PacketEvent_Info += CaptureManager_UDPPacket_Info;
            photonDecoder.Event_Photon_Info += PhotonDecoder_Event_Photon_Info;
            photonDecoder.Event_Photon_Cmd_Info += PhotonDecoder_Event_Photon_Cmd_Info;            
            albionDecoder.Event_Albion_Info += AlbionDecoder_Event_Albion_Info;


            // setup "real" packet processing hooks
            captureManager.PacketEvent_UDP += CaptureManager_PacketEvent_UDP;
            photonDecoder.Event_Photon_ReliableResponse += PhotonDecoder_Event_Photon_ReliableResponse;
            photonDecoder.Event_Photon_ReliableEvent += PhotonDecoder_Event_Photon_ReliableEvent;

            Console.WriteLine("Start Capturing Packets...");
            captureManager.StartCapture();
        }



        #region info logging        
        private void CaptureManager_UDPPacket_Info(string info)        /**/ { LogEvent(false,"Raw: " + info); }
        private void PhotonDecoder_Event_Photon_Cmd_Info(string info)  /**/ { LogEvent(false,"Photon Cmd: " + info);  packetStats.photon_commands++;  }
        private void PhotonDecoder_Event_Photon_Info(string info)      /**/ { LogEvent(false, "Photon: " + info); packetStats.photon_packets++;  }
        private void AlbionDecoder_Event_Albion_Info(string info)      /**/ { LogEvent(true, "Albion: " + info); }
        #endregion


        #region ************** packet wire up  ********************************
        private void CaptureManager_PacketEvent_UDP(UDPHeader packet) {
            packetStats.udp_packets++;
            photonDecoder.decodeUDPPacket(new BeBinaryReader(new MemoryStream(packet.Data,0,packet.payloadLength)));
        }
        private void PhotonDecoder_Event_Photon_ReliableResponse(ReliableMessage_Response info) {
            packetStats.photon_reliable_response++;
            albionDecoder.Decode_ReliableResponse(info);
        }
        private void PhotonDecoder_Event_Photon_ReliableEvent(ReliableMessage_EventData info) {
            packetStats.photon_reliable_event++;
            // LogEvent("Albion Event: " + info.evType);
        }
        #endregion


        //  *********************************   window UI **********************************


        private void MainWindow_Closed(object sender, EventArgs e) {
            captureManager.StopCapture();
            System.GC.Collect();
            Console.WriteLine("Albion Assistant Exiting...");
            System.Windows.Application.Current.Shutdown();
            // TODO: figure out how to make this quit faster.. it takes a while for the threads to exit...
        }


        public void LogEvent(string data) {
            LogEvent(true,data);
        }
        // this is the main way we log events
        public void LogEvent(bool sendToUI, string data) {
            Console.WriteLine(data);     // send everything to the console
            if (sendToUI) {
                this.Dispatcher.Invoke(new Action(() => {                               
                    treeView.Items.Insert(0, new MenuItem() { Title = data });
                }));            
            }
        }

        }

    public class MenuItem
    {
        public MenuItem()
        {
            this.Items = new ObservableCollection<MenuItem>();
        }

        public string Title { get; set; }

        public ObservableCollection<MenuItem> Items { get; set; }
    }


    public static class AppElevation {

        // Check for Administrastor App Elevation
        // https://stackoverflow.com/questions/2818179/how-do-i-force-my-net-application-to-run-as-administrator


        public static bool CheckForAdministrator() {

            try {
                WindowsIdentity user = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new WindowsPrincipal(user);
                bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

                return isAdmin;
            } catch (UnauthorizedAccessException ex) {
                Console.WriteLine("Unauthorized Access Exception trying to check role");
                return false;
            }

        }
        public static void PrintAppRoles() {

            AppDomain myDomain = Thread.GetDomain();

            myDomain.SetPrincipalPolicy(PrincipalPolicy.WindowsPrincipal);
            WindowsPrincipal myPrincipal = (WindowsPrincipal)Thread.CurrentPrincipal;
            Console.WriteLine("{0} belongs to: ", myPrincipal.Identity.Name.ToString());
            Array wbirFields = Enum.GetValues(typeof(WindowsBuiltInRole));
            foreach (object roleName in wbirFields) {
                try {
                    // Cast the role name to a RID represented by the WindowsBuildInRole value.
                    Console.WriteLine("{0}? {1}.", roleName,
                        myPrincipal.IsInRole((WindowsBuiltInRole)roleName));
                    Console.WriteLine("The RID for this role is: " + ((int)roleName).ToString());

                } catch (Exception) {
                    Console.WriteLine("{0}: Could not obtain role for this RID.",
                        roleName);
                }
            }            
        }

    }


     // throw some sample items into the UI control
            /*
            MenuItem root = new MenuItem() { Title = "Menu" };
            MenuItem childItem1 = new MenuItem() { Title = "Child item #1" };
            childItem1.Items.Add(new MenuItem() { Title = "Child item #1.1" });
            childItem1.Items.Add(new MenuItem() { Title = "Child item #1.2" });
            root.Items.Add(childItem1);
            root.Items.Add(new MenuItem() { Title = "Child item #2" });
            treeView.Items.Add(root);
            */

}
