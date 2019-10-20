﻿//
// Albion Assistant
// Copyright (C) David W. Jeske 2019
//


using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Threading;

using System.Security.Principal; // to check we are administrator

using System.Collections.ObjectModel;

// this needs to run as administrator to sniff network packets
// https://stackoverflow.com/questions/2818179/how-do-i-force-my-net-application-to-run-as-administrator


namespace AlbionAssistant
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        PacketCapture captureManager;

        public MainWindow()
        {
            InitializeComponent();
            this.Closed += MainWindow_Closed;
            treeView.Items.Add(
                new MenuItem{ 
                    Title = String.Format(
                        "This only works with Administrator, do we have it? .. [{0}]", 
                        AppElevation.CheckForAdministrator() ? "YES" : "NO")
                });
            // TODO: if we don't have administrator, we should put up an error dialog... 
            

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

            Console.WriteLine("Start Capturing Packets...");
            captureManager = new PacketCapture();

            captureManager.PacketEvent += CaptureManager_PacketEvent;


            captureManager.StartCapture();
        }

        private void CaptureManager_PacketEvent(string info) {
            this.Dispatcher.Invoke(new Action(() => {
                treeView.Items.Add(new MenuItem() { Title = info });
            }));
            
        }

        private void MainWindow_Closed(object sender, EventArgs e) {
            captureManager.StopCapture();
            System.GC.Collect();
            Console.WriteLine("Albion Assistant Exiting...");
            System.Windows.Application.Current.Shutdown();
            // TODO: figure out how to make this quit faster.. it takes a while for the threads to exit...
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

}
