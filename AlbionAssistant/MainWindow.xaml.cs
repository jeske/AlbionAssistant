//
// Albion Assistant
// Copyright (C) David W. Jeske 2019
//


using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;


namespace AlbionAssistant
{

    // see  also MainWindow_CodeBehind.cs

    public partial class MainWindow : Window {
        DispatcherTimer infoUpdateTimer = new DispatcherTimer();
        

        public MainWindow() {
            InitializeComponent();
            this.Closed += MainWindow_Closed;
            this.clearButton.Click += ClearButton_Click1;

            infoUpdateTimer.Interval = new TimeSpan(0,0,0,0,100);
            infoUpdateTimer.Tick += InfoUpdateTimer_Tick;
            infoUpdateTimer.Start();

            Setup_Packet_Capture();
        }

        private void InfoUpdateTimer_Tick(object sender, EventArgs e) {
             string newInfo = String.Format("{0} udp - {1} photon - {2} photon cmds",
                packetStats.udp_packets,
                packetStats.photon_packets,
                packetStats.photon_commands);
                
                infoBox.Dispatcher.Invoke(DispatcherPriority.Background, new Action(() => {
                    infoBox.Content = newInfo;     
                    // TODO: make this always update...
                    // https://stackoverflow.com/questions/5676202/how-to-force-a-wpf-binding-to-refresh/5676612#5676612
                }));                           
        }

        private void Button_Click(object sender, RoutedEventArgs e) {

        }

        private void ClearButton_Click1(object sender, RoutedEventArgs e) {
            treeView.Items.Clear();            
        }
    }
}