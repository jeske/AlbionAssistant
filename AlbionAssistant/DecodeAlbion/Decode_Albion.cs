using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using AlbionAssistant;

namespace AlbionAssistant {
    public class Decode_Albion {
        public delegate void Delegate_Albion_Info(string info);
        public event Delegate_Albion_Info Event_Albion_Info;

        public void Decode_ReliableResponse(ReliableMessage_Response info) {
            Event_Albion_Info?.Invoke(
                String.Format("RESPONSE [{0} - chn {1}] \n... {2}",
                    info.OperationCode,
                    info.ChannelID,
                    info.ParamaterData
                    ));

        }

    }
}
