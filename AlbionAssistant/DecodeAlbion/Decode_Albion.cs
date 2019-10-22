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

        private string RenderParameter(int paramID, PhotonDataAtom val) {
            switch ((AlbionParamID)paramID) {
                case AlbionParamID.albOperation:
                    var intval = val as PhotonData_Value<Int16>;
                    if (intval != null) {
                        return String.Format("[albOp {0}] = {1}:{2}",(int)paramID,((AlbionOperationType)intval.data).ToString(),intval.data);
                    } else {
                        return String.Format("[albOp {0}] = {1}",(int)paramID,val);
                    }
                default:
                    if (Enum.IsDefined(typeof(AlbionParamID),paramID)) {            
                        return String.Format("[{0}:{1}] = {2}", ((AlbionParamID)paramID).ToString(),paramID,val);
                    } else {
                        return String.Format("[{0}] = {1}",paramID.ToString(),val);
                    }                                  
            }
        }
        private string RenderParameters(ReliableMessage_Response.Paramaters parms) {            
                var acc = new List<string>();
                parms.ToList().ForEach(kvp => 
                    acc.Add( RenderParameter(kvp.Key, kvp.Value) ));
                    
                return "PhotonParms - \n... " + String.Join("\n... ",acc);

        }
        
        public void Decode_ReliableResponse(ReliableMessage_Response info) {
            Event_Albion_Info?.Invoke(
                String.Format("RESPONSE [{0} - chn {1}] \n... {2}",
                    info.OperationCode,
                    info.ChannelID,
                    RenderParameters(info.ParamaterData)
                    ));

        }

    }
}
