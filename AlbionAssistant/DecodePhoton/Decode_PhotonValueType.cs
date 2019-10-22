//
// AlbionAssistant
// Copyright (C) 2019 by David W. Jeske
//


using System;
using System.IO;
using System.Collections.Generic;

using System.Linq;
using Be.IO;

// https://doc.photonengine.com/en-us/realtime/current/reference/binary-protocol
// https://github.com/broderickhyman/photon_spectator/blob/master/decode_reliable_message.go


namespace AlbionAssistant {

    public static class Decode_PhotonValueType {
        public static PhotonDataAtom Decode(BinaryReader packet, PhotonParamType paramType) {
            switch (paramType) {
            
                case PhotonParamType.NilType_o:
                case PhotonParamType.NilType:         return new PhotonData_Nil();
                case PhotonParamType.BooleanType:     return new PhotonData_Value<bool>(paramType, packet.ReadByte() == 1 ? true : false);
                
                case PhotonParamType.Int8Type:        return new PhotonData_Value<byte>(paramType, packet.ReadByte());

                case PhotonParamType.Int16Type_o:
                case PhotonParamType.Int16Type:       return new PhotonData_Value<Int16>(paramType, packet.ReadInt16());
                case PhotonParamType.Int32Type:       return new PhotonData_Value<Int32>(paramType, packet.ReadInt32());
                case PhotonParamType.Int64Type:       return new PhotonData_Value<Int64>(paramType, packet.ReadInt64());
                
                case PhotonParamType.Float32Type:     return new PhotonData_Value<Single>(paramType, packet.ReadSingle());
                case PhotonParamType.DoubleType:      return new PhotonData_Value<Double>(paramType, packet.ReadDouble());

                case PhotonParamType.SliceType:       return PhotonData_SliceType.DecodeFrom(packet);
                case PhotonParamType.StringSliceType: return PhotonData_SliceType.DecodeFrom_WithType(packet, PhotonParamType.StringType);
                case PhotonParamType.Int8SliceType:   return PhotonData_SliceType.DecodeFrom_WithType(packet,PhotonParamType.Int8Type);
                case PhotonParamType.Int32SliceType:  return PhotonData_SliceType.DecodeFrom_WithType(packet, PhotonParamType.Int32Type);

                case PhotonParamType.StringType:
                    var len = packet.ReadUInt16();
                    byte[] raw_data = packet.ReadBytes(len);
                    string string_data = System.Text.Encoding.ASCII.GetString(raw_data);
                    return new PhotonData_Value<string>(paramType, string_data);

                case PhotonParamType.Custom:
                case PhotonParamType.DictionaryType:
	            case PhotonParamType.EventDateType:
	            case PhotonParamType.Hashtable:
	            case PhotonParamType.OperationResponseType:
	            case PhotonParamType.OperationRequestType:
	            case PhotonParamType.ObjectSliceType:
                    return new PhotonData_NotYetParsed(paramType);                    
                default:
                    return new PhotonData_UNRECOGNIZED(paramType);                    
            }

        }

    } // class Decode_PhotonValueType


    #region Photon Abstract Data Tree Types

    public abstract class PhotonDataAtom {
        public PhotonParamType type;
        public override string ToString() {
            return "PhotonDataAtom(" + type.ToString() + ")";      
        }
    }

    public class PhotonData_UNRECOGNIZED : PhotonDataAtom {
        public PhotonData_UNRECOGNIZED(PhotonParamType type) {
            this.type = type;
        }
        public override string ToString() {
            return "PhotonData_UNRECOGNIZED(" + type.ToString() + ")";
        }
    }

    public class PhotonData_NotYetParsed : PhotonDataAtom {
        public PhotonData_NotYetParsed(PhotonParamType type) {
            this.type = type;
        }
        public override string ToString() {
            return "PhotonData_NotYetParsed(" + type.ToString() + "," + ((int)type).ToString() + ")";
        }
    }

    public class PhotonData_Nil : PhotonDataAtom {
        public PhotonData_Nil() {
            this.type = PhotonParamType.NilType;
        }
        public override string ToString() {
            return "PhotonData_Nil";
        }
    }

    public class PhotonData_Value<T> : PhotonDataAtom  {        
        public T data;
        public PhotonData_Value(PhotonParamType type, T data) { 
            this.type = type;
            this.data = data; 
        }
        public override string ToString() {
            return String.Format("PhotonData_Value<{0}:{1}>({2})",
                type,typeof(T).ToString(),data.ToString());
        }
    }

    public class PhotonData_SliceValues : PhotonDataAtom {
        public PhotonDataAtom[] values;

        public PhotonData_SliceValues(PhotonParamType type, PhotonDataAtom[] values) {
            this.type = type;
            this.values = values;
        }
    }

    public class PhotonData_SliceType : PhotonDataAtom  {       
        public PhotonData_SliceValues data;

        public PhotonData_SliceType(PhotonParamType type, PhotonData_SliceValues data) {
            this.type = type;
            this.data = data;
        }
        public override string ToString() {
            return 
                String.Format("PhotonData_Slice<{0}:{1}> len {2} [ {3} ]",
                    type, data.type,
                    data.values.Length,
                    String.Join(", ", data.values.Select(x => x.ToString())));
        }
        
        public static PhotonData_SliceType DecodeFrom(BinaryReader packet) {
            var length = packet.ReadUInt16();
            PhotonParamType value_types = (PhotonParamType)packet.ReadByte();

            var acc = new List<PhotonDataAtom>();

            for (int i=0;i<length;i++) {
                acc.Add(Decode_PhotonValueType.Decode(packet,value_types));
            }
            return new PhotonData_SliceType(PhotonParamType.SliceType,new PhotonData_SliceValues(value_types,acc.ToArray()));
        }

        public static PhotonData_SliceType DecodeFrom_WithType(BinaryReader packet, PhotonParamType type) {
            var length = packet.ReadUInt16();

            var acc = new List<PhotonDataAtom>();

            for (int i = 0; i < length; i++) {
                acc.Add(Decode_PhotonValueType.Decode(packet, type));
            }
            return new PhotonData_SliceType(type,new PhotonData_SliceValues(type, acc.ToArray()));
        }

    }
    #endregion



    public enum PhotonParamType {
        Unk_1 = 1,
        Unk_116 = 116,


        
        NilType_o = 0,        
        Int16Type_o = 7,

        NilType = 42,

        DictionaryType = 68,

        StringSliceType = 97,

        Int8Type = 98,
        Custom = 99,
        DoubleType = 100,
        EventDateType = 101,
        Float32Type = 102,
        Hashtable = 104,
        Int32Type = 105,
        Int16Type = 107,
        
        Int64Type = 108,
        Int32SliceType = 110,
        BooleanType = 111,
        OperationResponseType = 112,
        OperationRequestType = 113,
        StringType = 115,



        Int8SliceType = 120,
        SliceType = 121,
        ObjectSliceType = 122,
    };




} // namespace