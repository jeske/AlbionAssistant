//
// Albion Assistant
// Copyright (C) David W. Jeske 2019
//

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Runtime;
using System.Runtime.InteropServices;

// Windows Filtering Platform (WFP) 
// 
// https://www.codeproject.com/Articles/17031/A-Network-Sniffer-in-C
// https://en.wikipedia.org/wiki/Windows_Filtering_Platform
// https://docs.microsoft.com/en-us/windows/win32/api/_fwp/
// https://social.msdn.microsoft.com/Forums/windowsdesktop/en-US/a65bf197-937b-401e-b15f-0e1c3decdb14/windows-filtering-platform-and-net?forum=wfp


// Using Windows Filtering Platform
//
// https://docs.microsoft.com/en-us/windows/win32/fwp/using-windows-filtering-platform

// NUGET
// PM> install-package system.runtime.interopservices


[StructLayout(LayoutKind.Sequential)]
public struct GUID
{

    /// unsigned int
    public uint Data1;

    /// unsigned short
    public ushort Data2;

    /// unsigned short
    public ushort Data3;

    /// unsigned char[8]
    [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 8)]
    public string Data4;
}

[StructLayout(LayoutKind.Sequential)]
public struct SID_IDENTIFIER_AUTHORITY
{

    /// BYTE[6]
    [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
    public byte[] Value;
}

[StructLayout(LayoutKind.Sequential)]
public struct SID
{

    /// BYTE->unsigned char
    public byte Revision;

    /// BYTE->unsigned char
    public byte SubAuthorityCount;

    /// SID_IDENTIFIER_AUTHORITY->_SID_IDENTIFIER_AUTHORITY
    public SID_IDENTIFIER_AUTHORITY IdentifierAuthority;

    /// DWORD[1]
    [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = System.Runtime.InteropServices.UnmanagedType.U4)]
    public uint[] SubAuthority;
}
// SEC_WINNT_AUTH_IDENTITY_W

[StructLayout(LayoutKind.Sequential)]
public unsafe struct SEC_WINNT_AUTH_IDENTITY_W
{

    /// unsigned short*
    public System.IntPtr User;

    /// unsigned int
    public uint UserLength;

    /// unsigned short*
    public System.IntPtr Domain;

    /// unsigned int
    public uint DomainLength;

    /// unsigned short*
    public IntPtr Password;

    /// unsigned int
    public uint PasswordLength;

    /// unsigned int
    public uint Flags;
}
// WFP SPECIFIC TYPES

//    FWP_BYTE_BLOB

[StructLayout(LayoutKind.Sequential)]
public struct FWP_BYTE_BLOB_
{

    /// UINT32->unsigned int
    public uint size;

    /// UINT8*
    [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPStr)]
    public string data;
}
// FWP_DISPLAY_DATA0

[StructLayout(LayoutKind.Sequential)]
public struct FWPM_DISPLAY_DATA0_
{

    /// wchar_t*
    [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
    public string name;

    /// wchar_t*
    [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
    public string description;
}
// FWP_SESSION0

[StructLayout(LayoutKind.Sequential)]
public struct FWPM_SESSION0
{

    /// GUID->_GUID
    public GUID sessionKey;

    /// FWPM_DISPLAY_DATA0->FWPM_DISPLAY_DATA0_
    public FWPM_DISPLAY_DATA0_ displayData;

    /// UINT32->unsigned int
    public uint flags;

    /// UINT32->unsigned int
    public uint txnWaitTimeoutInMSec;

    /// DWORD->unsigned int
    public uint processId;

    /// SID*
    public IntPtr sid;

    /// wchar_t*
    [System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.LPWStr)]
    public string username;

    /// BOOL->int
    public int kernelMode;
}
// FWPM_SUBLAYER0

[StructLayout(LayoutKind.Sequential)]
public struct FWPM_SUBLAYER0_
{

    /// GUID->_GUID
    public GUID subLayerKey;

    /// FWPM_DISPLAY_DATA0->FWPM_DISPLAY_DATA0_
    public FWPM_DISPLAY_DATA0_ displayData;

    /// UINT16->unsigned short
    public ushort flags;

    /// GUID*
    public System.IntPtr providerKey;

    /// FWP_BYTE_BLOB->FWP_BYTE_BLOB_
    public FWP_BYTE_BLOB_ providerData;

    /// UINT16->unsigned short
    public ushort weight;
}

// APIs

public unsafe partial class NativeMethods
{

    public UInt32 FWP_ACTION_TYPE;

    /// Return Type: DWORD->unsigned int
    ///serverName: wchar_t*
    ///authnService: UINT32->unsigned int
    ///authIdentity: SEC_WINNT_AUTH_IDENTITY_W*
    ///session: FWPM_SESSION0*
    ///engineHandle: HANDLE*
    [DllImport("FWPUClnt.dll", EntryPoint = "FwpmEngineOpen0")]
    public static extern uint FwpmEngineOpen0(
        [MarshalAsAttribute(UnmanagedType.LPWStr)] in string serverName, 
        uint authnService, 
        SEC_WINNT_AUTH_IDENTITY_W *authIdentity, 
        ref FWPM_SESSION0 session, 
        ref IntPtr engineHandle);


    /// Return Type: DWORD->unsigned int
    ///engineHandle: HANDLE->void*
    ///subLayer: FWPM_SUBLAYER0*
    ///sd: PSECURITY_DESCRIPTOR->PVOID->void*
    [DllImport("FWPUClnt.dll", EntryPoint = "FwpmSubLayerAdd0")]
    public static extern uint FwpmSubLayerAdd0(
        in IntPtr engineHandle, 
        ref FWPM_SUBLAYER0_ subLayer, 
        in IntPtr sd);

}



 public enum FWP_DATA_TYPE_
{
    FWP_EMPTY = 0,
    FWP_UINT8,
    FWP_UINT16,
    FWP_UINT32,
    FWP_UINT64,
    FWP_INT8,
    FWP_INT16,
    FWP_INT32,
    FWP_INT64,
    FWP_FLOAT,
    FWP_DOUBLE,
    FWP_BYTE_ARRAY16_TYPE,
    FWP_BYTE_BLOB_TYPE,
    FWP_SID,
    FWP_SECURITY_DESCRIPTOR_TYPE,
    FWP_TOKEN_INFORMATION_TYPE,
    FWP_TOKEN_ACCESS_INFORMATION_TYPE,
    FWP_UNICODE_STRING_TYPE,
    FWP_SINGLE_DATA_TYPE_MAX = 0xff,
    FWP_V4_ADDR_MASK,
    FWP_V6_ADDR_MASK,
    FWP_RANGE_TYPE,
    FWP_DATA_TYPE_MAX
};

public enum FWP_MATCH_TYPE_
{
    FWP_MATCH_EQUAL = 0,
    FWP_MATCH_GREATER = (FWP_MATCH_EQUAL + 1),
    FWP_MATCH_LESS = (FWP_MATCH_GREATER + 1),
    FWP_MATCH_GREATER_OR_EQUAL = (FWP_MATCH_LESS + 1),
    FWP_MATCH_LESS_OR_EQUAL = (FWP_MATCH_GREATER_OR_EQUAL + 1),
    FWP_MATCH_RANGE = (FWP_MATCH_LESS_OR_EQUAL + 1),
    FWP_MATCH_FLAGS_ALL_SET = (FWP_MATCH_RANGE + 1),
    FWP_MATCH_FLAGS_ANY_SET = (FWP_MATCH_FLAGS_ALL_SET + 1),
    FWP_MATCH_FLAGS_NONE_SET = (FWP_MATCH_FLAGS_ANY_SET + 1),
    FWP_MATCH_EQUAL_CASE_INSENSITIVE = (FWP_MATCH_FLAGS_NONE_SET + 1),
    FWP_MATCH_NOT_EQUAL = (FWP_MATCH_EQUAL_CASE_INSENSITIVE + 1),
    FWP_MATCH_TYPE_MAX = (FWP_MATCH_NOT_EQUAL + 1)
};



/********************
 * 
struct FWPM_DISPLAY_DATA0_
{
    wchar_t* name;
    wchar_t* description;
};

struct FWP_BYTE_BLOB_
{
    UINT32 size;
    UINT8* data;
};

struct FWP_BYTE_ARRAY6_
{
    UINT8 byteArray6[6];
};


struct FWP_BYTE_ARRAY16_
{
    UINT8 byteArray16[16];
};

struct _FWP_TOKEN_INFORMATION
{
    ULONG sidCount;
    PSID_AND_ATTRIBUTES sids;
    ULONG restrictedSidCount;
    PSID_AND_ATTRIBUTES restrictedSids;
};

struct FWP_V4_ADDR_AND_MASK_
{
    UINT32 addr;
    UINT32 mask;
};

struct FWP_V6_ADDR_AND_MASK_
{
    UINT8 addr[FWP_V6_ADDR_SIZE];
    UINT8 prefixLength;
};


struct FWP_VALUE0_
{
    FWP_DATA_TYPE type;
    union   {
        uint8 uint8;
        UINT16 uint16;
        UINT32 uint32;
        UINT64* uint64;
        INT8 int8;
        INT16 int16;
        INT32 int32;
        INT64* int64;
        float float32;
        double* double64;
        FWP_BYTE_ARRAY16* byteArray16;
        FWP_BYTE_BLOB* byteBlob;
        SID* sid;
        FWP_BYTE_BLOB* sd;
        FWP_TOKEN_INFORMATION* tokenInformation;
        FWP_BYTE_BLOB* tokenAccessInformation;
        LPWSTR unicodeString;
    };
};

struct FWP_RANGE0_
{
    FWP_VALUE0 valueLow;
    FWP_VALUE0 valueHigh;
}
FWP_RANGE0;

struct FWPM_ACTION0_
{
    FWP_ACTION_TYPE type;
    union
   {
      GUID filterType;
    GUID calloutKey;
};
} FWPM_ACTION0;

struct FWP_CONDITION_VALUE0_
{
    FWP_DATA_TYPE type;
    union
   {
      UINT8 uint8;
    UINT16 uint16;
    UINT32 uint32;
    UINT64* uint64;
    INT8 int8;
    INT16 int16;
    INT32 int32;
    INT64* int64;
    float float32;
    double* double64;
    FWP_BYTE_ARRAY16* byteArray16;
    FWP_BYTE_BLOB* byteBlob;
    SID* sid;
    FWP_BYTE_BLOB* sd;
    FWP_BYTE_BLOB* tokenInformation;
    FWP_BYTE_BLOB* tokenAccessInformation;
    LPWSTR unicodeString;
    FWP_BYTE_ARRAY6* byteArray6;
    FWP_V4_ADDR_AND_MASK* v4AddrMask;
    FWP_V6_ADDR_AND_MASK* v6AddrMask;
    FWP_RANGE0* rangeValue;
};
} FWP_CONDITION_VALUE0;

struct FWPM_FILTER_CONDITION0_
{
    GUID fieldKey;
    FWP_MATCH_TYPE matchType;
    FWP_CONDITION_VALUE0 conditionValue;
}
FWPM_FILTER_CONDITION0;


struct FWPM_FILTER0_
{
    GUID filterKey;
    FWPM_DISPLAY_DATA0 displayData;
    UINT32 flags;
    GUID* providerKey;
    FWP_BYTE_BLOB providerData;
    GUID layerKey;
    GUID subLayerKey;
    FWP_VALUE0 weight;
    UINT32 numFilterConditions;
    FWPM_FILTER_CONDITION0* filterCondition;
    FWPM_ACTION0 action;
    union
  {
     UINT64 rawContext;
    GUID providerContextKey;
};
GUID* reserved;
UINT64 filterId;
FWP_VALUE0 effectiveWeight;
} FWPM_FILTER0;



DWORD WINAPI FwpmFilterAdd0(__in HANDLE engineHandle,
                            __in const FWPM_FILTER0* filter,
                            __in_opt PSECURITY_DESCRIPTOR sd,
                            __out_opt UINT64* id);

*****/