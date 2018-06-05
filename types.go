package main

import (
	"github.com/google/gopacket/layers"
	"net"
	"github.com/google/gopacket"
	"fmt"
	"encoding/binary"
)

// SFlowRecord holds both flow sample records and counter sample records.
// A Record is the structure that actually holds the sampled data
// and / or counters.
type SFlowRecord interface {
}

// Implement my layer
type GenericSFlowDatagram struct {
	layers.BaseLayer
	DatagramVersion uint32
	AgentAddress    net.IP
	SubAgentID      uint32
	SequenceNumber  uint32
	AgentUptime     uint32
	SampleCount     uint32
	FlowSamples     []SFlowFlowSample
	CounterSamples  []SFlowCounterSample
}

type SFlowFlowSample struct {
	EnterpriseID          SFlowEnterpriseID
	Format                SFlowSampleType
	SampleLength          uint32
	SequenceNumber        uint32
	SourceIDClass         SFlowSourceFormat
	SourceIDIndex         SFlowSourceValue
	SamplingRate          uint32
	SamplePool            uint32
	Dropped               uint32
	InputInterfaceFormat  uint32
	InputInterface        uint32
	OutputInterfaceFormat uint32
	OutputInterface       uint32
	RecordCount           uint32
	Records               []SFlowRecord
}

type SFlowCounterSample struct {
	EnterpriseID   SFlowEnterpriseID
	Format         SFlowSampleType
	SampleLength   uint32
	SequenceNumber uint32
	SourceIDClass  SFlowSourceFormat
	SourceIDIndex  SFlowSourceValue
	RecordCount    uint32
	Records        []SFlowRecord
}

// SFlowDataSource encodes a 2-bit SFlowSourceFormat in its most significant
// 2 bits, and an SFlowSourceValue in its least significant 30 bits.
// These types and values define the meaning of the inteface information
// presented in the sample metadata.
type SFlowDataSource int32

type SFlowDataFormat uint32

type SFlowEnterpriseID uint32

const (
	SFlowStandard SFlowEnterpriseID = 0
)

/*
SFLFLOW_SAMPLE = 1,               enterprise = 0 : format = 1
SFLCOUNTERS_SAMPLE = 2,           enterprise = 0 : format = 2
SFLFLOW_SAMPLE_EXPANDED = 3,      enterprise = 0 : format = 3
SFLCOUNTERS_SAMPLE_EXPANDED = 4,  enterprise = 0 : format = 4
 */
type SFlowSampleType uint32

const (
	SFlowTypeFlowSample            SFlowSampleType = 1
	SFlowTypeCounterSample         SFlowSampleType = 2
	SFlowTypeExpandedFlowSample    SFlowSampleType = 3
	SFlowTypeExpandedCounterSample SFlowSampleType = 4
)

type SFlowSourceFormat uint32
type SFlowSourceValue uint32
type SFlowDataSourceExpanded struct {
	SourceIDClass SFlowSourceFormat
	SourceIDIndex SFlowSourceValue
}


// *********************************************************************
//  SFLOW FLOW
// *********************************************************************

type SFlowFlowDataFormat uint32

// SFlowBaseFlowRecord holds the fields common to all records
// of type SFlowFlowRecordType
type SFlowBaseFlowRecord struct {
	EnterpriseID   SFlowEnterpriseID
	Format         SFlowFlowRecordType
	FlowDataLength uint32
}

// SFlowFlowRecordType denotes what kind of Flow Record is
// represented. See RFC 3176
type SFlowFlowRecordType uint32

const (
	SFlowTypeRawPacketFlow                  SFlowFlowRecordType = 1
	SFlowTypeEthernetFrameFlow              SFlowFlowRecordType = 2
	SFlowTypeIpv4Flow                       SFlowFlowRecordType = 3
	SFlowTypeIpv6Flow                       SFlowFlowRecordType = 4
	SFlowTypeExtendedSwitchFlow             SFlowFlowRecordType = 1001
	SFlowTypeExtendedRouterFlow             SFlowFlowRecordType = 1002
	SFlowTypeExtendedGatewayFlow            SFlowFlowRecordType = 1003
	SFlowTypeExtendedUserFlow               SFlowFlowRecordType = 1004
	SFlowTypeExtendedUrlFlow                SFlowFlowRecordType = 1005
	SFlowTypeExtendedMlpsFlow               SFlowFlowRecordType = 1006
	SFlowTypeExtendedNatFlow                SFlowFlowRecordType = 1007
	SFlowTypeExtendedMlpsTunnelFlow         SFlowFlowRecordType = 1008
	SFlowTypeExtendedMlpsVcFlow             SFlowFlowRecordType = 1009
	SFlowTypeExtendedMlpsFecFlow            SFlowFlowRecordType = 1010
	SFlowTypeExtendedMlpsLvpFecFlow         SFlowFlowRecordType = 1011
	SFlowTypeExtendedVlanFlow               SFlowFlowRecordType = 1012
	SFlowTypeExtendedIpv4TunnelEgressFlow   SFlowFlowRecordType = 1023
	SFlowTypeExtendedIpv4TunnelIngressFlow  SFlowFlowRecordType = 1024
	SFlowTypeExtendedIpv6TunnelEgressFlow   SFlowFlowRecordType = 1025
	SFlowTypeExtendedIpv6TunnelIngressFlow  SFlowFlowRecordType = 1026
	SFlowTypeExtendedDecapsulateEgressFlow  SFlowFlowRecordType = 1027
	SFlowTypeExtendedDecapsulateIngressFlow SFlowFlowRecordType = 1028
	SFlowTypeExtendedVniEgressFlow          SFlowFlowRecordType = 1029
	SFlowTypeExtendedVniIngressFlow         SFlowFlowRecordType = 1030
)




// *********************************************************************
//  SFLOW COUNTER
// *********************************************************************

/*
SFLCOUNTERS_GENERIC      = 1,
SFLCOUNTERS_ETHERNET     = 2,
SFLCOUNTERS_TOKENRING    = 3,
SFLCOUNTERS_VG           = 4,
SFLCOUNTERS_VLAN         = 5,
SFLCOUNTERS_80211        = 6,
SFLCOUNTERS_LACP         = 7,
SFLCOUNTERS_SFP          = 10,
SFLCOUNTERS_PROCESSOR    = 1001,
SFLCOUNTERS_RADIO        = 1002,
SFLCOUNTERS_OFPORT       = 1004,
SFLCOUNTERS_PORTNAME     = 1005,
SFLCOUNTERS_HOST_HID     = 2000, // host id
SFLCOUNTERS_ADAPTORS     = 2001, // host adaptors
SFLCOUNTERS_HOST_PAR     = 2002, // host parent
SFLCOUNTERS_HOST_CPU     = 2003, // host cpu
SFLCOUNTERS_HOST_MEM     = 2004, // host memory
SFLCOUNTERS_HOST_DSK     = 2005, // host storage I/O
SFLCOUNTERS_HOST_NIO     = 2006, // host network I/O
SFLCOUNTERS_HOST_IP      = 2007,
SFLCOUNTERS_HOST_ICMP    = 2008,
SFLCOUNTERS_HOST_TCP     = 2009,
SFLCOUNTERS_HOST_UDP     = 2010,
SFLCOUNTERS_HOST_VRT_NODE = 2100, // host virt node
SFLCOUNTERS_HOST_VRT_CPU  = 2101, // host virt cpu
SFLCOUNTERS_HOST_VRT_MEM  = 2102, // host virt mem
SFLCOUNTERS_HOST_VRT_DSK  = 2103, // host virt storage
SFLCOUNTERS_HOST_VRT_NIO  = 2104, // host virt network I/O
SFLCOUNTERS_JVM           = 2105, // java runtime
SFLCOUNTERS_JMX           = 2106, // java JMX stats
SFLCOUNTERS_MEMCACHE      = 2200, // memcached (deprecated)
SFLCOUNTERS_HTTP          = 2201, // http
SFLCOUNTERS_APP           = 2202,
SFLCOUNTERS_APP_RESOURCE  = 2203,
SFLCOUNTERS_MEMCACHE2     = 2204, // memcached
SFLCOUNTERS_VDI           = 2205,
SFLCOUNTERS_APP_WORKERS   = 2206,
SFLCOUNTERS_OVSDP         = 2207,
SFLCOUNTERS_HOST_GPU_NVML = (5703 << 12) + 1, // = 23359489
SFLCOUNTERS_BCM_TABLES    = (4413 << 12) + 3,
*/
type SFlowCounterDataFormat uint32
type SFlowCounterRecordType uint32

const (
	SFlowTypeGenericInterfaceCounters   SFlowCounterRecordType = 1
	SFlowTypeEthernetInterfaceCounters  SFlowCounterRecordType = 2
	SFlowTypeTokenRingInterfaceCounters SFlowCounterRecordType = 3
	SFlowType100BaseVGInterfaceCounters SFlowCounterRecordType = 4
	SFlowTypeVLANCounters               SFlowCounterRecordType = 5
	SFlowTypeProcessorCounters          SFlowCounterRecordType = 1001
	SFlowTypeOFPortCounter              SFlowCounterRecordType = 1004
	SFlowTypeOFPortNameCounter          SFlowCounterRecordType = 1005
)

//-------------------------- SFlowRawPacketFlowRecord --------------------//

/*SFlowRawPacketFlowRecords hold information about a sampled
packet grabbed as it transited the agent. This is
perhaps the most useful and interesting record type,
as it holds the headers of the sampled packet and
can be used to build up a complete picture of the
traffic patterns on a network.
The raw packet header is sent back into gopacket for
decoding, and the resulting gopackt.Packet is stored
in the Header member
*/
type SFlowRawPacketFlowRecord struct {
	SFlowBaseFlowRecord
	HeaderProtocol SFlowRawHeaderProtocol
	FrameLength    uint32
	PayloadRemoved uint32
	HeaderLength   uint32
	Header         gopacket.Packet
}

// Raw packet record types have the following structure:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 Header Protocol               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 Frame Length                  |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 Payload Removed               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 Header Length                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  \                     Header                    \
//  \                                               \
//  \                                               \
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowRawHeaderProtocol uint32

const (
	SFlowProtoEthernet   SFlowRawHeaderProtocol = 1
	SFlowProtoISO88024   SFlowRawHeaderProtocol = 2
	SFlowProtoISO88025   SFlowRawHeaderProtocol = 3
	SFlowProtoFDDI       SFlowRawHeaderProtocol = 4
	SFlowProtoFrameRelay SFlowRawHeaderProtocol = 5
	SFlowProtoX25        SFlowRawHeaderProtocol = 6
	SFlowProtoPPP        SFlowRawHeaderProtocol = 7
	SFlowProtoSMDS       SFlowRawHeaderProtocol = 8
	SFlowProtoAAL5       SFlowRawHeaderProtocol = 9
	SFlowProtoAAL5_IP    SFlowRawHeaderProtocol = 10 /* e.g. Cisco AAL5 mux */
	SFlowProtoIPv4       SFlowRawHeaderProtocol = 11
	SFlowProtoIPv6       SFlowRawHeaderProtocol = 12
	SFlowProtoMPLS       SFlowRawHeaderProtocol = 13
	SFlowProtoPOS        SFlowRawHeaderProtocol = 14 /* RFC 1662, 2615 */
)


//-------------------------- Extended User Flow Record --------------------//


// **************************************************
//  Extended User Flow Record
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                Source Character Set           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 Source User Id                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |              Destination Character Set        |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |               Destination User ID             |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowExtendedUserFlow struct {
	SFlowBaseFlowRecord
	SourceCharSet      SFlowCharSet
	SourceUserID       string
	DestinationCharSet SFlowCharSet
	DestinationUserID  string
}

type SFlowCharSet uint32

const (
	SFlowCSunknown                 SFlowCharSet = 2
	SFlowCSASCII                   SFlowCharSet = 3
	SFlowCSISOLatin1               SFlowCharSet = 4
	SFlowCSISOLatin2               SFlowCharSet = 5
	SFlowCSISOLatin3               SFlowCharSet = 6
	SFlowCSISOLatin4               SFlowCharSet = 7
	SFlowCSISOLatinCyrillic        SFlowCharSet = 8
	SFlowCSISOLatinArabic          SFlowCharSet = 9
	SFlowCSISOLatinGreek           SFlowCharSet = 10
	SFlowCSISOLatinHebrew          SFlowCharSet = 11
	SFlowCSISOLatin5               SFlowCharSet = 12
	SFlowCSISOLatin6               SFlowCharSet = 13
	SFlowCSISOTextComm             SFlowCharSet = 14
	SFlowCSHalfWidthKatakana       SFlowCharSet = 15
	SFlowCSJISEncoding             SFlowCharSet = 16
	SFlowCSShiftJIS                SFlowCharSet = 17
	SFlowCSEUCPkdFmtJapanese       SFlowCharSet = 18
	SFlowCSEUCFixWidJapanese       SFlowCharSet = 19
	SFlowCSISO4UnitedKingdom       SFlowCharSet = 20
	SFlowCSISO11SwedishForNames    SFlowCharSet = 21
	SFlowCSISO15Italian            SFlowCharSet = 22
	SFlowCSISO17Spanish            SFlowCharSet = 23
	SFlowCSISO21German             SFlowCharSet = 24
	SFlowCSISO60DanishNorwegian    SFlowCharSet = 25
	SFlowCSISO69French             SFlowCharSet = 26
	SFlowCSISO10646UTF1            SFlowCharSet = 27
	SFlowCSISO646basic1983         SFlowCharSet = 28
	SFlowCSINVARIANT               SFlowCharSet = 29
	SFlowCSISO2IntlRefVersion      SFlowCharSet = 30
	SFlowCSNATSSEFI                SFlowCharSet = 31
	SFlowCSNATSSEFIADD             SFlowCharSet = 32
	SFlowCSNATSDANO                SFlowCharSet = 33
	SFlowCSNATSDANOADD             SFlowCharSet = 34
	SFlowCSISO10Swedish            SFlowCharSet = 35
	SFlowCSKSC56011987             SFlowCharSet = 36
	SFlowCSISO2022KR               SFlowCharSet = 37
	SFlowCSEUCKR                   SFlowCharSet = 38
	SFlowCSISO2022JP               SFlowCharSet = 39
	SFlowCSISO2022JP2              SFlowCharSet = 40
	SFlowCSISO13JISC6220jp         SFlowCharSet = 41
	SFlowCSISO14JISC6220ro         SFlowCharSet = 42
	SFlowCSISO16Portuguese         SFlowCharSet = 43
	SFlowCSISO18Greek7Old          SFlowCharSet = 44
	SFlowCSISO19LatinGreek         SFlowCharSet = 45
	SFlowCSISO25French             SFlowCharSet = 46
	SFlowCSISO27LatinGreek1        SFlowCharSet = 47
	SFlowCSISO5427Cyrillic         SFlowCharSet = 48
	SFlowCSISO42JISC62261978       SFlowCharSet = 49
	SFlowCSISO47BSViewdata         SFlowCharSet = 50
	SFlowCSISO49INIS               SFlowCharSet = 51
	SFlowCSISO50INIS8              SFlowCharSet = 52
	SFlowCSISO51INISCyrillic       SFlowCharSet = 53
	SFlowCSISO54271981             SFlowCharSet = 54
	SFlowCSISO5428Greek            SFlowCharSet = 55
	SFlowCSISO57GB1988             SFlowCharSet = 56
	SFlowCSISO58GB231280           SFlowCharSet = 57
	SFlowCSISO61Norwegian2         SFlowCharSet = 58
	SFlowCSISO70VideotexSupp1      SFlowCharSet = 59
	SFlowCSISO84Portuguese2        SFlowCharSet = 60
	SFlowCSISO85Spanish2           SFlowCharSet = 61
	SFlowCSISO86Hungarian          SFlowCharSet = 62
	SFlowCSISO87JISX0208           SFlowCharSet = 63
	SFlowCSISO88Greek7             SFlowCharSet = 64
	SFlowCSISO89ASMO449            SFlowCharSet = 65
	SFlowCSISO90                   SFlowCharSet = 66
	SFlowCSISO91JISC62291984a      SFlowCharSet = 67
	SFlowCSISO92JISC62991984b      SFlowCharSet = 68
	SFlowCSISO93JIS62291984badd    SFlowCharSet = 69
	SFlowCSISO94JIS62291984hand    SFlowCharSet = 70
	SFlowCSISO95JIS62291984handadd SFlowCharSet = 71
	SFlowCSISO96JISC62291984kana   SFlowCharSet = 72
	SFlowCSISO2033                 SFlowCharSet = 73
	SFlowCSISO99NAPLPS             SFlowCharSet = 74
	SFlowCSISO102T617bit           SFlowCharSet = 75
	SFlowCSISO103T618bit           SFlowCharSet = 76
	SFlowCSISO111ECMACyrillic      SFlowCharSet = 77
	SFlowCSa71                     SFlowCharSet = 78
	SFlowCSa72                     SFlowCharSet = 79
	SFlowCSISO123CSAZ24341985gr    SFlowCharSet = 80
	SFlowCSISO88596E               SFlowCharSet = 81
	SFlowCSISO88596I               SFlowCharSet = 82
	SFlowCSISO128T101G2            SFlowCharSet = 83
	SFlowCSISO88598E               SFlowCharSet = 84
	SFlowCSISO88598I               SFlowCharSet = 85
	SFlowCSISO139CSN369103         SFlowCharSet = 86
	SFlowCSISO141JUSIB1002         SFlowCharSet = 87
	SFlowCSISO143IECP271           SFlowCharSet = 88
	SFlowCSISO146Serbian           SFlowCharSet = 89
	SFlowCSISO147Macedonian        SFlowCharSet = 90
	SFlowCSISO150                  SFlowCharSet = 91
	SFlowCSISO151Cuba              SFlowCharSet = 92
	SFlowCSISO6937Add              SFlowCharSet = 93
	SFlowCSISO153GOST1976874       SFlowCharSet = 94
	SFlowCSISO8859Supp             SFlowCharSet = 95
	SFlowCSISO10367Box             SFlowCharSet = 96
	SFlowCSISO158Lap               SFlowCharSet = 97
	SFlowCSISO159JISX02121990      SFlowCharSet = 98
	SFlowCSISO646Danish            SFlowCharSet = 99
	SFlowCSUSDK                    SFlowCharSet = 100
	SFlowCSDKUS                    SFlowCharSet = 101
	SFlowCSKSC5636                 SFlowCharSet = 102
	SFlowCSUnicode11UTF7           SFlowCharSet = 103
	SFlowCSISO2022CN               SFlowCharSet = 104
	SFlowCSISO2022CNEXT            SFlowCharSet = 105
	SFlowCSUTF8                    SFlowCharSet = 106
	SFlowCSISO885913               SFlowCharSet = 109
	SFlowCSISO885914               SFlowCharSet = 110
	SFlowCSISO885915               SFlowCharSet = 111
	SFlowCSISO885916               SFlowCharSet = 112
	SFlowCSGBK                     SFlowCharSet = 113
	SFlowCSGB18030                 SFlowCharSet = 114
	SFlowCSOSDEBCDICDF0415         SFlowCharSet = 115
	SFlowCSOSDEBCDICDF03IRV        SFlowCharSet = 116
	SFlowCSOSDEBCDICDF041          SFlowCharSet = 117
	SFlowCSISO115481               SFlowCharSet = 118
	SFlowCSKZ1048                  SFlowCharSet = 119
	SFlowCSUnicode                 SFlowCharSet = 1000
	SFlowCSUCS4                    SFlowCharSet = 1001
	SFlowCSUnicodeASCII            SFlowCharSet = 1002
	SFlowCSUnicodeLatin1           SFlowCharSet = 1003
	SFlowCSUnicodeJapanese         SFlowCharSet = 1004
	SFlowCSUnicodeIBM1261          SFlowCharSet = 1005
	SFlowCSUnicodeIBM1268          SFlowCharSet = 1006
	SFlowCSUnicodeIBM1276          SFlowCharSet = 1007
	SFlowCSUnicodeIBM1264          SFlowCharSet = 1008
	SFlowCSUnicodeIBM1265          SFlowCharSet = 1009
	SFlowCSUnicode11               SFlowCharSet = 1010
	SFlowCSSCSU                    SFlowCharSet = 1011
	SFlowCSUTF7                    SFlowCharSet = 1012
	SFlowCSUTF16BE                 SFlowCharSet = 1013
	SFlowCSUTF16LE                 SFlowCharSet = 1014
	SFlowCSUTF16                   SFlowCharSet = 1015
	SFlowCSCESU8                   SFlowCharSet = 1016
	SFlowCSUTF32                   SFlowCharSet = 1017
	SFlowCSUTF32BE                 SFlowCharSet = 1018
	SFlowCSUTF32LE                 SFlowCharSet = 1019
	SFlowCSBOCU1                   SFlowCharSet = 1020
	SFlowCSWindows30Latin1         SFlowCharSet = 2000
	SFlowCSWindows31Latin1         SFlowCharSet = 2001
	SFlowCSWindows31Latin2         SFlowCharSet = 2002
	SFlowCSWindows31Latin5         SFlowCharSet = 2003
	SFlowCSHPRoman8                SFlowCharSet = 2004
	SFlowCSAdobeStandardEncoding   SFlowCharSet = 2005
	SFlowCSVenturaUS               SFlowCharSet = 2006
	SFlowCSVenturaInternational    SFlowCharSet = 2007
	SFlowCSDECMCS                  SFlowCharSet = 2008
	SFlowCSPC850Multilingual       SFlowCharSet = 2009
	SFlowCSPCp852                  SFlowCharSet = 2010
	SFlowCSPC8CodePage437          SFlowCharSet = 2011
	SFlowCSPC8DanishNorwegian      SFlowCharSet = 2012
	SFlowCSPC862LatinHebrew        SFlowCharSet = 2013
	SFlowCSPC8Turkish              SFlowCharSet = 2014
	SFlowCSIBMSymbols              SFlowCharSet = 2015
	SFlowCSIBMThai                 SFlowCharSet = 2016
	SFlowCSHPLegal                 SFlowCharSet = 2017
	SFlowCSHPPiFont                SFlowCharSet = 2018
	SFlowCSHPMath8                 SFlowCharSet = 2019
	SFlowCSHPPSMath                SFlowCharSet = 2020
	SFlowCSHPDesktop               SFlowCharSet = 2021
	SFlowCSVenturaMath             SFlowCharSet = 2022
	SFlowCSMicrosoftPublishing     SFlowCharSet = 2023
	SFlowCSWindows31J              SFlowCharSet = 2024
	SFlowCSGB2312                  SFlowCharSet = 2025
	SFlowCSBig5                    SFlowCharSet = 2026
	SFlowCSMacintosh               SFlowCharSet = 2027
	SFlowCSIBM037                  SFlowCharSet = 2028
	SFlowCSIBM038                  SFlowCharSet = 2029
	SFlowCSIBM273                  SFlowCharSet = 2030
	SFlowCSIBM274                  SFlowCharSet = 2031
	SFlowCSIBM275                  SFlowCharSet = 2032
	SFlowCSIBM277                  SFlowCharSet = 2033
	SFlowCSIBM278                  SFlowCharSet = 2034
	SFlowCSIBM280                  SFlowCharSet = 2035
	SFlowCSIBM281                  SFlowCharSet = 2036
	SFlowCSIBM284                  SFlowCharSet = 2037
	SFlowCSIBM285                  SFlowCharSet = 2038
	SFlowCSIBM290                  SFlowCharSet = 2039
	SFlowCSIBM297                  SFlowCharSet = 2040
	SFlowCSIBM420                  SFlowCharSet = 2041
	SFlowCSIBM423                  SFlowCharSet = 2042
	SFlowCSIBM424                  SFlowCharSet = 2043
	SFlowCSIBM500                  SFlowCharSet = 2044
	SFlowCSIBM851                  SFlowCharSet = 2045
	SFlowCSIBM855                  SFlowCharSet = 2046
	SFlowCSIBM857                  SFlowCharSet = 2047
	SFlowCSIBM860                  SFlowCharSet = 2048
	SFlowCSIBM861                  SFlowCharSet = 2049
	SFlowCSIBM863                  SFlowCharSet = 2050
	SFlowCSIBM864                  SFlowCharSet = 2051
	SFlowCSIBM865                  SFlowCharSet = 2052
	SFlowCSIBM868                  SFlowCharSet = 2053
	SFlowCSIBM869                  SFlowCharSet = 2054
	SFlowCSIBM870                  SFlowCharSet = 2055
	SFlowCSIBM871                  SFlowCharSet = 2056
	SFlowCSIBM880                  SFlowCharSet = 2057
	SFlowCSIBM891                  SFlowCharSet = 2058
	SFlowCSIBM903                  SFlowCharSet = 2059
	SFlowCSIBBM904                 SFlowCharSet = 2060
	SFlowCSIBM905                  SFlowCharSet = 2061
	SFlowCSIBM918                  SFlowCharSet = 2062
	SFlowCSIBM1026                 SFlowCharSet = 2063
	SFlowCSIBMEBCDICATDE           SFlowCharSet = 2064
	SFlowCSEBCDICATDEA             SFlowCharSet = 2065
	SFlowCSEBCDICCAFR              SFlowCharSet = 2066
	SFlowCSEBCDICDKNO              SFlowCharSet = 2067
	SFlowCSEBCDICDKNOA             SFlowCharSet = 2068
	SFlowCSEBCDICFISE              SFlowCharSet = 2069
	SFlowCSEBCDICFISEA             SFlowCharSet = 2070
	SFlowCSEBCDICFR                SFlowCharSet = 2071
	SFlowCSEBCDICIT                SFlowCharSet = 2072
	SFlowCSEBCDICPT                SFlowCharSet = 2073
	SFlowCSEBCDICES                SFlowCharSet = 2074
	SFlowCSEBCDICESA               SFlowCharSet = 2075
	SFlowCSEBCDICESS               SFlowCharSet = 2076
	SFlowCSEBCDICUK                SFlowCharSet = 2077
	SFlowCSEBCDICUS                SFlowCharSet = 2078
	SFlowCSUnknown8BiT             SFlowCharSet = 2079
	SFlowCSMnemonic                SFlowCharSet = 2080
	SFlowCSMnem                    SFlowCharSet = 2081
	SFlowCSVISCII                  SFlowCharSet = 2082
	SFlowCSVIQR                    SFlowCharSet = 2083
	SFlowCSKOI8R                   SFlowCharSet = 2084
	SFlowCSHZGB2312                SFlowCharSet = 2085
	SFlowCSIBM866                  SFlowCharSet = 2086
	SFlowCSPC775Baltic             SFlowCharSet = 2087
	SFlowCSKOI8U                   SFlowCharSet = 2088
	SFlowCSIBM00858                SFlowCharSet = 2089
	SFlowCSIBM00924                SFlowCharSet = 2090
	SFlowCSIBM01140                SFlowCharSet = 2091
	SFlowCSIBM01141                SFlowCharSet = 2092
	SFlowCSIBM01142                SFlowCharSet = 2093
	SFlowCSIBM01143                SFlowCharSet = 2094
	SFlowCSIBM01144                SFlowCharSet = 2095
	SFlowCSIBM01145                SFlowCharSet = 2096
	SFlowCSIBM01146                SFlowCharSet = 2097
	SFlowCSIBM01147                SFlowCharSet = 2098
	SFlowCSIBM01148                SFlowCharSet = 2099
	SFlowCSIBM01149                SFlowCharSet = 2100
	SFlowCSBig5HKSCS               SFlowCharSet = 2101
	SFlowCSIBM1047                 SFlowCharSet = 2102
	SFlowCSPTCP154                 SFlowCharSet = 2103
	SFlowCSAmiga1251               SFlowCharSet = 2104
	SFlowCSKOI7switched            SFlowCharSet = 2105
	SFlowCSBRF                     SFlowCharSet = 2106
	SFlowCSTSCII                   SFlowCharSet = 2107
	SFlowCSCP51932                 SFlowCharSet = 2108
	SFlowCSWindows874              SFlowCharSet = 2109
	SFlowCSWindows1250             SFlowCharSet = 2250
	SFlowCSWindows1251             SFlowCharSet = 2251
	SFlowCSWindows1252             SFlowCharSet = 2252
	SFlowCSWindows1253             SFlowCharSet = 2253
	SFlowCSWindows1254             SFlowCharSet = 2254
	SFlowCSWindows1255             SFlowCharSet = 2255
	SFlowCSWindows1256             SFlowCharSet = 2256
	SFlowCSWindows1257             SFlowCharSet = 2257
	SFlowCSWindows1258             SFlowCharSet = 2258
	SFlowCSTIS620                  SFlowCharSet = 2259
	SFlowCS50220                   SFlowCharSet = 2260
	SFlowCSreserved                SFlowCharSet = 3000
)

// **************************************************
//  Extended URL Flow Record
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   direction                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      URL                      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      Host                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowURLDirection uint32

const (
	SFlowURLsrc SFlowURLDirection = 1
	SFlowURLdst SFlowURLDirection = 2
)

type SFlowExtendedURLRecord struct {
	SFlowBaseFlowRecord
	Direction SFlowURLDirection
	URL       string
	Host      string
}
/*SFlowExtendedSwitchFlowRecord give additional information
about the sampled packet if it's available. It's mainly
useful for getting at the incoming and outgoing VLANs
An agent may or may not provide this information.*/
type SFlowExtendedSwitchFlowRecord struct {
	SFlowBaseFlowRecord
	IncomingVLAN         uint32
	IncomingVLANPriority uint32
	OutgoingVLAN         uint32
	OutgoingVLANPriority uint32
}

// Extended switch records have the following structure:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   Incoming VLAN               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                Incoming VLAN Priority         |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   Outgoing VLAN               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                Outgoing VLAN Priority         |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// SFlowExtendedRouterFlowRecord gives additional information
// about the layer 3 routing information used to forward
// the packet
type SFlowExtendedRouterFlowRecord struct {
	SFlowBaseFlowRecord
	NextHop                net.IP
	NextHopSourceMask      uint32
	NextHopDestinationMask uint32
}

// Extended router records have the following structure:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |   IP version of next hop router (1=v4|2=v6)   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /     Next Hop address (v4=4byte|v6=16byte)     /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |              Next Hop Source Mask             |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |              Next Hop Destination Mask        |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


//------------------------------

// SFlowExtendedGatewayFlowRecord describes information treasured by
// nework engineers everywhere: AS path information listing which
// BGP peer sent the packet, and various other BGP related info.
// This information is vital because it gives a picture of how much
// traffic is being sent from / received by various BGP peers.

// Extended gateway records have the following structure:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |   IP version of next hop router (1=v4|2=v6)   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /     Next Hop address (v4=4byte|v6=16byte)     /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                       AS                      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  Source AS                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    Peer AS                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  AS Path Count                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /                AS Path / Sequence             /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /                   Communities                 /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    Local Pref                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// AS Path / Sequence:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |     AS Source Type (Path=1 / Sequence=2)      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |              Path / Sequence length           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /              Path / Sequence Members          /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// Communities:

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                communitiy length              |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /              communitiy Members               /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowExtendedGatewayFlowRecord struct {
	SFlowBaseFlowRecord
	NextHop     net.IP
	AS          uint32
	SourceAS    uint32
	PeerAS      uint32
	ASPathCount uint32
	ASPath      []SFlowASDestination
	Communities []uint32
	LocalPref   uint32
}

type SFlowASPathType uint32

const (
	SFlowASSet      SFlowASPathType = 1
	SFlowASSequence SFlowASPathType = 2
)

type SFlowASDestination struct {
	Type    SFlowASPathType
	Count   uint32
	Members []uint32
}

// **************************************************
//  Packet IP version 4 Record
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                     Length                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    Protocol                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  Source IPv4                  |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                Destination IPv4               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   Source Port                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                Destionation Port              |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   TCP Flags                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      TOS                      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowIpv4Record struct {
	// The length of the IP packet excluding ower layer encapsulations
	Length uint32
	// IP Protocol type (for example, TCP = 6, UDP = 17)
	Protocol uint32
	// Source IP Address
	IPSrc net.IP
	// Destination IP Address
	IPDst net.IP
	// TCP/UDP source port number or equivalent
	PortSrc uint32
	// TCP/UDP destination port number or equivalent
	PortDst uint32
	// TCP flags
	TCPFlags uint32
	// IP type of service
	TOS uint32
}

// **************************************************
//  Packet IP version 6 Record
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                     Length                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    Protocol                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  Source IPv4                  |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                Destination IPv4               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   Source Port                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                Destionation Port              |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   TCP Flags                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    Priority                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowIpv6Record struct {
	// The length of the IP packet excluding ower layer encapsulations
	Length uint32
	// IP Protocol type (for example, TCP = 6, UDP = 17)
	Protocol uint32
	// Source IP Address
	IPSrc net.IP
	// Destination IP Address
	IPDst net.IP
	// TCP/UDP source port number or equivalent
	PortSrc uint32
	// TCP/UDP destination port number or equivalent
	PortDst uint32
	// TCP flags
	TCPFlags uint32
	// IP priority
	Priority uint32
}

// **************************************************
//  Extended IPv4 Tunnel Egress
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /           Packet IP version 4 Record          /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowExtendedIpv4TunnelEgressRecord struct {
	SFlowBaseFlowRecord
	SFlowIpv4Record SFlowIpv4Record
}

// **************************************************
//  Extended IPv4 Tunnel Ingress
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /           Packet IP version 4 Record          /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowExtendedIpv4TunnelIngressRecord struct {
	SFlowBaseFlowRecord
	SFlowIpv4Record SFlowIpv4Record
}

// **************************************************
//  Extended IPv6 Tunnel Egress
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /           Packet IP version 6 Record          /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowExtendedIpv6TunnelEgressRecord struct {
	SFlowBaseFlowRecord
	SFlowIpv6Record
}

// **************************************************
//  Extended IPv6 Tunnel Ingress
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /           Packet IP version 6 Record          /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowExtendedIpv6TunnelIngressRecord struct {
	SFlowBaseFlowRecord
	SFlowIpv6Record
}

// **************************************************
//  Extended Decapsulate Egress
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |               Inner Header Offset             |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowExtendedDecapsulateEgressRecord struct {
	SFlowBaseFlowRecord
	InnerHeaderOffset uint32
}

// **************************************************
//  Extended Decapsulate Ingress
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |               Inner Header Offset             |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowExtendedDecapsulateIngressRecord struct {
	SFlowBaseFlowRecord
	InnerHeaderOffset uint32
}

// **************************************************
//  Extended VNI Egress
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                       VNI                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowExtendedVniEgressRecord struct {
	SFlowBaseFlowRecord
	VNI uint32
}
// **************************************************
//  Extended VNI Ingress
// **************************************************

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  record length                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                       VNI                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowExtendedVniIngressRecord struct {
	SFlowBaseFlowRecord
	VNI uint32
}

// ****************************************************************************************************
//  Counter Record
// ****************************************************************************************************

type SFlowBaseCounterRecord struct {
	EnterpriseID   SFlowEnterpriseID
	Format         SFlowCounterRecordType
	FlowDataLength uint32
}

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  counter length               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    IfIndex                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    IfType                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfSpeed                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfDirection                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    IfStatus                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IFInOctets                  |
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfInUcastPkts               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  IfInMulticastPkts            |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  IfInBroadcastPkts            |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    IfInDiscards               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    InInErrors                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  IfInUnknownProtos            |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfOutOctets                 |
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfOutUcastPkts              |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  IfOutMulticastPkts           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  IfOutBroadcastPkts           |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   IfOutDiscards               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    IfOUtErrors                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 IfPromiscouousMode            |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowGenericInterfaceCounters struct {
	SFlowBaseCounterRecord
	IfIndex            uint32
	IfType             uint32
	IfSpeed            uint64
	IfDirection        uint32
	IfStatus           uint32
	IfInOctets         uint64
	IfInUcastPkts      uint32
	IfInMulticastPkts  uint32
	IfInBroadcastPkts  uint32
	IfInDiscards       uint32
	IfInErrors         uint32
	IfInUnknownProtos  uint32
	IfOutOctets        uint64
	IfOutUcastPkts     uint32
	IfOutMulticastPkts uint32
	IfOutBroadcastPkts uint32
	IfOutDiscards      uint32
	IfOutErrors        uint32
	IfPromiscuousMode  uint32
}

//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  counter length               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  /                   counter data                /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowEthernetCounters struct {
	SFlowBaseCounterRecord
	AlignmentErrors           uint32
	FCSErrors                 uint32
	SingleCollisionFrames     uint32
	MultipleCollisionFrames   uint32
	SQETestErrors             uint32
	DeferredTransmissions     uint32
	LateCollisions            uint32
	ExcessiveCollisions       uint32
	InternalMacTransmitErrors uint32
	CarrierSenseErrors        uint32
	FrameTooLongs             uint32
	InternalMacReceiveErrors  uint32
	SymbolErrors              uint32
}

// **************************************************
//  Processor Counter Record
// **************************************************
//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |      20 bit Interprise (0)     |12 bit format |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  counter length               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    FiveSecCpu                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    OneMinCpu                  |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    GiveMinCpu                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   TotalMemory                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    FreeMemory                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowProcessorCounters struct {
	SFlowBaseCounterRecord
	FiveSecCpu  uint32 // 5 second average CPU utilization
	OneMinCpu   uint32 // 1 minute average CPU utilization
	FiveMinCpu  uint32 // 5 minute average CPU utilization
	TotalMemory uint64 // total memory (in bytes)
	FreeMemory  uint64 // free memory (in bytes)
}

// **************************************************
//  OpenFlow Counter Record
// **************************************************
//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |           openflow datapath id  LLLLLLLL      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |           openflow datapath id  HHHHHHHH      |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                  openflow port                |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
type SFlowOFPortCounters struct {
	SFlowBaseCounterRecord
	OfDataPathId []byte // OpenFlow Data Path ID For each OVS bridge instances
	OfPort       uint32 // OpenFlow Port
}
// **************************************************
//  OpenFlow Port Name Counter Record
// **************************************************
//  0                      15                      31
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                 record length                 |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   skipBytes                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   Port Name                   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

type SFlowOFPortNameCounters struct {
	SFlowBaseCounterRecord
	OfPortName string // OpenFlow Port Name For each OVS bridge instances
}


// ****************************************************************************************************
//  Decode Flow and Counters type
// ****************************************************************************************************

func (sdf SFlowDataFormat) decode() (SFlowEnterpriseID, SFlowSampleType) {
	leftField := sdf >> 12
	rightField := uint32(0xFFF) & uint32(sdf)
	return SFlowEnterpriseID(leftField), SFlowSampleType(rightField)
}

func (sdce SFlowDataSourceExpanded) decode() (SFlowSourceFormat, SFlowSourceValue) {
	leftField := sdce.SourceIDClass >> 30
	rightField := uint32(0x3FFFFFFF) & uint32(sdce.SourceIDIndex)
	return SFlowSourceFormat(leftField), SFlowSourceValue(rightField)
}

func (sdc SFlowDataSource) decode() (SFlowSourceFormat, SFlowSourceValue) {
	leftField := sdc >> 30
	rightField := uint32(0x3FFFFFFF) & uint32(sdc)
	return SFlowSourceFormat(leftField), SFlowSourceValue(rightField)
}

func (cdf SFlowCounterDataFormat) decode() (SFlowEnterpriseID, SFlowCounterRecordType) {
	leftField := cdf >> 12
	rightField := uint32(0xFFF) & uint32(cdf)
	return SFlowEnterpriseID(leftField), SFlowCounterRecordType(rightField)
}

func (fdf SFlowFlowDataFormat) decode() (SFlowEnterpriseID, SFlowFlowRecordType) {
	leftField := fdf >> 12
	rightField := uint32(0xFFF) & uint32(fdf)
	return SFlowEnterpriseID(leftField), SFlowFlowRecordType(rightField)
}

func (ad *SFlowASDestination) decodePath(data *[]byte) {
	*data, ad.Type = (*data)[4:], SFlowASPathType(binary.BigEndian.Uint32((*data)[:4]))
	*data, ad.Count = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	ad.Members = make([]uint32, ad.Count)
	for i := uint32(0); i < ad.Count; i++ {
		var member uint32
		*data, member = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
		ad.Members[i] = member
	}
}

// *********************************************************************
//  SFLOW To String
// *********************************************************************
func (rt SFlowFlowRecordType) String() string {
	switch rt {
	case SFlowTypeRawPacketFlow:
		return "Raw Packet Flow Record"
	case SFlowTypeEthernetFrameFlow:
		return "Ethernet Frame Flow Record"
	case SFlowTypeIpv4Flow:
		return "IPv4 Flow Record"
	case SFlowTypeIpv6Flow:
		return "IPv6 Flow Record"
	case SFlowTypeExtendedSwitchFlow:
		return "Extended Switch Flow Record"
	case SFlowTypeExtendedRouterFlow:
		return "Extended Router Flow Record"
	case SFlowTypeExtendedGatewayFlow:
		return "Extended Gateway Flow Record"
	case SFlowTypeExtendedUserFlow:
		return "Extended User Flow Record"
	case SFlowTypeExtendedUrlFlow:
		return "Extended URL Flow Record"
	case SFlowTypeExtendedMlpsFlow:
		return "Extended MPLS Flow Record"
	case SFlowTypeExtendedNatFlow:
		return "Extended NAT Flow Record"
	case SFlowTypeExtendedMlpsTunnelFlow:
		return "Extended MPLS Tunnel Flow Record"
	case SFlowTypeExtendedMlpsVcFlow:
		return "Extended MPLS VC Flow Record"
	case SFlowTypeExtendedMlpsFecFlow:
		return "Extended MPLS FEC Flow Record"
	case SFlowTypeExtendedMlpsLvpFecFlow:
		return "Extended MPLS LVP FEC Flow Record"
	case SFlowTypeExtendedVlanFlow:
		return "Extended VLAN Flow Record"
	case SFlowTypeExtendedIpv4TunnelEgressFlow:
		return "Extended IPv4 Tunnel Egress Record"
	case SFlowTypeExtendedIpv4TunnelIngressFlow:
		return "Extended IPv4 Tunnel Ingress Record"
	case SFlowTypeExtendedIpv6TunnelEgressFlow:
		return "Extended IPv6 Tunnel Egress Record"
	case SFlowTypeExtendedIpv6TunnelIngressFlow:
		return "Extended IPv6 Tunnel Ingress Record"
	case SFlowTypeExtendedDecapsulateEgressFlow:
		return "Extended Decapsulate Egress Record"
	case SFlowTypeExtendedDecapsulateIngressFlow:
		return "Extended Decapsulate Ingress Record"
	case SFlowTypeExtendedVniEgressFlow:
		return "Extended VNI Ingress Record"
	case SFlowTypeExtendedVniIngressFlow:
		return "Extended VNI Ingress Record"
	default:
		return ""
	}
}

func (sfhp SFlowRawHeaderProtocol) String() string {
	switch sfhp {
	case SFlowProtoEthernet:
		return "ETHERNET-ISO88023"
	case SFlowProtoISO88024:
		return "ISO88024-TOKENBUS"
	case SFlowProtoISO88025:
		return "ISO88025-TOKENRING"
	case SFlowProtoFDDI:
		return "FDDI"
	case SFlowProtoFrameRelay:
		return "FRAME-RELAY"
	case SFlowProtoX25:
		return "X25"
	case SFlowProtoPPP:
		return "PPP"
	case SFlowProtoSMDS:
		return "SMDS"
	case SFlowProtoAAL5:
		return "AAL5"
	case SFlowProtoAAL5_IP:
		return "AAL5-IP"
	case SFlowProtoIPv4:
		return "IPv4"
	case SFlowProtoIPv6:
		return "IPv6"
	case SFlowProtoMPLS:
		return "MPLS"
	case SFlowProtoPOS:
		return "POS"
	}
	return "UNKNOWN"
}

func (urld SFlowURLDirection) String() string {
	switch urld {
	case SFlowURLsrc:
		return "Source address is the server"
	case SFlowURLdst:
		return "Destination address is the server"
	default:
		return ""
	}
}

func (apt SFlowASPathType) String() string {
	switch apt {
	case SFlowASSet:
		return "AS Set"
	case SFlowASSequence:
		return "AS Sequence"
	default:
		return ""
	}
}

func (asd SFlowASDestination) String() string {
	switch asd.Type {
	case SFlowASSet:
		return fmt.Sprint("AS Set:", asd.Members)
	case SFlowASSequence:
		return fmt.Sprint("AS Sequence:", asd.Members)
	default:
		return ""
	}
}




