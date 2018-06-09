package main

import (
	"github.com/google/gopacket"
	"fmt"
	"encoding/binary"
	"github.com/google/gopacket/layers"
	"errors"
	"net"
	"encoding/json"
	"github.com/google/gopacket/pcap"
	"log"
	"reflect"
)

var GenericSFlowType = gopacket.RegisterLayerType(12345, gopacket.LayerTypeMetadata{Name: "MyLayerType", Decoder: gopacket.DecodeFunc(decodeGenericSFlowDatagramLayer)})

// ****************************************************************************************************
//  Register Costume SFlow Layer
// ****************************************************************************************************

func (m GenericSFlowDatagram) LayerType() gopacket.LayerType { return GenericSFlowType }

//func (m MyLayer) LayerContents() []byte { return m.FlowSamples }

//func (m MyLayer) LayerPayload() []byte { return m.FlowSamples }

func (m GenericSFlowDatagram) LayerContents() []byte { return []byte{} }

func (d *GenericSFlowDatagram) Payload() []byte { return nil }

func (m GenericSFlowDatagram) LayerPayload() []byte { return []byte{} }

func (d *GenericSFlowDatagram) CanDecode() gopacket.LayerClass { return GenericSFlowType }

func (d *GenericSFlowDatagram) NextLayerType() gopacket.LayerType { return gopacket.LayerTypePayload }

func decodeGenericSFlowDatagramLayer(data []byte, p gopacket.PacketBuilder) error {
	// Create my layer
	myl := &GenericSFlowDatagram{}
	fmt.Println("+++++++++++");
	err := decodeGenericSFlowDatagramLayerByByte(data, myl)
	if err != nil {
		return err
	}
	p.AddLayer(myl)
	p.SetApplicationLayer(myl)
	return nil
}

func decodeGenericSFlowDatagramLayerByByte(data []byte, myl *GenericSFlowDatagram) error {
	var agentAddressType layers.SFlowIPType
	fmt.Println("Data in decodeMyLayerByByte")
	//fmt.Println(data)

	data, myl.DatagramVersion = data[4:], binary.BigEndian.Uint32(data[:4])
	data, agentAddressType = data[4:], layers.SFlowIPType(binary.BigEndian.Uint32(data[:4]))
	data, myl.AgentAddress = data[agentAddressType.Length():], data[:agentAddressType.Length()]
	data, myl.SubAgentID = data[4:], binary.BigEndian.Uint32(data[:4])
	data, myl.SequenceNumber = data[4:], binary.BigEndian.Uint32(data[:4])
	data, myl.AgentUptime = data[4:], binary.BigEndian.Uint32(data[:4])
	data, myl.SampleCount = data[4:], binary.BigEndian.Uint32(data[:4])

	if myl.SampleCount < 1 {
		fmt.Errorf("SFlow Datagram has invalid sample length: %d", myl.SampleCount)
	}

	for i := uint32(0); i < myl.SampleCount; i++ {
		sdf := SFlowDataFormat(binary.BigEndian.Uint32(data[:4]))
		_, sampleType := sdf.decode()
		switch sampleType {
		case SFlowTypeFlowSample:
			if flowSample, err := decodeFlowSample(&data, false); err == nil {
				myl.FlowSamples = append(myl.FlowSamples, flowSample)
			} else {
				//return err
			}
		case SFlowTypeCounterSample:
			if counterSample, err := decodeCounterSample(&data, false); err == nil {
				myl.CounterSamples = append(myl.CounterSamples, counterSample)
			} else {
				//return err
			}
			//case SFlowTypeExpandedFlowSample:
			//	if flowSample, err := decodeFlowSample(&data, true); err == nil {
			//		s.FlowSamples = append(s.FlowSamples, flowSample)
			//	} else {
			//		return err
			//	}
			//case SFlowTypeExpandedCounterSample:
			//	if counterSample, err := decodeCounterSample(&data, true); err == nil {
			//		s.CounterSamples = append(s.CounterSamples, counterSample)
			//	} else {
			//		return err
			//	}

		default:
			fmt.Errorf("Unsupported SFlow sample type %d", sampleType)
		}
	}
	return nil
}

// ****************************************************************************************************
// Generic Flow Sample Decoding
// ****************************************************************************************************

func decodeFlowSample(data *[]byte, expanded bool) (SFlowFlowSample, error) {
	s := SFlowFlowSample{}
	var sdf SFlowDataFormat
	*data, sdf = (*data)[4:], SFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	var sdc SFlowDataSource

	s.EnterpriseID, s.Format = sdf.decode()
	*data, s.SampleLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, s.SequenceNumber = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	if expanded {
		*data, s.SourceIDClass = (*data)[4:], SFlowSourceFormat(binary.BigEndian.Uint32((*data)[:4]))
		*data, s.SourceIDIndex = (*data)[4:], SFlowSourceValue(binary.BigEndian.Uint32((*data)[:4]))
	} else {
		*data, sdc = (*data)[4:], SFlowDataSource(binary.BigEndian.Uint32((*data)[:4]))
		s.SourceIDClass, s.SourceIDIndex = sdc.decode()
	}
	*data, s.SamplingRate = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, s.SamplePool = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, s.Dropped = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	if expanded {
		*data, s.InputInterfaceFormat = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
		*data, s.InputInterface = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
		*data, s.OutputInterfaceFormat = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
		*data, s.OutputInterface = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	} else {
		*data, s.InputInterface = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
		*data, s.OutputInterface = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	}
	*data, s.RecordCount = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	for i := uint32(0); i < s.RecordCount; i++ {
		rdf := SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
		_, flowRecordType := rdf.decode()

		switch flowRecordType {
		case SFlowTypeRawPacketFlow:
			if record, err := decodeRawPacketFlowRecord(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedUserFlow:
			if record, err := decodeExtendedUserFlow(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedUrlFlow:
			if record, err := decodeExtendedURLRecord(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedSwitchFlow:
			if record, err := decodeExtendedSwitchFlowRecord(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedRouterFlow:
			if record, err := decodeExtendedRouterFlowRecord(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedGatewayFlow:
			if record, err := decodeExtendedGatewayFlowRecord(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeEthernetFrameFlow:
			// TODO
			skipRecord(data)
			return s, errors.New("skipping TypeEthernetFrameFlow")
		case SFlowTypeIpv4Flow:
			if record, err := decodeSFlowIpv4Record(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeIpv6Flow:
			if record, err := decodeSFlowIpv6Record(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedMlpsFlow:
			// TODO
			skipRecord(data)
			return s, errors.New("skipping TypeExtendedMlpsFlow")
		case SFlowTypeExtendedNatFlow:
			// TODO
			skipRecord(data)
			return s, errors.New("skipping TypeExtendedNatFlow")
		case SFlowTypeExtendedMlpsTunnelFlow:
			// TODO
			skipRecord(data)
			return s, errors.New("skipping TypeExtendedMlpsTunnelFlow")
		case SFlowTypeExtendedMlpsVcFlow:
			// TODO
			skipRecord(data)
			return s, errors.New("skipping TypeExtendedMlpsVcFlow")
		case SFlowTypeExtendedMlpsFecFlow:
			// TODO
			skipRecord(data)
			return s, errors.New("skipping TypeExtendedMlpsFecFlow")
		case SFlowTypeExtendedMlpsLvpFecFlow:
			// TODO
			skipRecord(data)
			return s, errors.New("skipping TypeExtendedMlpsLvpFecFlow")
		case SFlowTypeExtendedVlanFlow:
			// TODO
			skipRecord(data)
			return s, errors.New("skipping TypeExtendedVlanFlow")
		case SFlowTypeExtendedIpv4TunnelEgressFlow:
			if record, err := decodeExtendedIpv4TunnelEgress(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedIpv4TunnelIngressFlow:
			if record, err := decodeExtendedIpv4TunnelIngress(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedIpv6TunnelEgressFlow:
			if record, err := decodeExtendedIpv6TunnelEgress(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedIpv6TunnelIngressFlow:
			if record, err := decodeExtendedIpv6TunnelIngress(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedDecapsulateEgressFlow:
			if record, err := decodeExtendedDecapsulateEgress(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedDecapsulateIngressFlow:
			if record, err := decodeExtendedDecapsulateIngress(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedVniEgressFlow:
			if record, err := decodeExtendedVniEgress(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeExtendedVniIngressFlow:
			if record, err := decodeExtendedVniIngress(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		default:
			return s, fmt.Errorf("Unsupported flow record type: %d", flowRecordType)
		}
	}
	return s, nil
}

func decodeRawPacketFlowRecord(data *[]byte) (SFlowRawPacketFlowRecord, error) {
	rec := SFlowRawPacketFlowRecord{}
	header := []byte{}
	var fdf SFlowFlowDataFormat

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	rec.EnterpriseID, rec.Format = fdf.decode()
	*data, rec.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, rec.HeaderProtocol = (*data)[4:], SFlowRawHeaderProtocol(binary.BigEndian.Uint32((*data)[:4]))
	*data, rec.FrameLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, rec.PayloadRemoved = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, rec.HeaderLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	headerLenWithPadding := int(rec.HeaderLength + ((4 - rec.HeaderLength) % 4))
	*data, header = (*data)[headerLenWithPadding:], (*data)[:headerLenWithPadding]
	rec.Header = gopacket.NewPacket(header, layers.LayerTypeEthernet, gopacket.Default)
	return rec, nil
}

func decodeExtendedUserFlow(data *[]byte) (SFlowExtendedUserFlow, error) {
	eu := SFlowExtendedUserFlow{}
	var fdf SFlowFlowDataFormat
	var srcUserLen uint32
	var srcUserLenWithPad int
	var srcUserBytes []byte
	var dstUserLen uint32
	var dstUserLenWithPad int
	var dstUserBytes []byte

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	eu.EnterpriseID, eu.Format = fdf.decode()
	*data, eu.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, eu.SourceCharSet = (*data)[4:], SFlowCharSet(binary.BigEndian.Uint32((*data)[:4]))
	*data, srcUserLen = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	srcUserLenWithPad = int(srcUserLen + ((4 - srcUserLen) % 4))
	*data, srcUserBytes = (*data)[srcUserLenWithPad:], (*data)[:srcUserLenWithPad]
	eu.SourceUserID = string(srcUserBytes[:srcUserLen])
	*data, eu.DestinationCharSet = (*data)[4:], SFlowCharSet(binary.BigEndian.Uint32((*data)[:4]))
	*data, dstUserLen = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	dstUserLenWithPad = int(dstUserLen + ((4 - dstUserLen) % 4))
	*data, dstUserBytes = (*data)[dstUserLenWithPad:], (*data)[:dstUserLenWithPad]
	eu.DestinationUserID = string(dstUserBytes[:dstUserLen])
	return eu, nil
}

func decodeExtendedURLRecord(data *[]byte) (SFlowExtendedURLRecord, error) {
	eur := SFlowExtendedURLRecord{}
	var fdf SFlowFlowDataFormat
	var urlLen uint32
	var urlLenWithPad int
	var hostLen uint32
	var hostLenWithPad int
	var urlBytes []byte
	var hostBytes []byte

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	eur.EnterpriseID, eur.Format = fdf.decode()
	*data, eur.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, eur.Direction = (*data)[4:], SFlowURLDirection(binary.BigEndian.Uint32((*data)[:4]))
	*data, urlLen = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	urlLenWithPad = int(urlLen + ((4 - urlLen) % 4))
	*data, urlBytes = (*data)[urlLenWithPad:], (*data)[:urlLenWithPad]
	eur.URL = string(urlBytes[:urlLen])
	*data, hostLen = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	hostLenWithPad = int(hostLen + ((4 - hostLen) % 4))
	*data, hostBytes = (*data)[hostLenWithPad:], (*data)[:hostLenWithPad]
	eur.Host = string(hostBytes[:hostLen])
	return eur, nil
}

func decodeExtendedSwitchFlowRecord(data *[]byte) (SFlowExtendedSwitchFlowRecord, error) {
	es := SFlowExtendedSwitchFlowRecord{}
	var fdf SFlowFlowDataFormat

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	es.EnterpriseID, es.Format = fdf.decode()
	*data, es.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, es.IncomingVLAN = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, es.IncomingVLANPriority = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, es.OutgoingVLAN = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, es.OutgoingVLANPriority = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	return es, nil
}

func decodeExtendedRouterFlowRecord(data *[]byte) (SFlowExtendedRouterFlowRecord, error) {
	er := SFlowExtendedRouterFlowRecord{}
	var fdf SFlowFlowDataFormat
	var extendedRouterAddressType layers.SFlowIPType

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	er.EnterpriseID, er.Format = fdf.decode()
	*data, er.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, extendedRouterAddressType = (*data)[4:], layers.SFlowIPType(binary.BigEndian.Uint32((*data)[:4]))
	*data, er.NextHop = (*data)[extendedRouterAddressType.Length():], (*data)[:extendedRouterAddressType.Length()]
	*data, er.NextHopSourceMask = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, er.NextHopDestinationMask = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	return er, nil
}

func decodeExtendedGatewayFlowRecord(data *[]byte) (SFlowExtendedGatewayFlowRecord, error) {
	eg := SFlowExtendedGatewayFlowRecord{}
	var fdf SFlowFlowDataFormat
	var extendedGatewayAddressType layers.SFlowIPType
	var communitiesLength uint32
	var community uint32

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	eg.EnterpriseID, eg.Format = fdf.decode()
	*data, eg.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, extendedGatewayAddressType = (*data)[4:], layers.SFlowIPType(binary.BigEndian.Uint32((*data)[:4]))
	*data, eg.NextHop = (*data)[extendedGatewayAddressType.Length():], (*data)[:extendedGatewayAddressType.Length()]
	*data, eg.AS = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, eg.SourceAS = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, eg.PeerAS = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, eg.ASPathCount = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	for i := uint32(0); i < eg.ASPathCount; i++ {
		asPath := SFlowASDestination{}
		asPath.decodePath(data)
		eg.ASPath = append(eg.ASPath, asPath)
	}
	*data, communitiesLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	eg.Communities = make([]uint32, communitiesLength)
	for j := uint32(0); j < communitiesLength; j++ {
		*data, community = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
		eg.Communities[j] = community
	}
	*data, eg.LocalPref = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	return eg, nil
}

func decodeSFlowIpv4Record(data *[]byte) (SFlowIpv4Record, error) {
	si := SFlowIpv4Record{}

	*data, si.Length = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, si.Protocol = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, si.IPSrc = (*data)[4:], net.IP((*data)[:4])
	*data, si.IPDst = (*data)[4:], net.IP((*data)[:4])
	*data, si.PortSrc = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, si.PortDst = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, si.TCPFlags = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, si.TOS = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	return si, nil
}

func decodeSFlowIpv6Record(data *[]byte) (SFlowIpv6Record, error) {
	si := SFlowIpv6Record{}

	*data, si.Length = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, si.Protocol = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, si.IPSrc = (*data)[16:], net.IP((*data)[:16])
	*data, si.IPDst = (*data)[16:], net.IP((*data)[:16])
	*data, si.PortSrc = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, si.PortDst = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, si.TCPFlags = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, si.Priority = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	return si, nil
}

func decodeExtendedIpv4TunnelEgress(data *[]byte) (SFlowExtendedIpv4TunnelEgressRecord, error) {
	rec := SFlowExtendedIpv4TunnelEgressRecord{}
	var fdf SFlowFlowDataFormat

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	rec.EnterpriseID, rec.Format = fdf.decode()
	*data, rec.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	rec.SFlowIpv4Record, _ = decodeSFlowIpv4Record(data)

	return rec, nil
}

func decodeExtendedIpv4TunnelIngress(data *[]byte) (SFlowExtendedIpv4TunnelIngressRecord, error) {
	rec := SFlowExtendedIpv4TunnelIngressRecord{}
	var fdf SFlowFlowDataFormat

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	rec.EnterpriseID, rec.Format = fdf.decode()
	*data, rec.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	rec.SFlowIpv4Record, _ = decodeSFlowIpv4Record(data)

	return rec, nil
}

func decodeExtendedIpv6TunnelEgress(data *[]byte) (SFlowExtendedIpv6TunnelEgressRecord, error) {
	rec := SFlowExtendedIpv6TunnelEgressRecord{}
	var fdf SFlowFlowDataFormat

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	rec.EnterpriseID, rec.Format = fdf.decode()
	*data, rec.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	rec.SFlowIpv6Record, _ = decodeSFlowIpv6Record(data)

	return rec, nil
}

func decodeExtendedIpv6TunnelIngress(data *[]byte) (SFlowExtendedIpv6TunnelIngressRecord, error) {
	rec := SFlowExtendedIpv6TunnelIngressRecord{}
	var fdf SFlowFlowDataFormat

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	rec.EnterpriseID, rec.Format = fdf.decode()
	*data, rec.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	rec.SFlowIpv6Record, _ = decodeSFlowIpv6Record(data)

	return rec, nil
}

func decodeExtendedDecapsulateEgress(data *[]byte) (SFlowExtendedDecapsulateEgressRecord, error) {
	rec := SFlowExtendedDecapsulateEgressRecord{}
	var fdf SFlowFlowDataFormat

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	rec.EnterpriseID, rec.Format = fdf.decode()
	*data, rec.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, rec.InnerHeaderOffset = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	return rec, nil
}

func decodeExtendedDecapsulateIngress(data *[]byte) (SFlowExtendedDecapsulateIngressRecord, error) {
	rec := SFlowExtendedDecapsulateIngressRecord{}
	var fdf SFlowFlowDataFormat

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	rec.EnterpriseID, rec.Format = fdf.decode()
	*data, rec.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, rec.InnerHeaderOffset = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	return rec, nil
}

func decodeExtendedVniEgress(data *[]byte) (SFlowExtendedVniEgressRecord, error) {
	rec := SFlowExtendedVniEgressRecord{}
	var fdf SFlowFlowDataFormat

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	rec.EnterpriseID, rec.Format = fdf.decode()
	*data, rec.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, rec.VNI = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	return rec, nil
}

func decodeExtendedVniIngress(data *[]byte) (SFlowExtendedVniIngressRecord, error) {
	rec := SFlowExtendedVniIngressRecord{}
	var fdf SFlowFlowDataFormat

	*data, fdf = (*data)[4:], SFlowFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	rec.EnterpriseID, rec.Format = fdf.decode()
	*data, rec.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, rec.VNI = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	return rec, nil
}

// ****************************************************************************************************
//  Counter Decoding
// ****************************************************************************************************

func decodeCounterSample(data *[]byte, expanded bool) (SFlowCounterSample, error) {
	s := SFlowCounterSample{}
	var sdc SFlowDataSource
	var sdce SFlowDataSourceExpanded
	var sdf SFlowDataFormat

	*data, sdf = (*data)[4:], SFlowDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	s.EnterpriseID, s.Format = sdf.decode()
	*data, s.SampleLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, s.SequenceNumber = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	if expanded {
		*data, sdce = (*data)[8:], SFlowDataSourceExpanded{SFlowSourceFormat(binary.BigEndian.Uint32((*data)[:4])), SFlowSourceValue(binary.BigEndian.Uint32((*data)[4:8]))}
		s.SourceIDClass, s.SourceIDIndex = sdce.decode()
	} else {
		*data, sdc = (*data)[4:], SFlowDataSource(binary.BigEndian.Uint32((*data)[:4]))
		s.SourceIDClass, s.SourceIDIndex = sdc.decode()
	}
	//fmt.Println("SourceIDIndex: ", s.SourceIDIndex)
	*data, s.RecordCount = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	for i := uint32(0); i < s.RecordCount; i++ {
		cdf := SFlowCounterDataFormat(binary.BigEndian.Uint32((*data)[:4]))
		_, counterRecordType := cdf.decode()
		switch counterRecordType {
		case SFlowTypeGenericInterfaceCounters:
			if record, err := decodeGenericInterfaceCounters(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeEthernetInterfaceCounters:
			if record, err := decodeEthernetCounters(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeTokenRingInterfaceCounters:
			skipRecord(data)
			return s, errors.New("skipping TypeTokenRingInterfaceCounters")
		case SFlowType100BaseVGInterfaceCounters:
			skipRecord(data)
			return s, errors.New("skipping Type100BaseVGInterfaceCounters")
		case SFlowTypeVLANCounters:
			skipRecord(data)
			return s, errors.New("skipping TypeVLANCounters")
		case SFlowTypeProcessorCounters:
			if record, err := decodeProcessorCounters(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeOFPortCounter:
			if record, err := decodeOFPortCounters(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		case SFlowTypeOFPortNameCounter:
			if record, err := decodeOFPortNameCounters(data); err == nil {
				s.Records = append(s.Records, record)
			} else {
				return s, err
			}
		default:
			return s, fmt.Errorf("Invalid counter record type: %d", counterRecordType)
		}
	}
	return s, nil
}

func skipRecord(data *[]byte) {
	recordLength := int(binary.BigEndian.Uint32((*data)[4:]))
	*data = (*data)[(recordLength+((4-recordLength)%4))+8:]
}

func decodeGenericInterfaceCounters(data *[]byte) (SFlowGenericInterfaceCounters, error) {
	gic := SFlowGenericInterfaceCounters{}
	var cdf SFlowCounterDataFormat

	*data, cdf = (*data)[4:], SFlowCounterDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	gic.EnterpriseID, gic.Format = cdf.decode()
	*data, gic.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfIndex = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfType = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfSpeed = (*data)[8:], binary.BigEndian.Uint64((*data)[:8])
	*data, gic.IfDirection = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfStatus = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfInOctets = (*data)[8:], binary.BigEndian.Uint64((*data)[:8])
	*data, gic.IfInUcastPkts = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfInMulticastPkts = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfInBroadcastPkts = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfInDiscards = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfInErrors = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfInUnknownProtos = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfOutOctets = (*data)[8:], binary.BigEndian.Uint64((*data)[:8])
	*data, gic.IfOutUcastPkts = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfOutMulticastPkts = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfOutBroadcastPkts = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfOutDiscards = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfOutErrors = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, gic.IfPromiscuousMode = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	return gic, nil
}

func decodeEthernetCounters(data *[]byte) (SFlowEthernetCounters, error) {
	ec := SFlowEthernetCounters{}
	var cdf SFlowCounterDataFormat

	*data, cdf = (*data)[4:], SFlowCounterDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	ec.EnterpriseID, ec.Format = cdf.decode()
	*data, ec.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.AlignmentErrors = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.FCSErrors = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.SingleCollisionFrames = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.MultipleCollisionFrames = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.SQETestErrors = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.DeferredTransmissions = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.LateCollisions = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.ExcessiveCollisions = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.InternalMacTransmitErrors = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.CarrierSenseErrors = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.FrameTooLongs = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.InternalMacReceiveErrors = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, ec.SymbolErrors = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	return ec, nil
}

func decodeProcessorCounters(data *[]byte) (SFlowProcessorCounters, error) {
	pc := SFlowProcessorCounters{}
	var cdf SFlowCounterDataFormat
	var high32, low32 uint32

	*data, cdf = (*data)[4:], SFlowCounterDataFormat(binary.BigEndian.Uint32((*data)[:4]))
	pc.EnterpriseID, pc.Format = cdf.decode()
	*data, pc.FlowDataLength = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])

	*data, pc.FiveSecCpu = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, pc.OneMinCpu = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, pc.FiveMinCpu = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, high32 = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, low32 = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	pc.TotalMemory = (uint64(high32) << 32) + uint64(low32)
	*data, high32 = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	*data, low32 = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	pc.FreeMemory = (uint64(high32)) + uint64(low32)

	return pc, nil
}

func decodeOFPortCounters(data *[]byte) (SFlowOFPortCounters, error) {
	ofc := SFlowOFPortCounters{}

	*data = (*data)[4:]

	// For length
	*data = (*data)[4:]
	//*data, ofc.OfDataPathId = (*data)[8:], binary.BigEndian.Uint64((*data)[:8])
	*data, ofc.OfDataPathId = (*data)[8:], (*data)[:8]
	*data, ofc.OfPort = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	//fmt.Println("Path ID: ", ofc.OfDataPathId)
	return ofc, nil
}

func decodeOFPortNameCounters(data *[]byte) (SFlowOFPortNameCounters, error) {
	ofpnc := SFlowOFPortNameCounters{}
	var portNameLenght uint32
	var portNameLenWithPad int
	var portNameBytes []byte

	/*
	remove SFlowFlowDataFormat byte from previous method (in prev method we didn't remove them from *data)
	tag = 1005 -> SFLCOUNTERS_PORTNAME
	length
	skipBytes
	name
	 */
	*data = (*data)[4:]
	// remove length data
	*data = (*data)[4:]

	*data, portNameLenght = (*data)[4:], binary.BigEndian.Uint32((*data)[:4])
	portNameLenWithPad = int(portNameLenght + ((4 - portNameLenght) % 4))
	*data, portNameBytes = (*data)[portNameLenWithPad:], (*data)[:portNameLenWithPad]
	ofpnc.OfPortName = string(portNameBytes[:portNameLenght])
	//fmt.Println("port name: ", ofpnc.OfPortName)

	return ofpnc, nil
}

func main() {
	xnfvAllSwitches := XnfvAllSwitches{}

	if handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever); err != nil {
		//if handle, err := pcap.OpenLive(); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter("udp and port 6343"); err != nil { // optional
		panic(err)
	} else {

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			var isSflow = false
			p := gopacket.NewPacket(packet.Data(), layers.LayerTypeEthernet, gopacket.Default)

			fmt.Println("---------------------------------------------------------")
			fmt.Println("*************************** ")
			if len(packet.Layers()) > 0 {
				for _, layer := range packet.Layers() {
					if layer.LayerType() == layers.LayerTypeSFlow {
						isSflow = true
						//decodeMyLayerByByte(layer.LayerContents(), &myl)
						//fmt.Println("Sflow Sample")
						sflow := layer.(*layers.SFlowDatagram)
						fmt.Println(sflow.SubAgentID)
						if len(sflow.FlowSamples) > 0 {
							data, err := json.Marshal(sflow)
							if err != nil {
								log.Fatal(err)
							}
							fmt.Printf("%s\n", data)

							for i := 0; i < len(sflow.FlowSamples); i++ {

								//data, err := json.Marshal(sflow.FlowSamples[i])
								//if err != nil {
								//	log.Fatal(err)
								//}
								//fmt.Printf("%s\n", data)

								//fmt.Println(sflow.FlowSamples[i].InputInterface)
								//fmt.Println(sflow.FlowSamples[i].InputInterfaceFormat)
								if len(sflow.FlowSamples[i].Records) > 0 {
									for j := 0; j < len(sflow.FlowSamples[i].Records); j++ {
										fmt.Println("++++++++++++++++++++")
										//fmt.Println(string((sflow.FlowSamples[i].Records[j]).(type)))
										//fmt.Println(reflect.TypeOf(sflow.FlowSamples[i].Records[j]))

										if reflect.TypeOf(sflow.FlowSamples[i].Records[j]) == reflect.TypeOf((*layers.SFlowRawPacketFlowRecord)(nil)).Elem() {
											t1, ok := (sflow.FlowSamples[i].Records[j]).(layers.SFlowRawPacketFlowRecord)
											if ok {

												//found switch with specific in InputInterface ID
												if len(xnfvAllSwitches.allAvailableSwitches) > 0 {
													for jj := 0; jj < len(xnfvAllSwitches.allAvailableSwitches); jj ++ {
														if len(xnfvAllSwitches.allAvailableSwitches[jj].switchPortsStatistics) > 0 {
															for ii := 0; ii < len(xnfvAllSwitches.allAvailableSwitches[jj].switchPortsStatistics); ii ++ {
																if xnfvAllSwitches.allAvailableSwitches[jj].switchPortsStatistics[ii].interfacePortIndex == SFlowSourceValue(sflow.FlowSamples[i].InputInterface) {
																	packet := gopacket.NewPacket(t1.Header.Data(), layers.LayerTypeEthernet, gopacket.Default)
																	xnfvAllSwitches.allAvailableSwitches[jj].switchPortsStatistics[ii].PacketHeader = packet.Layers()
																	break
																}
															}
														}
													}
												}
												//packet := gopacket.NewPacket(t1.Header.Data(), layers.LayerTypeEthernet, gopacket.Default)
												//fmt.Println(packet)
												//if len(packet.Layers()) > 0 {
												//	for _, layer := range packet.Layers() {
												//		fmt.Println("OOOOOOOKKKKKKK $$$$$$$$$$")
												//		fmt.Println(layer.LayerType())
												//		data, err := json.Marshal(layer)
												//		if err != nil {
												//			log.Fatal(err)
												//		}
												//		fmt.Printf("%s\n", data)
												//	}
												//}

											}
										}

										//fmt.Println(sflow.FlowSamples[i].Records[j])
									}
								}
							}
						}

						//fmt.Println("111111")
						//fmt.Println(layer.LayerPayload())
						//fmt.Println("2222222")
						//fmt.Println(layer.LayerContents())
						//decodeMyLayerByByte(layer.LayerPayload(), &myl)
						//fmt.Println(myl)
						//fmt.Println(myl)
					} else {
						//decodeMyLayerByByte(layer.LayerContents(), &myl)
						//fmt.Println("Counter Sample")
						//fmt.Println(myl)
					}
				}
			}
			if !isSflow {
				genericSflowCounter := GenericSFlowDatagram{}
				fmt.Println("Counter Sample")
				decodeGenericSFlowDatagramLayerByByte(p.Layers()[3].LayerContents(), &genericSflowCounter)

				if len(genericSflowCounter.CounterSamples) > 0 {
					for i := 0; i < len(genericSflowCounter.CounterSamples); i++ {
						var currentSwitchDataPathId []byte
						for ii := 0; ii < len(genericSflowCounter.CounterSamples[i].Records); ii++ {
							// If Record is "SFlowOFPortCounters"
							if reflect.TypeOf(genericSflowCounter.CounterSamples[i].Records[ii]) == reflect.TypeOf((*SFlowOFPortCounters)(nil)).Elem() {
								sFlowOFPortCounter, ok := (genericSflowCounter.CounterSamples[i].Records[ii]).(SFlowOFPortCounters)
								if ok {
									currentSwitchDataPathId = sFlowOFPortCounter.OfDataPathId
									if len(xnfvAllSwitches.allAvailableSwitches) > 0 {
										isSwitchAddedBefore := false
										for j := 0; j < len(xnfvAllSwitches.allAvailableSwitches); j ++ {
											// Check if specific switch add to xnfvAllSwitches before or not
											if reflect.DeepEqual(xnfvAllSwitches.allAvailableSwitches[j].switchDataPath, sFlowOFPortCounter.OfDataPathId) {
												isSwitchAddedBefore = true
												break
											}
										}
										if !isSwitchAddedBefore {
											xnfvAllSwitches.allAvailableSwitches = append(xnfvAllSwitches.allAvailableSwitches, XnfSwitchSflow{
												sFlowOFPortCounter.OfDataPathId, nil})
										}
									} else {
										// "xnfvAllSwitches" is empty So add new Switch to it
										xnfvAllSwitches.allAvailableSwitches = append(xnfvAllSwitches.allAvailableSwitches, XnfSwitchSflow{
											sFlowOFPortCounter.OfDataPathId, nil})
									}
								}
							} else if reflect.TypeOf(genericSflowCounter.CounterSamples[i].Records[ii]) == reflect.TypeOf((*SFlowOFPortNameCounters)(nil)).Elem() {
								sFlowOFPortNameCounter, ok := (genericSflowCounter.CounterSamples[i].Records[ii]).(SFlowOFPortNameCounters)
								if ok && len(currentSwitchDataPathId) > 0 {
									if len(xnfvAllSwitches.allAvailableSwitches) > 0 {
										for j := 0; j < len(xnfvAllSwitches.allAvailableSwitches); j ++ {
											// Check if specific switch add to xnfvAllSwitches before or not
											if reflect.DeepEqual(xnfvAllSwitches.allAvailableSwitches[j].switchDataPath, currentSwitchDataPathId) {
												// find specific port on switch
												if len(xnfvAllSwitches.allAvailableSwitches[j].switchPortsStatistics) > 0 {
													isPortStatisticsAddedBefore := false
													for i := 0; i < len(xnfvAllSwitches.allAvailableSwitches[j].switchPortsStatistics); i++ {
														if xnfvAllSwitches.allAvailableSwitches[j].switchPortsStatistics[i].interfacePortName == sFlowOFPortNameCounter.OfPortName {
															isPortStatisticsAddedBefore = true
															break
														}
													}
													if !isPortStatisticsAddedBefore {
														xnfvAllSwitches.allAvailableSwitches[j].switchPortsStatistics = append(xnfvAllSwitches.allAvailableSwitches[j].switchPortsStatistics,
															XnfvSwitchPort{
																sFlowOFPortNameCounter.OfPortName,
																genericSflowCounter.CounterSamples[i].SourceIDIndex,
																[]gopacket.Layer{},
																genericSflowCounter})
													}
												} else {
													xnfvAllSwitches.allAvailableSwitches[j].switchPortsStatistics = append(xnfvAllSwitches.allAvailableSwitches[j].switchPortsStatistics,
														XnfvSwitchPort{
															sFlowOFPortNameCounter.OfPortName,
															genericSflowCounter.CounterSamples[i].SourceIDIndex,
															[]gopacket.Layer{},
															genericSflowCounter})
												}
											}
										}
									}
								}
							}
						}

					}
				}

				//data, err := json.Marshal(mySflowCounter)
				//if err != nil {
				//	log.Fatal(err)
				//}
				//fmt.Printf("%s\n", data)
			}

			//fmt.Println(xnfvAllSwitches)
			//data, err := json.Marshal(xnfvAllSwitches)
			//if err != nil {
			//	log.Fatal(err)
			//}
			//fmt.Printf("%s\n", data)

			for i := 0; i < len(xnfvAllSwitches.allAvailableSwitches); i++ {
				fmt.Println("<------------>")
				fmt.Println("switchDataPath -> ", xnfvAllSwitches.allAvailableSwitches[i].switchDataPath)
				for j := 0; j < len(xnfvAllSwitches.allAvailableSwitches[i].switchPortsStatistics); j++ {
					fmt.Println("interfacePortName -> ", xnfvAllSwitches.allAvailableSwitches[i].switchPortsStatistics[j].interfacePortName)
					fmt.Println("interfacePortIndex -> ", xnfvAllSwitches.allAvailableSwitches[i].switchPortsStatistics[j].interfacePortIndex)
					fmt.Println("SubAgentID -> ", xnfvAllSwitches.allAvailableSwitches[i].switchPortsStatistics[j].interfaceSflowDatagram.SubAgentID)
					fmt.Println("PacketHeader -> ", xnfvAllSwitches.allAvailableSwitches[i].switchPortsStatistics[j].PacketHeader)
				}
			}
			fmt.Println("***************************")
			fmt.Println(" ");
			fmt.Println(" ");
			fmt.Println(" ");
			fmt.Println(" ");
		}

	}

}
