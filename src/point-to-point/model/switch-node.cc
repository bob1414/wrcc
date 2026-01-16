#include "ns3/ipv4.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include "ns3/pause-header.h"
#include "ns3/flow-id-tag.h"
#include "ns3/boolean.h"
#include "ns3/uinteger.h"
#include "ns3/double.h"
#include "switch-node.h"
#include "qbb-net-device.h"
#include "ppp-header.h"
#include "ns3/int-header.h"
#include <cmath>
#include "qbb-header.h"
#include "cn-header.h"
#include "ns3/log.h"
#include "ns3/random-variable.h"

NS_LOG_COMPONENT_DEFINE("SwitchNode_Device");

namespace ns3 {

TypeId SwitchNode::GetTypeId (void)
{
  static TypeId tid = TypeId ("ns3::SwitchNode")
    .SetParent<Node> ()
    .AddConstructor<SwitchNode> ()
	.AddAttribute("EcnEnabled",
			"Enable ECN marking.",
			BooleanValue(false),
			MakeBooleanAccessor(&SwitchNode::m_ecnEnabled),
			MakeBooleanChecker())
	.AddAttribute("CcMode",
			"CC mode.",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ccMode),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("AckHighPrio",
			"Set high priority for ACK/NACK or not",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::m_ackHighPrio),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("MaxRtt",
			"Max Rtt of the network",
			UintegerValue(9000),
			MakeUintegerAccessor(&SwitchNode::m_maxRtt),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("SwitchCC_PERS",
			"Control Swithc CC Agent running time",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::SwitchCC_Persistence),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("SwitchCC_EN",
			"Open Ingress and Enngress Function",
			UintegerValue(0),
			MakeUintegerAccessor(&SwitchNode::Switch_EN),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("WRCC_T",
			"Max T of the WRCC Stat",
			UintegerValue(5000),
			MakeUintegerAccessor(&SwitchNode::WRCC_T),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("WRCC_Alpha",
			"WRCC wc_alpha",
			DoubleValue(0.01),
			MakeDoubleAccessor(&SwitchNode::wc_alpha),
			MakeDoubleChecker<double>())
	.AddAttribute("WRCC_Beta",
			"WRCC wc_beta",
			DoubleValue(1.1),
			MakeDoubleAccessor(&SwitchNode::wc_beta),
			MakeDoubleChecker<double>())
	.AddAttribute("WRCC_RTTgain",
			"RTT Static gain for Port RTT Static",
			DoubleValue(0.02),
			MakeDoubleAccessor(&SwitchNode::dgain),
			MakeDoubleChecker<double>())
	.AddAttribute("WRCC_AutoParmEn",
			"WRCC_AutoParmEn",
			UintegerValue(1),
			MakeUintegerAccessor(&SwitchNode::AutoParmEn),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("minRate",
			"Switch Flow m_minRate",
			UintegerValue(100),
			MakeUintegerAccessor(&SwitchNode::m_minRate),
			MakeUintegerChecker<uint32_t>())
	.AddAttribute("maxRate",
			"Switch Flow m_maxRate",
			UintegerValue(100000),
			MakeUintegerAccessor(&SwitchNode::m_maxRate),
			MakeUintegerChecker<uint32_t>())
  ;
  return tid;
}

SwitchNode::SwitchNode(){
	m_ecmpSeed = m_id;
	m_node_type = 1;
	m_mmu = CreateObject<SwitchMmu>();
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < pCnt; j++)
			for (uint32_t k = 0; k < qCnt; k++)
				m_bytes[i][j][k] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_txBytes[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_lastPktSize[i] = m_lastPktTs[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_u[i] = 0;

	SwitchCCInit();
}

SwitchNode::SwitchNode(uint32_t domain){
	m_ecmpSeed = m_id;
	m_node_type = 1;
	m_domain_id = domain;//Node.h, domain type
	m_mmu = CreateObject<SwitchMmu>();
	for (uint32_t i = 0; i < pCnt; i++)
		for (uint32_t j = 0; j < pCnt; j++)
			for (uint32_t k = 0; k < qCnt; k++)
				m_bytes[i][j][k] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_txBytes[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_lastPktSize[i] = m_lastPktTs[i] = 0;
	for (uint32_t i = 0; i < pCnt; i++)
		m_u[i] = 0;
	
	SwitchCCInit();
}

int SwitchNode::GetOutDev(Ptr<const Packet> p, CustomHeader &ch){
	// look up entries
	auto entry = m_rtTable.find(ch.dip);

	// no matching entry
	if (entry == m_rtTable.end())
		return -1;

	// entry found
	auto &nexthops = entry->second;

	// pick one next hop based on hash
	union {
		uint8_t u8[4+4+2+2];
		uint32_t u32[3];
	} buf;
	buf.u32[0] = ch.sip;
	buf.u32[1] = ch.dip;
	if (ch.l3Prot == 0x6)
		buf.u32[2] = ch.tcp.sport | ((uint32_t)ch.tcp.dport << 16);
	else if (ch.l3Prot == 0x11)
		buf.u32[2] = ch.udp.sport | ((uint32_t)ch.udp.dport << 16);
	else if (ch.l3Prot == 0xFC || ch.l3Prot == 0xFD)
		buf.u32[2] = ch.ack.sport | ((uint32_t)ch.ack.dport << 16);

	uint32_t idx = EcmpHash(buf.u8, 12, m_ecmpSeed) % nexthops.size();
	return nexthops[idx];
}

void SwitchNode::CheckAndSendPfc(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldPause(inDev, qIndex)){
		device->SendPfc(qIndex, 0);
		m_mmu->SetPause(inDev, qIndex);
		if(m_ccMode == 15){
			//PFC Pause Notify
			PFCTrigerNow(inDev);
		}
	}
}
void SwitchNode::CheckAndSendResume(uint32_t inDev, uint32_t qIndex){
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[inDev]);
	if (m_mmu->CheckShouldResume(inDev, qIndex)){
		device->SendPfc(qIndex, 1);
		m_mmu->SetResume(inDev, qIndex);
	}
}

void SwitchNode::SendToDev(Ptr<Packet>p, CustomHeader &ch){
	int idx = GetOutDev(p, ch);
	if (idx >= 0){
		NS_ASSERT_MSG(m_devices[idx]->IsLinkUp(), "The routing table look up should return link that is up");

		// determine the qIndex
		uint32_t qIndex;
		if (ch.l3Prot == 0xFF || ch.l3Prot == 0xFE || (m_ackHighPrio && (ch.l3Prot == 0xFD || ch.l3Prot == 0xFC))){  //QCN or PFC or NACK, go highest priority
			qIndex = 0;
		}else{
			qIndex = (ch.l3Prot == 0x06 ? 1 : ch.udp.pg); // if TCP, put to queue 1
		}

		// admission control
		FlowIdTag t;
		p->PeekPacketTag(t);
		uint32_t inDev = t.GetFlowId();
		if (qIndex != 0){ //not highest priority
			if (m_mmu->CheckIngressAdmission(inDev, qIndex, p->GetSize()) && m_mmu->CheckEgressAdmission(idx, qIndex, p->GetSize())){			// Admission control
				m_mmu->UpdateIngressAdmission(inDev, qIndex, p->GetSize());

				if(Switch_EN){
					//IngressPipline Handler, highest priority pkt do not save
					//PS : inDev is ingress's Port , idx is engress's Port;
					IngressPipline(inDev,idx,qIndex,p,ch);
				}

				m_mmu->UpdateEgressAdmission(idx, qIndex, p->GetSize());
			}else{
				return; // Drop
			}
			CheckAndSendPfc(inDev, qIndex);
		}
		m_bytes[inDev][idx][qIndex] += p->GetSize();
		m_devices[idx]->SwitchSend(qIndex, p, ch);
	}else
		return; // Drop
}

uint32_t SwitchNode::EcmpHash(const uint8_t* key, size_t len, uint32_t seed) {
  uint32_t h = seed;
  if (len > 3) {
    const uint32_t* key_x4 = (const uint32_t*) key;
    size_t i = len >> 2;
    do {
      uint32_t k = *key_x4++;
      k *= 0xcc9e2d51;
      k = (k << 15) | (k >> 17);
      k *= 0x1b873593;
      h ^= k;
      h = (h << 13) | (h >> 19);
      h += (h << 2) + 0xe6546b64;
    } while (--i);
    key = (const uint8_t*) key_x4;
  }
  if (len & 3) {
    size_t i = len & 3;
    uint32_t k = 0;
    key = &key[i - 1];
    do {
      k <<= 8;
      k |= *key--;
    } while (--i);
    k *= 0xcc9e2d51;
    k = (k << 15) | (k >> 17);
    k *= 0x1b873593;
    h ^= k;
  }
  h ^= len;
  h ^= h >> 16;
  h *= 0x85ebca6b;
  h ^= h >> 13;
  h *= 0xc2b2ae35;
  h ^= h >> 16;
  return h;
}

void SwitchNode::SetEcmpSeed(uint32_t seed){
	m_ecmpSeed = seed;
}

void SwitchNode::AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx){
	uint32_t dip = dstAddr.Get();
	m_rtTable[dip].push_back(intf_idx);
}

void SwitchNode::ClearTable(){
	m_rtTable.clear();
}

// This function can only be called in switch mode
bool SwitchNode::SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch){
	SendToDev(packet, ch);
	return true;
}

void SwitchNode::SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p){
	FlowIdTag t;
	p->PeekPacketTag(t);
	if (qIndex != 0){
		uint32_t inDev = t.GetFlowId();
		m_mmu->RemoveFromIngressAdmission(inDev, qIndex, p->GetSize());
		m_mmu->RemoveFromEgressAdmission(ifIndex, qIndex, p->GetSize());
		m_bytes[inDev][ifIndex][qIndex] -= p->GetSize();
		if (m_ecnEnabled){
			bool egressCongested = m_mmu->ShouldSendCN(ifIndex, qIndex);
			if (egressCongested){
				PppHeader ppp;
				Ipv4Header h;
				p->RemoveHeader(ppp);
				p->RemoveHeader(h);
				h.SetEcn((Ipv4Header::EcnType)0x03);
				p->AddHeader(h);
				p->AddHeader(ppp);
			}
		}
		//CheckAndSendPfc(inDev, qIndex);
		CheckAndSendResume(inDev, qIndex);
		if(Switch_EN){
			EngressPipline(inDev, ifIndex, qIndex, p);
		}
	}
	if (1){
		uint8_t* buf = p->GetBuffer();
		if (buf[PppHeader::GetStaticSize() + 9] == 0x11){ // udp packet
			IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
			Ptr<QbbNetDevice> dev = DynamicCast<QbbNetDevice>(m_devices[ifIndex]);
			if (m_ccMode == 3){ // HPCC
				ih->PushHop(Simulator::Now().GetTimeStep(), m_txBytes[ifIndex], dev->GetQueue()->GetNBytesTotal(), dev->GetDataRate().GetBitRate());
			}else if (m_ccMode == 10){ // HPCC-PINT
				uint64_t t = Simulator::Now().GetTimeStep();
				uint64_t dt = t - m_lastPktTs[ifIndex];
				if (dt > m_maxRtt)
					dt = m_maxRtt;
				uint64_t B = dev->GetDataRate().GetBitRate() / 8; //Bps
				uint64_t qlen = dev->GetQueue()->GetNBytesTotal();
				double newU;

				/**************************
				 * approximate calc
				 *************************/
				int b = 20, m = 16, l = 20; // see log2apprx's paremeters
				int sft = logres_shift(b,l);
				double fct = 1<<sft; // (multiplication factor corresponding to sft)
				double log_T = log2(m_maxRtt)*fct; // log2(T)*fct
				double log_B = log2(B)*fct; // log2(B)*fct
				double log_1e9 = log2(1e9)*fct; // log2(1e9)*fct
				double qterm = 0;
				double byteTerm = 0;
				double uTerm = 0;
				if ((qlen >> 8) > 0){
					int log_dt = log2apprx(dt, b, m, l); // ~log2(dt)*fct
					int log_qlen = log2apprx(qlen >> 8, b, m, l); // ~log2(qlen / 256)*fct
					qterm = pow(2, (
								log_dt + log_qlen + log_1e9 - log_B - 2*log_T
								)/fct
							) * 256;
					// 2^((log2(dt)*fct+log2(qlen/256)*fct+log2(1e9)*fct-log2(B)*fct-2*log2(T)*fct)/fct)*256 ~= dt*qlen*1e9/(B*T^2)
				}
				if (m_lastPktSize[ifIndex] > 0){
					int byte = m_lastPktSize[ifIndex];
					int log_byte = log2apprx(byte, b, m, l);
					byteTerm = pow(2, (
								log_byte + log_1e9 - log_B - log_T
								)/fct
							);
					// 2^((log2(byte)*fct+log2(1e9)*fct-log2(B)*fct-log2(T)*fct)/fct) ~= byte*1e9 / (B*T)
				}
				if (m_maxRtt > dt && m_u[ifIndex] > 0){
					int log_T_dt = log2apprx(m_maxRtt - dt, b, m, l); // ~log2(T-dt)*fct
					int log_u = log2apprx(int(round(m_u[ifIndex] * 8192)), b, m, l); // ~log2(u*512)*fct
					uTerm = pow(2, (
								log_T_dt + log_u - log_T
								)/fct
							) / 8192;
					// 2^((log2(T-dt)*fct+log2(u*512)*fct-log2(T)*fct)/fct)/512 = (T-dt)*u/T
				}
				newU = qterm+byteTerm+uTerm;

				#if 0
				/**************************
				 * accurate calc
				 *************************/
				double weight_ewma = double(dt) / m_maxRtt;
				double u;
				if (m_lastPktSize[ifIndex] == 0)
					u = 0;
				else{
					double txRate = m_lastPktSize[ifIndex] / double(dt); // B/ns
					u = (qlen / m_maxRtt + txRate) * 1e9 / B;
				}
				newU = m_u[ifIndex] * (1 - weight_ewma) + u * weight_ewma;
				printf(" %lf\n", newU);
				#endif

				/************************
				 * update PINT header
				 ***********************/
				uint16_t power = Pint::encode_u(newU);
				if (power > ih->GetPower())
					ih->SetPower(power);

				m_u[ifIndex] = newU;
			}
		}
	}
	m_txBytes[ifIndex] += p->GetSize();
	m_lastPktSize[ifIndex] = p->GetSize();
	m_lastPktTs[ifIndex] = Simulator::Now().GetTimeStep();
}

int SwitchNode::logres_shift(int b, int l){
	static int data[] = {0,0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5};
	return l - data[b];
}

int SwitchNode::log2apprx(int x, int b, int m, int l){
	int x0 = x;
	int msb = int(log2(x)) + 1;
	if (msb > m){
		x = (x >> (msb - m) << (msb - m));
		#if 0
		x += + (1 << (msb - m - 1));
		#else
		int mask = (1 << (msb-m)) - 1;
		if ((x0 & mask) > (rand() & mask))
			x += 1<<(msb-m);
		#endif
	}
	return int(log2(x) * (1<<logres_shift(b, l)));
}

/*WRCC Switch Function Extend*/
void SwitchNode::SwitchCCInit(){
	if(m_ccMode == 15){
		for (uint32_t i = 0; i < pCnt; i++)
		{
			Eventtick[i] = 0;
			m_InputByte[i] = 0;
			m_OutputRtt[i] = 0;
			m_engressQTh[i] = 0;
			m_lastQ[i] = 0;
			SlowDownMark[i] = 64;
			TransMark[i] = 0;
			m_engresscrossPFC[i] = 0;
		}	
	}
}

void SwitchNode::IngressPipline(uint32_t ingress_port, uint32_t engress_port, uint32_t qIndex, Ptr<Packet> p, CustomHeader &ch){
	/*CC Agent Stat Detection*/
	CCIngressAgent(engress_port,p,ch);
	/*CC FLowTable Update*/
	if(m_ccMode == 15){
		uint32_t rttest = ch.ack.ih.wrcc.RTTest;
		if(rttest > 0 && m_OutputRtt[engress_port] == 0){
			/*Init Value*/
			m_OutputRtt[engress_port] = rttest;
		}else{
			m_OutputRtt[engress_port] = dgain*rttest + (1-dgain)*m_OutputRtt[engress_port];
		}
		/*Switch Peer to Peer Static; Pkt Byte or PktNum*/
		if(IsRDMAPkt(p,ch)){
			UpdatePBSTable(ingress_port,engress_port,p->GetSize());
		}
	}
}

void SwitchNode::EngressPipline(uint32_t ingress_port,uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p){
	CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header | CustomHeader::L4_Header);
	ch.getInt = 1; // parse INT header
	p->PeekHeader(ch);//Deserialize but does _not_ remove the header

	/*CC Agent Stat Detection*/
	CCEngressAgent(ifIndex,p,ch);

	if(m_ccMode == 15){
		//Switch Info
		int64_t now = Simulator::Now().GetTimeStep();
		uint32_t localdomain = m_domain_id;
		uint32_t localFrate = m_currentRate[ifIndex];

		//Flow Info
		FlowID flowId = getFlowID(p,ch);
		std::string flowId_key = FlowIDtoKey(flowId);

		//Pkt Info
		uint32_t pkt_rate = ch.udp.ih.wrcc.Fairate;
		uint16_t pkt_domain = ch.udp.ih.wrcc.domainid;
		uint16_t pkt_first = ch.udp.ih.wrcc.firstbdp;

		if(pkt_first < 1000){
		// > 1000 Reserved Command Field ; pkt_first Must be in [0,999]
		if(pkt_domain == localdomain){
			if(localFrate < pkt_rate){
				if(pkt_first > 0){
					ModifyWRCCINTR(p,localFrate,2);
					auto ite = WRCCHashTable[ifIndex].find(flowId_key);
					if(ite == WRCCHashTable[ifIndex].end()){
						WRCCHashTable[ifIndex][flowId_key] = now;
						SendWRCCRatePkt(ifIndex,p);
					}else{
						int64_t lastInterval = now - WRCCHashTable[ifIndex][flowId_key];
						if(lastInterval >= WRCC_T){
							WRCCHashTable[ifIndex][flowId_key] = now;
							SendWRCCRatePkt(ifIndex,p);
						}
					}
				}else{
					// ModifyWRCCINT(p,localFrate);
					ModifyWRCCINTR(p,localFrate,2);
				}
			}
		}else{
			if(localFrate < pkt_rate){
				ModifyWRCCINTR(p,localFrate,2);
			}
		}
	}
	}
}

void SwitchNode::CCIngressAgent(uint32_t engress_port, Ptr<Packet> p, CustomHeader &ch){
	// NS_LOG_FUNCTION(this);
	if(m_ccMode == 15){
		m_InputByte[engress_port] += p->GetSize();
	}
}

void SwitchNode::CCEngressAgent(uint32_t port, Ptr<Packet> p, CustomHeader &ch){
	// NS_LOG_FUNCTION(this);
}

//FlowTable Function
SwitchNode::FlowID SwitchNode::getFlowID(Ptr<const Packet>, CustomHeader &ch){
	FlowID targetflow(ch.sip,ch.dip,ch.udp.sport,ch.udp.dport,ch.udp.pg);
	return targetflow;
}

SwitchNode::FlowID SwitchNode::KeytoFlowID(std::string key){
	// NS_LOG_FUNCTION(this);
    std::vector<uint32_t> integers;  
    size_t pos = 0;  
    std::string token;  
    while ((pos = key.find("|")) != std::string::npos) {  
        token = key.substr(0, pos);  
        integers.push_back(std::stoul(token));  
        key = key.substr(pos + 1);
    }
	NS_ASSERT_MSG(integers.size() == 5, "Switch Node Flow ID's Length Error,Error key:");
	FlowID flowId(integers[0],integers[1],integers[2],integers[3],integers[4]);
	return flowId;
}

std::string SwitchNode::FlowIDtoKey(FlowID flowId){
	// NS_LOG_FUNCTION(this);
	return std::to_string(flowId.sip)+"|"+ std::to_string(flowId.dip)+"|"+ std::to_string(flowId.sport)+"|"+ std::to_string(flowId.dport)+"|"+std::to_string(flowId.pg)+"|";
}
bool SwitchNode::IsRDMAPkt(Ptr<const Packet>, CustomHeader &ch){
	// FlowID targetflow(ch.sip,ch.dip,ch.udp.sport,ch.udp.dport,ch.udp.pg);
	if(ch.udp.dport >= 100 && ch.udp.pg == 3)
		return true;
	else
		return false;
}
bool SwitchNode::IsRDMAPkt(FlowID flowId){
	//queue 3 and dport is 100 , pkt is rdma's pkt
	if(flowId.dport >= 100 && flowId.pg == 3)
		return true;
	else
		return false;
}

//Peer to Peer Stat Table Function
uint32_t SwitchNode::ReadPBSTable(uint32_t ingressport,uint32_t egressport){
	if(pairByteStat.find(egressport) != pairByteStat.end())
	{
		if(pairByteStat[egressport].find(ingressport) != pairByteStat[egressport].end()){
			return pairByteStat[egressport][ingressport];
		}
	}
	return 0;
}
void SwitchNode::UpdatePBSTable(uint32_t ingressport,uint32_t egressport,uint32_t psize){
	uint32_t tempByte = ReadPBSTable(ingressport,egressport);
	if(tempByte){
		pairByteStat[egressport][ingressport] = tempByte + psize;
	}
	else{
		pairByteStat[egressport][ingressport] = psize;
	}
	InsertPFCTrItem(ingressport,egressport);
}
void SwitchNode::DelPBSTable(uint32_t ingressport,uint32_t egressport){
	if(ReadPBSTable(ingressport,egressport)){
		pairByteStat[egressport][ingressport] = 0;
	}
}
bool SwitchNode::JudgeEngressPort(uint32_t egressport){
	if(pairByteStat.find(egressport) != pairByteStat.end()){
		if(!pairByteStat[egressport].empty()){
			for (auto ite = pairByteStat[egressport].begin(); ite != pairByteStat[egressport].end(); ite++){
				if(ite->second > 0){
					return true;
				}
			}
		}
	}
	return false;
}
//IngressPort PFC Triger Lookup
void SwitchNode::InsertPFCTrItem(uint32_t ingressport,uint32_t egressport){
	if(PFCTriger.find(ingressport) == PFCTriger.end() || PFCTriger[ingressport].find(egressport) == PFCTriger[ingressport].end()){
			PFCTriger[ingressport][egressport] = 0;
	}
}
void SwitchNode::PFCTrigerNow(uint32_t ingressport){
	NS_ASSERT_MSG(PFCTriger.find(ingressport) != PFCTriger.end(),"PFCTriger Static Error");
	for (auto& inner_pair : PFCTriger[ingressport]){
		inner_pair.second += 1;
	}
}
double SwitchNode::ReadEmptyPFCTriger(uint32_t egressport){
	std::vector<uint32_t> values;
	for (auto& outer_pair : PFCTriger){
		for (auto& pair : outer_pair.second){
			if (pair.first == egressport){
				if(pair.second != 0){
					values.push_back(pair.second);
					pair.second = 0;
				}
			}
		}
	}
	if (values.empty())
		return 0.0;
	double sum = std::accumulate(values.begin(), values.end(), 0.0);
	double average = sum / values.size();
	return average;
}

/*WRCC Switch Control Pkt Send*/
void SwitchNode::ModifyWRCCINT(Ptr<Packet>p,uint32_t fairate){
	// NS_LOG_FUNCTION(this);
	uint8_t* buf = p->GetBuffer();
	if (buf[PppHeader::GetStaticSize() + 9] == 0x11){
		IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
		ih->wrcc.Fairate = fairate;
	}
}
void SwitchNode::ModifyWRCCINTR(Ptr<Packet>p,uint32_t fairate,uint32_t n_fdp){
	// NS_LOG_FUNCTION(this);
	uint8_t* buf = p->GetBuffer();
	if (buf[PppHeader::GetStaticSize() + 9] == 0x11){
		IntHeader *ih = (IntHeader*)&buf[PppHeader::GetStaticSize() + 20 + 8 + 6]; // ppp, ip, udp, SeqTs, INT
		ih->wrcc.Fairate = fairate;
		ih->wrcc.firstbdp = n_fdp;
	}
}
void SwitchNode::SendWRCCRatePkt(uint32_t port, Ptr<Packet> trip){
	//FCNP PSN = 0, to do: PSN = trip.psn and head.SetProtocol(0xFB);
	// NS_LOG_FUNCTION(this);

	CustomHeader och(CustomHeader::L2_Header | CustomHeader::L3_Header | CustomHeader::L4_Header);
	och.getInt = 1; // parse INT header
	trip->PeekHeader(och);//Deserialize but does _not_ remove the header

	IntHeader ih;
	ih.wrcc.Fairate = och.udp.ih.wrcc.Fairate;
	/*Ensure that Switch do not Modify the ACK INT;1001 is FCNP; 1000 is ACK/NAK*/
	ih.wrcc.firstbdp = 1001;
	ih.wrcc.domainid = this->m_domain_id;

	qbbHeader seqh;
	// seqh.SetSeq(0);
	seqh.SetSeq(och.udp.seq);/*Ensure the Sender Know the Last Seq*/
	seqh.SetPG(och.udp.pg);
	seqh.SetSport(och.udp.dport);
	seqh.SetDport(och.udp.sport);
	seqh.SetIntHeader(ih);
	seqh.SetCnp();

	//Generate FCNP
	Ptr<Packet> newp = Create<Packet>(std::max(60-14-20-(int)seqh.GetSerializedSize(), 0));
	newp->AddHeader(seqh);

	Ipv4Header head;
	head.SetDestination(Ipv4Address(och.sip));
	head.SetSource(Ipv4Address(och.dip));
	head.SetProtocol(0xFC);
	head.SetTtl(64);
	head.SetPayloadSize(newp->GetSize());
	head.SetIdentification(UniformVariable(0, 65536).GetValue());
	newp->AddHeader(head);

	PppHeader ppp;
	ppp.SetProtocol (0x0021);//Ipv4
	newp->AddHeader(ppp);

	CustomHeader ch(CustomHeader::L2_Header | CustomHeader::L3_Header | CustomHeader::L4_Header);
	ch.getInt = 1;
	newp->PeekHeader(ch);
	newp->AddPacketTag(FlowIdTag(port));

	int idx = GetOutDev(newp, ch);
	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[idx]);
	device->SwitchSend(0,newp,ch);
}


/*********************
 * WRCC Switch Function
 ********************/
void SwitchNode:: StartClockEvent(double starttime){
	for (uint32_t i = 0; i < pCnt; i++){
		if(Eventtick[i] > 0){
			if(m_ccMode == 15){
				m_WRCCtrlTimer[i] = Simulator::Schedule(Seconds(starttime)+NanoSeconds(WRCC_T), &SwitchNode::HandleWRCClock, this, i);
				m_currentRate[i] = m_maxRate;
				//Static Cycle too small
				ActStatic[i] = UINT32_MAX;
			}
		}
	}
}

void SwitchNode::SetSWCCTick(uint32_t port){
	Eventtick[port] = 1;
}

void SwitchNode::ScheduleWRCClockEvent(uint32_t port){
	m_WRCCtrlTimer[port] = Simulator::Schedule(NanoSeconds(WRCC_T), &SwitchNode::HandleWRCClock, this, port);
}

void SwitchNode::HandleWRCClock(uint32_t port){
	NS_LOG_FUNCTION(this);

	uint32_t currentRate = 0,queueSize = 0,MaxDyQueue = 0;

	//WRCC Engress QueueSize and Max PFC Queue Size
	for(int i = 0; i < qCnt; i++){
		queueSize += m_mmu->egress_bytes[port][i];
	}

	if(m_InputByte[port] > 0){
		//PFC Static 
		DyEngressQthUpdate(port);
		MaxDyQueue = m_engressQTh[port];
		//FaitRate Calculate
		m_currentRate[port] = RecalculateWRCCFairRate2(port,queueSize,MaxDyQueue);
		m_InputByte[port] = 0;
		ActStatic[port] = 1;
		//
		// m_OutputRtt[port] = 0; //set 0 and 
	}else{
		if(ActStatic[port] < UINT32_MAX)
			ActStatic[port] ++;
	}
	//Next Schedule
	ScheduleWRCClockEvent(port);
}

int SwitchNode::RecalculateWRCCFairRate2(uint32_t port, uint32_t queuesize, uint32_t MaxQueue){
	NS_LOG_FUNCTION(this<<this->GetId());
	int fairRate = 0;
	int fMin = m_minRate;//m_minRate,100 Mbps
	int fMax = m_maxRate;//m_maxRate,100000 Mbps for single Flow
	double rttoffset;
	int currentRate,inputRate,queuerate,avgrtt,defaultrtt,actrtt;
	int RateEst = 1,RateOff = -1;

	Ptr<QbbNetDevice> device = DynamicCast<QbbNetDevice>(m_devices[port]);
	int MaxBandwidth = device->GetDataRate().GetBitRate()/1000000;

	int actstatic = WRCC_T;
	if(UINT32_MAX > ActStatic[port]){
		//Normal Static
		actstatic = WRCC_T*ActStatic[port];
	}
	defaultrtt = WRCC_T; /*ns*/
	if(m_OutputRtt[port] == 0){
		avgrtt = (defaultrtt/1000);
	}else{
		avgrtt = m_OutputRtt[port];//Port AvgRTT, us;
	}
	actrtt = std::max(defaultrtt,avgrtt*1000); //ns,RTT

	currentRate = m_currentRate[port];//Mbps, FairRate of last Period
	inputRate = m_InputByte[port] * 8 / (actstatic / 1000); //Mbps, SendRate of Current Rece Rate

	uint32_t QueueOff = queuesize > MaxQueue*0.5? queuesize-MaxQueue*0.5 : 0;
	int TargetB = MaxBandwidth;

	queuerate = QueueOff * 8 /avgrtt; //Mbps, Queue Consume Rate
	rttoffset = (double)defaultrtt/actrtt; /*RTT Offset > 1*/

	//Static Parm
	double tempalpha = 0.1;
	double a = tempalpha, b = tempalpha*tempalpha*1.4142;

	double target = 1;
	if(inputRate >= MaxBandwidth){
		target = (double)inputRate/(double)MaxBandwidth;
	}

	//PFC Trigger Num
	double PFCTrigN = m_engresscrossPFC[port];
	bool extreme_congestion = PFCTrigN > 0 ? true : false;
	if(extreme_congestion){
		target = std::max(2.0,target);
	}

	double tarbandwidth = wc_alpha;

	if(target >= tarbandwidth){
		fairRate = currentRate / target;
	}
	else{
		AutoTurnParm2(port, a , b , inputRate);
		RateOff = a*(TargetB - inputRate) - b*queuerate; //Mbps, Int
		fairRate = RateAdjustLimit(currentRate,rttoffset*RateOff/m_maxRate);
	}
	/*Rate Limiter*/
	if (fairRate < fMin)
		fairRate = fMin;
	if (fMax < fairRate)
		fairRate = fMax;
	return fairRate;
}


void SwitchNode::DyEngressQthUpdate(uint32_t egress_port){
	uint32_t QueueTh = 0,ingressport = 0, ingressportByte = 0, inputrate = 0, PFCNum = 0;
	if(JudgeEngressPort(egress_port)){
		for (auto ite = pairByteStat[egress_port].begin(); ite != pairByteStat[egress_port].end(); ite++){
			ingressport = ite->first;
			ingressportByte = ite->second;
			NS_ASSERT_MSG(ingressport>0&&ingressport <= pCnt ,"WRCCTh Error Port ID "<<ingressport);
			/*Test*/
			if(ingressportByte > 0){
				QueueTh += m_mmu->GetPfcThreshold(ingressport);
			}
			DelPBSTable(ingressport,egress_port);
		}
	}
	if(QueueTh == 0){
		QueueTh = m_mmu->GetPfcThreshold(egress_port);
	}
	m_engressQTh[egress_port] = QueueTh;
	m_engresscrossPFC[egress_port] = ReadEmptyPFCTriger(egress_port);
}

void SwitchNode::AutoTurnParm(uint32_t port, double& a , double& b, uint32_t queuesize){
	if(TransMark[port]){
		if(queuesize > m_lastQ[port])
			SlowDownMark[port] = SlowDownMark[port]*2;
		else
			SlowDownMark[port] = SlowDownMark[port]/2;
	}else{
		if(queuesize > m_lastQ[port]){
			SlowDownMark[port] = SlowDownMark[port]/2;
		}
	}
	/*Parm Calculate*/
	if(SlowDownMark[port] < 2)
		SlowDownMark[port] = 2;
	else if (SlowDownMark[port] > 64)
		SlowDownMark[port] = 64;
	
	a = (double)1/SlowDownMark[port];
	b = a * a * 1.41421;
}

void SwitchNode::AutoTurnParm2(uint32_t port, double& a , double& b, int inputrate){
	if(inputrate >= m_maxRate){
		SlowDownMark[port] = 2;
	}else{
		uint32_t level = 2;
		uint32_t maxrate = m_maxRate;
		uint32_t interval = maxrate - inputrate;
		while(interval < maxrate/level && level < 64){
			level *=2;
		}
		SlowDownMark[port] = level;
	}
	a = (double)1/SlowDownMark[port];
	b = 0.5 * a;
}

int SwitchNode::RateAdjustLimit(int currentRate,double amplitude){
	double readyrate = (double)currentRate*(1+amplitude);
	double interval = readyrate - currentRate;
	if(interval > 0 && interval < 1){
		return currentRate + 1;
	}
	if(interval < 0 && interval > -1){
		return currentRate - 1;
	}
	return (int)readyrate;
}

int SwitchNode::RateAdjustLimit2(int currentRate,double amplitude,double rttoff){
	double readyrate = (double)currentRate*(1+amplitude)*rttoff;
	double interval = readyrate - currentRate;
	if(interval > 0 && interval < 1){
		return currentRate + 1;
	}
	if(interval < 0 && interval > -1){
		return currentRate - 1;
	}
	return (int)readyrate;
}



} /* namespace ns3 */
