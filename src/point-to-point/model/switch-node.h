#ifndef SWITCH_NODE_H
#define SWITCH_NODE_H

#include <unordered_map>
#include <ns3/node.h>
#include "qbb-net-device.h"
#include "switch-mmu.h"
#include "pint.h"

namespace ns3 {

class Packet;

class SwitchNode : public Node{
	static const uint32_t pCnt = 257;	// Number of ports used
	static const uint32_t qCnt = 8;	// Number of queues/priorities used
	uint32_t m_ecmpSeed;
	std::unordered_map<uint32_t, std::vector<int> > m_rtTable; // map from ip address (u32) to possible ECMP port (index of dev)

	// monitor of PFC
	uint32_t m_bytes[pCnt][pCnt][qCnt]; // m_bytes[inDev][outDev][qidx] is the bytes from inDev enqueued for outDev at qidx
	
	uint64_t m_txBytes[pCnt]; // counter of tx bytes

	uint32_t m_lastPktSize[pCnt];
	uint64_t m_lastPktTs[pCnt]; // ns
	double m_u[pCnt];

protected:
	bool m_ecnEnabled;
	uint32_t m_ccMode;
	uint64_t m_maxRtt;

	uint32_t m_ackHighPrio; // set high priority for ACK/NACK

private:
	int GetOutDev(Ptr<const Packet>, CustomHeader &ch);
	void SendToDev(Ptr<Packet>p, CustomHeader &ch);
	static uint32_t EcmpHash(const uint8_t* key, size_t len, uint32_t seed);
	void CheckAndSendPfc(uint32_t inDev, uint32_t qIndex);
	void CheckAndSendResume(uint32_t inDev, uint32_t qIndex);
public:
	Ptr<SwitchMmu> m_mmu;

	static TypeId GetTypeId (void);
	SwitchNode();
	void SetEcmpSeed(uint32_t seed);
	void AddTableEntry(Ipv4Address &dstAddr, uint32_t intf_idx);
	void ClearTable();
	bool SwitchReceiveFromDevice(Ptr<NetDevice> device, Ptr<Packet> packet, CustomHeader &ch);
	void SwitchNotifyDequeue(uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p);

	// for approximate calc in PINT
	int logres_shift(int b, int l);
	int log2apprx(int x, int b, int m, int l); // given x of at most b bits, use most significant m bits of x, calc the result in l bits

	/*IngressPipline && EngressPipline*/
	uint32_t SwitchCC_Persistence;
	uint32_t Switch_EN;

	SwitchNode(uint32_t domain);

	void SwitchCCInit();

	void IngressPipline(uint32_t ingress_port,uint32_t engress_port, uint32_t qIndex, Ptr<Packet> p, CustomHeader &ch);
	void EngressPipline(uint32_t ingress_port,uint32_t ifIndex, uint32_t qIndex, Ptr<Packet> p);
	void CCIngressAgent(uint32_t port, Ptr<Packet> p, CustomHeader &ch);
	void CCEngressAgent(uint32_t port, Ptr<Packet> p, CustomHeader &ch);

	/*Switch Flow Table*/
	//FLowTable Struct
	struct FlowID{
		uint32_t sip; //!< source address
		uint32_t dip; //!< destination address
		uint16_t sport;        //!< Source port
		uint16_t dport;   //!< Destination port
		uint16_t pg; //PFC Queue
		FlowID(uint32_t sip,uint32_t dip,uint16_t sport,uint16_t dport,uint16_t pg) : sip(sip),dip(dip),sport(sport),dport(dport),pg(pg) {}
		bool operator==(const FlowID& other) const {
			return sip == other.sip && dip == other.dip && sport == other.sport && dport == other.dport && pg == other.pg;  
		}
		void show(){
			printf("%lu sip:%u dip:%u sport:%u dport:%u pg:%u \n",Simulator::Now().GetTimeStep(),sip,dip,sport,dport,pg);
		}
	};
	
	//FlowTable Function
	FlowID getFlowID(Ptr<const Packet>, CustomHeader &ch);
	FlowID KeytoFlowID(std::string key);
	std::string FlowIDtoKey(FlowID flowId);

	bool IsRDMAPkt(FlowID flowId);
	bool IsRDMAPkt(Ptr<const Packet>, CustomHeader &ch);

	/*********************
	 * WRCC, CC_Mode 15, Switch
	 ********************/
	uint32_t m_minRate;//Mbps
	uint32_t m_maxRate;//maxRate is Server's NIC Max Bandwidth

	std::unordered_map<std::string,int64_t> WRCCHashTable[pCnt];

	uint32_t WRCC_T;// ns
	double wc_alpha, wc_beta, dgain;
	uint32_t AutoParmEn;

	//WRCC Pkt Static
	uint32_t m_currentRate[pCnt];
	uint32_t m_InputByte[pCnt]; //Per-Port Input Bytes
	uint32_t m_OutputRtt[pCnt]; //Per-Port RTT
	uint32_t m_engressQTh[pCnt];
	uint32_t m_lastQ[pCnt];
	uint32_t SlowDownMark[pCnt],TransMark[pCnt];
	std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t> > pairByteStat;
	//WRCC InputRate 0
	uint32_t ActStatic[pCnt];

	//Peer to Peer Stat Table Function
	uint32_t ReadPBSTable(uint32_t ingressport,uint32_t egressport);
	void UpdatePBSTable(uint32_t ingressport,uint32_t egressport,uint32_t psize);
	void DelPBSTable(uint32_t ingressport,uint32_t egressport);
	bool JudgeEngressPort(uint32_t egressport);

	//IngressPort PFC Triger Lookup
	double m_engresscrossPFC[pCnt];
	std::unordered_map<uint32_t, std::unordered_map<uint32_t, uint32_t> > PFCTriger;
	void InsertPFCTrItem(uint32_t ingressport,uint32_t egressport);
	void PFCTrigerNow(uint32_t ingressport);
	double ReadEmptyPFCTriger(uint32_t egressport);

	/*WRCC Switch Control Pkt*/
	void ModifyWRCCINT(Ptr<Packet>p,uint32_t fairate);
	void ModifyWRCCINTR(Ptr<Packet>p,uint32_t fairate,uint32_t n_fdp);
	void SendWRCCRatePkt(uint32_t port, Ptr<Packet> trip);

	//FairRate Calculate
	int Eventtick[pCnt];
	EventId m_WRCCtrlTimer[pCnt]; // Port FairRate Calculate Hander
	void SetSWCCTick(uint32_t port);
	void StartClockEvent(double starttime);
	void ScheduleWRCClockEvent(uint32_t port);
	void HandleWRCClock(uint32_t port);
	int RecalculateWRCCFairRate2(uint32_t port, uint32_t queuesize, uint32_t MaxQueue);
	void DyEngressQthUpdate(uint32_t port);
	void AutoTurnParm(uint32_t port, double& a , double& b, uint32_t queuesize);
	void AutoTurnParm2(uint32_t port, double& a , double& b, int inputrate);

	int RateAdjustLimit(int currentRate,double amplitude);
	int RateAdjustLimit2(int currentRate,double amplitude,double rttoff);

};

} /* namespace ns3 */

#endif /* SWITCH_NODE_H */
