// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mixed_plen_decap_gribi_entries_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/open-traffic-generator/snappi/gosnappi"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/featureprofiles/internal/gribi"
	"github.com/openconfig/gribigo/chk"
	"github.com/openconfig/gribigo/constants"
	"github.com/openconfig/gribigo/fluent"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/otg"
	"github.com/openconfig/ygot/ygot"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// Settings for configuring the baseline testbed with the test
// topology.
//
// The testbed consists of ate:port1 -> dut:port1,
// dut:port2 -> ate:port2.
//
//   * ate:port1 -> dut:port1 subnet 192.0.2.1/30
//   * ate:port2 -> dut:port2 subnet 192.0.2.5/30

const (
	plenIPv4            = 30
	plenIPv6            = 126
	dscpEncapA1         = 10
	dscpEncapA2         = 18
	dscpEncapB1         = 20
	dscpEncapB2         = 28
	dscpEncapNoMatch    = 30
	ipv4OuterSrc111Addr = "198.51.100.111/32"
	ipv4OuterSrc222Addr = "198.51.100.222/32"
	ipv4OuterDst1       = "192.51.100.64"
	ipv4OuterDst2       = "192.55.200.3"
	ipv4OuterDst3       = "192.51.128.5"
	ipv4OuterSrc1       = "198.51.100.111"
	ipv4OuterDst4       = "192.58.200.7"
	prot4               = 4
	prot41              = 41
	polName             = "pol1"
	nhIndex             = 1
	nhgIndex            = 1
	gribiIPv4entry1     = "192.51.100.1/24"
	gribiIPv4entry2     = "192.55.200.3/32"
	gribiIPv4entry3     = "192.51.129.0/22"
	niDecapTeVrf        = "DECAP_TE_VRF"
	tolerancePct        = 2
	tolerance           = 50
	flow1               = "flow1-ip-in-ip"
	flow2               = "flow2-ip-in-ip"
	flow3               = "flow3-ip-in-ip"
	flow4               = "flow4-ipv6-in-ip"
	flow5               = "flow5-ipv6-in-ip"
	flow6               = "flow6-ipv6-in-ip"
	flow7               = "flow7-neg-ip-in-ip"
	wantLoss            = true
	v4Flow              = true
	decapPacket         = true
)

var (
	dutPort1 = attrs.Attributes{
		Desc:    "dutPort1",
		IPv4:    "192.0.2.1",
		IPv6:    "2001:db8::192:0:2:1",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}
	atePort1 = attrs.Attributes{
		Name:    "atePort1",
		IPv4:    "192.0.2.2",
		MAC:     "02:00:01:01:01:01",
		IPv6:    "2001:db8::192:0:2:2",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}
	dutPort2 = attrs.Attributes{
		Desc:    "dutPort2",
		IPv4:    "192.0.2.5",
		IPv6:    "2001:db8::192:0:2:5",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}
	atePort2 = attrs.Attributes{
		Name:    "atePort2",
		IPv4:    "192.0.2.6",
		MAC:     "02:00:02:01:01:01",
		IPv6:    "2001:db8::192:0:2:6",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}
)

// awaitTimeout calls a fluent client Await, adding a timeout to the context.
func awaitTimeout(ctx context.Context, t testing.TB, c *fluent.GRIBIClient, timeout time.Duration) error {
	t.Helper()
	subctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return c.Await(subctx, t)
}

type testArgs struct {
	ctx        context.Context
	client     *fluent.GRIBIClient
	dut        *ondatra.DUTDevice
	ate        *ondatra.ATEDevice
	otgConfig  gosnappi.Config
	top        gosnappi.Config
	electionID gribi.Uint128
	otg        *otg.OTG
}

type policyFwRule struct {
	SeqId           uint32
	protocol        oc.UnionUint8
	dscpSet         []uint8
	sourceAddr      string
	decapNi         string
	postDecapNi     string
	decapFallbackNi string
}

func configureVrfSelectionPolicy(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	d := &oc.Root{}
	dutPolFwdPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).PolicyForwarding()

	pfRule1 := &policyFwRule{SeqId: 1, protocol: 4, dscpSet: []uint8{dscpEncapA1, dscpEncapA2}, sourceAddr: ipv4OuterSrc222Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "ENCAP_TE_VRF_A", decapFallbackNi: "TE_VRF_222"}
	pfRule2 := &policyFwRule{SeqId: 2, protocol: 41, dscpSet: []uint8{dscpEncapA1, dscpEncapA2}, sourceAddr: ipv4OuterSrc222Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "ENCAP_TE_VRF_A", decapFallbackNi: "TE_VRF_222"}
	pfRule3 := &policyFwRule{SeqId: 3, protocol: 4, dscpSet: []uint8{dscpEncapA1, dscpEncapA2}, sourceAddr: ipv4OuterSrc111Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "ENCAP_TE_VRF_A", decapFallbackNi: "TE_VRF_111"}
	pfRule4 := &policyFwRule{SeqId: 4, protocol: 41, dscpSet: []uint8{dscpEncapA1, dscpEncapA2}, sourceAddr: ipv4OuterSrc111Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "ENCAP_TE_VRF_A", decapFallbackNi: "TE_VRF_111"}

	pfRule5 := &policyFwRule{SeqId: 5, protocol: 4, dscpSet: []uint8{dscpEncapB1, dscpEncapB2}, sourceAddr: ipv4OuterSrc222Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "ENCAP_TE_VRF_B", decapFallbackNi: "TE_VRF_222"}
	pfRule6 := &policyFwRule{SeqId: 6, protocol: 41, dscpSet: []uint8{dscpEncapB1, dscpEncapB2}, sourceAddr: ipv4OuterSrc222Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "ENCAP_TE_VRF_B", decapFallbackNi: "TE_VRF_222"}
	pfRule7 := &policyFwRule{SeqId: 7, protocol: 4, dscpSet: []uint8{dscpEncapB1, dscpEncapB2}, sourceAddr: ipv4OuterSrc111Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "ENCAP_TE_VRF_B", decapFallbackNi: "TE_VRF_111"}
	pfRule8 := &policyFwRule{SeqId: 8, protocol: 41, dscpSet: []uint8{dscpEncapB1, dscpEncapB2}, sourceAddr: ipv4OuterSrc111Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "ENCAP_TE_VRF_B", decapFallbackNi: "TE_VRF_111"}

	pfRule9 := &policyFwRule{SeqId: 9, protocol: 4, sourceAddr: ipv4OuterSrc222Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "DEFAULT", decapFallbackNi: "TE_VRF_222"}
	pfRule10 := &policyFwRule{SeqId: 10, protocol: 41, sourceAddr: ipv4OuterSrc222Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "DEFAULT", decapFallbackNi: "TE_VRF_222"}
	pfRule11 := &policyFwRule{SeqId: 11, protocol: 4, sourceAddr: ipv4OuterSrc111Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "DEFAULT", decapFallbackNi: "TE_VRF_111"}
	pfRule12 := &policyFwRule{SeqId: 12, protocol: 41, sourceAddr: ipv4OuterSrc111Addr,
		decapNi: "DECAP_TE_VRF", postDecapNi: "DEFAULT", decapFallbackNi: "TE_VRF_111"}

	pfRuleList := []*policyFwRule{pfRule1, pfRule2, pfRule3, pfRule4, pfRule5, pfRule6,
		pfRule7, pfRule8, pfRule9, pfRule10, pfRule11, pfRule12}

	ni := d.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	niP := ni.GetOrCreatePolicyForwarding()
	niPf := niP.GetOrCreatePolicy(polName)
	niPf.SetType(oc.Policy_Type_VRF_SELECTION_POLICY)

	for _, pfRule := range pfRuleList {
		pfR := niPf.GetOrCreateRule(pfRule.SeqId)
		pfRProtoIPv4 := pfR.GetOrCreateIpv4()
		pfRProtoIPv4.Protocol = oc.UnionUint8(pfRule.protocol)
		if pfRule.dscpSet != nil {
			pfRProtoIPv4.DscpSet = pfRule.dscpSet
		}
		pfRProtoIPv4.SourceAddress = ygot.String(pfRule.sourceAddr)
		pfRAction := pfR.GetOrCreateAction()
		pfRAction.DecapNetworkInstance = ygot.String(pfRule.decapNi)
		pfRAction.PostDecapNetworkInstance = ygot.String(pfRule.postDecapNi)
		pfRAction.DecapFallbackNetworkInstance = ygot.String(pfRule.decapFallbackNi)
	}
	pfR := niPf.GetOrCreateRule(13)
	pfRAction := pfR.GetOrCreateAction()
	pfRAction.NetworkInstance = ygot.String("DEFAULT")

	p1 := dut.Port(t, "port1")
	intf := niP.GetOrCreateInterface(p1.Name())
	intf.ApplyVrfSelectionPolicy = ygot.String(polName)
	intf.GetOrCreateInterfaceRef().Interface = ygot.String(p1.Name())
	intf.GetOrCreateInterfaceRef().Subinterface = ygot.Uint32(0)
	if deviations.InterfaceRefConfigUnsupported(dut) {
		intf.InterfaceRef = nil
	}
	gnmi.Replace(t, dut, dutPolFwdPath.Config(), niP)
}

// configureNetworkInstance configures vrfs DECAP_TE_VRF,ENCAP_TE_VRF_A,ENCAP_TE_VRF_B,
// TE_VRF_222, TE_VRF_111.
func configNonDefaultNetworkInstance(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	c := &oc.Root{}
	vrfs := []string{"DECAP_TE_VRF", "ENCAP_TE_VRF_A", "ENCAP_TE_VRF_B", "TE_VRF_222", "TE_VRF_111"}
	for _, vrf := range vrfs {
		ni := c.GetOrCreateNetworkInstance(vrf)
		ni.Type = oc.NetworkInstanceTypes_NETWORK_INSTANCE_TYPE_L3VRF
		gnmi.Replace(t, dut, gnmi.OC().NetworkInstance(vrf).Config(), ni)
	}
}

// configureDUT configures port1-2 on the DUT.
func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	t.Helper()
	d := gnmi.OC()

	p1 := dut.Port(t, "port1")
	p2 := dut.Port(t, "port2")

	gnmi.Replace(t, dut, d.Interface(p1.Name()).Config(), dutPort1.NewOCInterface(p1.Name(), dut))
	gnmi.Replace(t, dut, d.Interface(p2.Name()).Config(), dutPort2.NewOCInterface(p2.Name(), dut))

	if deviations.ExplicitPortSpeed(dut) {
		fptest.SetPortSpeed(t, dut.Port(t, "port1"))
		fptest.SetPortSpeed(t, dut.Port(t, "port2"))
	}
	if deviations.ExplicitInterfaceInDefaultVRF(dut) {
		fptest.AssignToNetworkInstance(t, dut, p1.Name(), deviations.DefaultNetworkInstance(dut), 0)
		fptest.AssignToNetworkInstance(t, dut, p2.Name(), deviations.DefaultNetworkInstance(dut), 0)
	}
}

func configureGribiRoute(ctx context.Context, t *testing.T, dut *ondatra.DUTDevice, args *testArgs) {
	t.Helper()
	// Using gRIBI, install an  IPv4Entry for the prefix 192.51.100.1/24 that points to a
	// NextHopGroup that contains a single NextHop that specifies decapsulating the IPv4
	// header and specifies the DEFAULT network instance.This IPv4Entry should be installed
	// into the DECAP_TE_VRF.

	args.client.Modify().AddEntry(t,
		fluent.NextHopEntry().WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			WithIndex(nhIndex).WithDecapsulateHeader(fluent.IPinIP).
			WithNextHopNetworkInstance(deviations.DefaultNetworkInstance(dut)),
		fluent.NextHopGroupEntry().WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			WithID(nhgIndex).AddNextHop(nhIndex, 1),
		fluent.IPv4Entry().WithNetworkInstance("DECAP_TE_VRF").
			WithPrefix(gribiIPv4entry1).WithNextHopGroup(nhgIndex),
	)

	args.client.Modify().AddEntry(t,
		fluent.IPv4Entry().WithNetworkInstance("DECAP_TE_VRF").
			WithPrefix(gribiIPv4entry2).WithNextHopGroup(nhgIndex),
	)

	args.client.Modify().AddEntry(t,
		fluent.IPv4Entry().WithNetworkInstance("DECAP_TE_VRF").
			WithPrefix(gribiIPv4entry3).WithNextHopGroup(nhgIndex),
	)

	args.client.Modify().AddEntry(t,
		fluent.NextHopEntry().WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			WithIndex(2).WithNextHopNetworkInstance(deviations.DefaultNetworkInstance(dut)),
		fluent.NextHopGroupEntry().WithNetworkInstance(deviations.DefaultNetworkInstance(dut)).
			WithID(2).AddNextHop(2, 1),
		fluent.IPv4Entry().WithNetworkInstance("TE_VRF_111").
			WithPrefix("0.0.0.0/0").WithNextHopGroup(2),
	)

	// Default route in TE VRF

	if err := awaitTimeout(args.ctx, t, args.client, time.Minute); err != nil {
		t.Logf("Could not program entries via client, got err, check error codes: %v", err)
	}

	chk.HasResult(t, args.client.Results(t),
		fluent.OperationResult().WithNextHopOperation(nhIndex).WithOperationType(constants.Add).
			WithProgrammingResult(fluent.InstalledInFIB).AsResult(),
		chk.IgnoreOperationID(),
	)
	chk.HasResult(t, args.client.Results(t),
		fluent.OperationResult().WithNextHopGroupOperation(nhIndex).WithOperationType(constants.Add).
			WithProgrammingResult(fluent.InstalledInFIB).AsResult(),
		chk.IgnoreOperationID(),
	)
	chk.HasResult(t, args.client.Results(t),
		fluent.OperationResult().WithIPv4Operation(gribiIPv4entry1).WithOperationType(constants.Add).
			WithProgrammingResult(fluent.InstalledInFIB).AsResult(),
		chk.IgnoreOperationID(),
	)
	chk.HasResult(t, args.client.Results(t),
		fluent.OperationResult().WithIPv4Operation(gribiIPv4entry2).WithOperationType(constants.Add).
			WithProgrammingResult(fluent.InstalledInFIB).AsResult(),
		chk.IgnoreOperationID(),
	)
	chk.HasResult(t, args.client.Results(t),
		fluent.OperationResult().WithIPv4Operation(gribiIPv4entry3).WithOperationType(constants.Add).
			WithProgrammingResult(fluent.InstalledInFIB).AsResult(),
		chk.IgnoreOperationID(),
	)
	chk.HasResult(t, args.client.Results(t),
		fluent.OperationResult().WithIPv4Operation("0.0.0.0/0").WithOperationType(constants.Add).
			WithProgrammingResult(fluent.InstalledInFIB).AsResult(),
		chk.IgnoreOperationID(),
	)
}

func configureOTG(t *testing.T, otg *otg.OTG) gosnappi.Config {
	t.Helper()
	config := gosnappi.NewConfig()
	port1 := config.Ports().Add().SetName("port1")
	port2 := config.Ports().Add().SetName("port2")

	iDut1Dev := config.Devices().Add().SetName(atePort1.Name)
	iDut1Eth := iDut1Dev.Ethernets().Add().SetName(atePort1.Name + ".Eth").SetMac(atePort1.MAC)
	iDut1Eth.Connection().SetChoice(gosnappi.EthernetConnectionChoice.PORT_NAME).SetPortName(port1.Name())
	iDut1Ipv4 := iDut1Eth.Ipv4Addresses().Add().SetName(atePort1.Name + ".IPv4")
	iDut1Ipv4.SetAddress(atePort1.IPv4).SetGateway(dutPort1.IPv4).SetPrefix(uint32(atePort1.IPv4Len))
	iDut1Ipv6 := iDut1Eth.Ipv6Addresses().Add().SetName(atePort1.Name + ".IPv6")
	iDut1Ipv6.SetAddress(atePort1.IPv6).SetGateway(dutPort1.IPv6).SetPrefix(uint32(atePort1.IPv6Len))

	iDut2Dev := config.Devices().Add().SetName(atePort2.Name)
	iDut2Eth := iDut2Dev.Ethernets().Add().SetName(atePort2.Name + ".Eth").SetMac(atePort2.MAC)
	iDut2Eth.Connection().SetChoice(gosnappi.EthernetConnectionChoice.PORT_NAME).SetPortName(port2.Name())
	iDut2Ipv4 := iDut2Eth.Ipv4Addresses().Add().SetName(atePort2.Name + ".IPv4")
	iDut2Ipv4.SetAddress(atePort2.IPv4).SetGateway(dutPort2.IPv4).SetPrefix(uint32(atePort2.IPv4Len))
	iDut2Ipv6 := iDut2Eth.Ipv6Addresses().Add().SetName(atePort2.Name + ".IPv6")
	iDut2Ipv6.SetAddress(atePort2.IPv6).SetGateway(dutPort2.IPv6).SetPrefix(uint32(atePort2.IPv6Len))

	config.Captures().Add().SetName("packetCapture").SetPortNames([]string{port2.Name()}).SetFormat(gosnappi.CaptureFormat.PCAP)

	t.Logf("Pushing config to ATE and starting protocols...")
	otg.PushConfig(t, config)
	time.Sleep(30 * time.Second)
	otg.StartProtocols(t)
	time.Sleep(30 * time.Second)
	t.Log(config.Msg().GetCaptures())
	return config
}

func createFlow(flowName, outDstIP, outSrcIP string, isV4InnHeader bool) gosnappi.Flow {
	// Create traffic flow.
	flow := gosnappi.NewFlow().SetName(flowName)
	flow.Metrics().SetEnable(true)
	flow.TxRx().Device().
		SetTxNames([]string{atePort1.Name + ".IPv4"}).
		SetRxNames([]string{atePort2.Name + ".IPv4"})
	flow.Size().SetFixed(512)
	flow.Rate().SetPps(100)
	flow.Duration().SetChoice("continuous")
	flow.Packet().Add().Ethernet().Src().SetValue(atePort1.MAC)
	// Outer IP header
	flow.Packet().Add().Ipv4().Src().SetValue(outSrcIP)
	flow.Packet().Add().Ipv4().Dst().SetValue(outDstIP)
	// Inner v4/v6 Header
	if isV4InnHeader {
		flow.Packet().Add().Ipv4().Src().SetValue(atePort1.IPv4)
		flow.Packet().Add().Ipv4().Dst().SetValue(atePort2.IPv4)
	} else {
		flow.Packet().Add().Ipv6().Src().SetValue(atePort1.IPv6)
		flow.Packet().Add().Ipv6().Dst().SetValue(atePort2.IPv6)
	}
	return flow
}

func sendTraffic(t *testing.T, args *testArgs) {
	t.Helper()
	// Start packet capture.
	cs := gosnappi.NewControlState()
	cs.Port().Capture().SetState(gosnappi.StatePortCaptureState.START)
	args.otg.SetControlState(t, cs)
	// Send traffic.
	t.Logf("Starting traffic")
	args.otg.StartTraffic(t)
	time.Sleep(15 * time.Second)
	t.Logf("Stop traffic")
	args.otg.StopTraffic(t)
}

func createNegTestFlow(t *testing.T, config gosnappi.Config, otg *otg.OTG) {
	t.Helper()
	flow7 := createFlow("flow7-neg-ip-in-ip", ipv4OuterDst4, ipv4OuterSrc1, v4Flow)

	config.Flows().Clear()

	config.Flows().Append(flow7)

	t.Logf("Pushing negative test flow to OTG...")
	otg.PushConfig(t, config)
	time.Sleep(30 * time.Second)
	otg.StartProtocols(t)
	time.Sleep(30 * time.Second)
}

func createGoodFlows(t *testing.T, config gosnappi.Config, otg *otg.OTG) {
	t.Helper()
	flow1 := createFlow("flow1-ip-in-ip", ipv4OuterDst1, ipv4OuterSrc1, v4Flow)
	flow2 := createFlow("flow2-ip-in-ip", ipv4OuterDst2, ipv4OuterSrc1, v4Flow)
	flow3 := createFlow("flow3-ip-in-ip", ipv4OuterDst3, ipv4OuterSrc1, v4Flow)
	flow4 := createFlow("flow4-ipv6-in-ip", ipv4OuterDst1, ipv4OuterSrc1, !v4Flow)
	flow5 := createFlow("flow5-ipv6-in-ip", ipv4OuterDst2, ipv4OuterSrc1, !v4Flow)
	flow6 := createFlow("flow6-ipv6-in-ip", ipv4OuterDst3, ipv4OuterSrc1, !v4Flow)

	config.Flows().Clear() //Clear all flows before adding.

	flowList := []gosnappi.Flow{flow1, flow2, flow3, flow4, flow5, flow6}
	for _, flow := range flowList {
		config.Flows().Append(flow)
	}

	t.Logf("Pushing all good Flows to OTG...")
	otg.PushConfig(t, config)
	time.Sleep(30 * time.Second)
	otg.StartProtocols(t)
	time.Sleep(30 * time.Second)
}

func verifyTraffic(t *testing.T, args *testArgs, flowList []string, wantLoss, decapPacket bool) {
	t.Helper()
	time.Sleep(3 * time.Minute)
	for _, flowName := range flowList {
		t.Logf("Verifying flow metrics for the flow %s\n", flowName)
		recvMetric := gnmi.Get(t, args.otg, gnmi.OTG().Flow(flowName).State())
		txPackets := recvMetric.GetCounters().GetOutPkts()
		rxPackets := recvMetric.GetCounters().GetInPkts()
		lostPackets := txPackets - rxPackets
		var lossPct uint64
		if txPackets != 0 {
			lossPct = lostPackets * 100 / txPackets
		} else {
			t.Errorf("Traffic stats are not correct %v", recvMetric)
		}
		if wantLoss {
			if lossPct < 100-tolerancePct {
				t.Errorf("Traffic is expected to fail %s\n got %v, want 100%% failure", flowName, lossPct)
			} else {
				t.Logf("Traffic Loss Test Passed!")
			}
		} else {
			if lossPct > tolerancePct {
				t.Errorf("Traffic Loss Pct for Flow: %s\n got %v, want 0", flowName, lossPct)
			} else {
				t.Logf("Traffic Test Passed!")
			}
		}
	}
	bytes := args.otg.GetCapture(t, gosnappi.NewCaptureRequest().SetPortName(args.otgConfig.Ports().Items()[1].Name()))
	f, err := os.CreateTemp("", "pcap")
	if err != nil {
		t.Fatalf("ERROR: Could not create temporary pcap file: %v\n", err)
	}
	if _, err := f.Write(bytes); err != nil {
		t.Fatalf("ERROR: Could not write bytes to pcap file: %v\n", err)
	}
	f.Close()
	validateTraffic(t, f.Name(), decapPacket)
}

func validateTraffic(t *testing.T, filename string, decapPacket bool) {
	t.Helper()
	handle, err := pcap.OpenOffline(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	if decapPacket {
		validateTrafficDecap(t, packetSource)
	} else {
		validateTrafficNonDecap(t, packetSource)
	}
}

func validateTrafficDecap(t *testing.T, packetSource *gopacket.PacketSource) {
	t.Helper()
	t.Log("Validate traffic for decap routes")
	var packetCheckCount uint32 = 0
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ipPacket, _ := ipLayer.(*layers.IPv4)
		innerPacket := gopacket.NewPacket(ipPacket.Payload, ipPacket.NextLayerType(), gopacket.Default)
		if packetCheckCount > 5 {
			break
		}
		packetCheckCount++
		ipInnerLayer := innerPacket.Layer(layers.LayerTypeIPv4)
		ipv6InnerLayer := innerPacket.Layer(layers.LayerTypeIPv6)
		if ipInnerLayer != nil {
			t.Errorf("Packets are not decapped, Inner IP header is not removed.")
		}
		if ipv6InnerLayer != nil {
			t.Errorf("Packets are not decapped, Inner IPv6 header is not removed.")
		}
	}
}

func validateTrafficNonDecap(t *testing.T, packetSource *gopacket.PacketSource) {
	t.Helper()
	t.Log("Validate traffic non decap routes")
	var packetCheckCount uint32 = 1
	for packet := range packetSource.Packets() {
		if packetCheckCount >= 5 {
			break
		}
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ipPacket, _ := ipLayer.(*layers.IPv4)
		innerPacket := gopacket.NewPacket(ipPacket.Payload, ipPacket.NextLayerType(), gopacket.Default)
		ipInnerLayer := innerPacket.Layer(layers.LayerTypeIPv4)
		if ipInnerLayer != nil {
			if ipPacket.DstIP.String() != ipv4OuterDst4 {
				t.Errorf("Negatice test for Decap failed. Traffic sent to route which does not match the decap route are decaped")
			}
			ipInnerPacket, _ := ipInnerLayer.(*layers.IPv4)
			if ipInnerPacket.DstIP.String() != atePort2.IPv4 {
				t.Errorf("Negatice test for Decap failed. Traffic sent to route which does not match the decap route are decaped")
			}
			t.Logf("Traffic for non decap routes passed.")
			break
		}
	}
}

func configStaticRoute(t *testing.T, dut *ondatra.DUTDevice, prefix string, nexthop string) {
	t.Helper()
	ni := oc.NetworkInstance{Name: ygot.String(deviations.DefaultNetworkInstance(dut))}
	static := ni.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut))
	sr := static.GetOrCreateStatic(prefix)
	nh := sr.GetOrCreateNextHop("0")
	nh.NextHop = oc.UnionString(nexthop)
	gnmi.Update(t, dut, gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_STATIC, deviations.StaticProtocolName(dut)).Config(), static)
}

// TestMixedPrefLenDecapGribiEntries is to validate Support for decap actions with mixed
// prefixes installed through gRIBI.
func TestMixedPrefLenDecapGribiEntries(t *testing.T) {
	ctx := context.Background()
	dut := ondatra.DUT(t, "dut")
	gribic := dut.RawAPIs().GRIBI(t)
	ate := ondatra.ATE(t, "ate")
	top := gosnappi.NewConfig()

	t.Run("Configure Default Network Instance", func(t *testing.T) {
		fptest.ConfigureDefaultNetworkInstance(t, dut)
	})

	t.Run("Configure Non-Default Network Instances", func(t *testing.T) {
		configNonDefaultNetworkInstance(t, dut)
	})

	t.Run("Configure interfaces on DUT", func(t *testing.T) {
		configureDUT(t, dut)
	})

	t.Run("Apply vrf selectioin policy to DUT port-1", func(t *testing.T) {
		configureVrfSelectionPolicy(t, dut)
	})

	otg := ate.OTG()
	var otgConfig gosnappi.Config
	t.Run("Configure OTG", func(t *testing.T) {
		otgConfig = configureOTG(t, otg)
	})

	negTestAddr := fmt.Sprintf("%s/%d", ipv4OuterDst4, uint32(32))
	t.Run("Add static route for validating negative traffic test", func(t *testing.T) {
		configStaticRoute(t, dut, negTestAddr, atePort2.IPv4)
	})

	// Connect gRIBI client to DUT referred to as gRIBI - using PRESERVE persistence and
	// SINGLE_PRIMARY mode, with FIB ACK requested. Specify gRIBI as the leader.
	client := fluent.NewClient()
	client.Connection().WithStub(gribic).WithPersistence().WithInitialElectionID(1, 0).
		WithFIBACK().WithRedundancyMode(fluent.ElectedPrimaryClient)
	client.Start(ctx, t)
	defer client.Stop(t)

	defer func() {
		// Flush all entries after test.
		if err := gribi.FlushAll(client); err != nil {
			t.Error(err)
		}
	}()

	client.StartSending(ctx, t)
	if err := awaitTimeout(ctx, t, client, time.Minute); err != nil {
		t.Fatalf("Await got error during session negotiation for clientA: %v", err)
	}
	eID := gribi.BecomeLeader(t, client)

	args := &testArgs{
		ctx:        ctx,
		client:     client,
		dut:        dut,
		ate:        ate,
		otgConfig:  otgConfig,
		top:        top,
		electionID: eID,
		otg:        otg,
	}

	t.Run("Flush existing gRIBI routes before test", func(t *testing.T) {
		if err := gribi.FlushAll(client); err != nil {
			t.Fatal(err)
		}
	})

	if deviations.GribiDecapMixedPlenUnsupported(dut) {
		t.Skip("Gribi route programming with mixed prefix length is not supported.")
	}
	t.Run("Program gRIBi routes 192.51.100.1/24, 192.55.200.3/32, and 192.51.129.0/22",
		func(t *testing.T) {
			configureGribiRoute(ctx, t, dut, args)
		})

	t.Run("Create ip-in-ip and ipv6-in-ip traffic flows, send traffic and verify", func(t *testing.T) {
		createGoodFlows(t, otgConfig, otg)
		sendTraffic(t, args)
		verifyTraffic(t, args, []string{flow1, flow2, flow3, flow4, flow5, flow6}, !wantLoss, decapPacket)
	})

	t.Run("Create traffic flow for non decap route, send traffic and verify", func(t *testing.T) {
		createNegTestFlow(t, otgConfig, otg)
		sendTraffic(t, args)
		verifyTraffic(t, args, []string{flow7}, !wantLoss, !decapPacket)
	})
}
