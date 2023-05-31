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

package bgp_route_reflector_capabilities_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/featureprofiles/internal/attrs"
	"github.com/openconfig/featureprofiles/internal/deviations"
	"github.com/openconfig/featureprofiles/internal/fptest"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
)

func TestMain(m *testing.M) {
	fptest.RunTests(m)
}

// The testbed consists of ate:port1 -> dut:port1 and
// dut:port2 -> ate:port2.  The first pair is called the "source"
// pair, and the second the "destination" pair.
//
// Source: ate:port1 -> dut:port1 subnet 192.0.2.0/30
// Destination: dut:port2 -> ate:port2 subnet 192.0.2.4/30
//
// Note that the first (.0, .3) and last (.4, .7) IPv4 addresses are
// reserved from the subnet for broadcast, so a /30 leaves exactly 2
// usable addresses. This does not apply to IPv6 which allows /127
// for point to point links, but we use /126 so the numbering is
// consistent with IPv4.

const (
	trafficDuration        = 1 * time.Minute
	ipv4SrcTraffic         = "192.0.2.2"
	advertisedRoutesv4CIDR = "203.0.113.1/32"
	peerGrpName1           = "BGP-PEER-GROUP1"
	peerGrpName2           = "BGP-PEER-GROUP2"
	routeCount             = 254
	dutAS                  = 500
	ateAS1                 = 500
	ateAS2                 = 200
	plenIPv4               = 30
	plenIPv6               = 126
	removeASPath           = true
	clusterID              = "1.1.1.1"
	locPref                = 50
	// https://github.com/openconfig/featureprofiles/issues/1683
	commColor         = "color:3:0"
	setPathAttrPolicy = "SET-BGP-PATH-ATTR"
	aclStatement20    = "20"
	bgpMED100         = 100
)

var (
	dutSrc = attrs.Attributes{
		Desc:    "DUT to ATE source",
		IPv4:    "192.0.2.1",
		IPv6:    "2001:db8::192:0:2:1",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}
	ateSrc = attrs.Attributes{
		Name:    "ateSrc",
		IPv4:    "192.0.2.2",
		IPv6:    "2001:db8::192:0:2:2",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}
	dutDst = attrs.Attributes{
		Desc:    "DUT to ATE destination",
		IPv4:    "192.0.2.5",
		IPv6:    "2001:db8::192:0:2:5",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}
	ateDst = attrs.Attributes{
		Name:    "atedst",
		IPv4:    "192.0.2.6",
		IPv6:    "2001:db8::192:0:2:6",
		IPv4Len: plenIPv4,
		IPv6Len: plenIPv6,
	}
)

// configureDUT configures all the interfaces on the DUT.
func configureDUT(t *testing.T, dut *ondatra.DUTDevice) {
	dc := gnmi.OC()
	i1 := dutSrc.NewOCInterface(dut.Port(t, "port1").Name(), dut)
	gnmi.Replace(t, dut, dc.Interface(i1.GetName()).Config(), i1)

	i2 := dutDst.NewOCInterface(dut.Port(t, "port2").Name(), dut)
	gnmi.Replace(t, dut, dc.Interface(i2.GetName()).Config(), i2)
}

// verifyPortsUp asserts that each port on the device is operating
func verifyPortsUp(t *testing.T, dev *ondatra.Device) {
	t.Helper()
	for _, p := range dev.Ports() {
		status := gnmi.Get(t, dev, gnmi.OC().Interface(p.Name()).OperStatus().State())
		if want := oc.Interface_OperStatus_UP; status != want {
			t.Errorf("%s Status: got %v, want %v", p, status, want)
		}
	}
}

// bgpCreateNbr creates a BGP object with neighbors pointing to ateSrc and ateDst.
func bgpCreateNbr(localAs, peerAs uint32, dut *ondatra.DUTDevice) *oc.NetworkInstance_Protocol {
	nbr1v4 := &bgpNeighbor{as: ateAS1, neighborip: ateSrc.IPv4, isV4: true, peerGrp: peerGrpName1}
	nbr2v4 := &bgpNeighbor{as: ateAS2, neighborip: ateDst.IPv4, isV4: true, peerGrp: peerGrpName2}
	nbrs := []*bgpNeighbor{nbr1v4, nbr2v4}

	d := &oc.Root{}
	ni1 := d.GetOrCreateNetworkInstance(deviations.DefaultNetworkInstance(dut))
	ni_proto := ni1.GetOrCreateProtocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	bgp := ni_proto.GetOrCreateBgp()
	global := bgp.GetOrCreateGlobal()
	global.RouterId = ygot.String(dutDst.IPv4)
	global.As = ygot.Uint32(localAs)
	global.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Enabled = ygot.Bool(true)

	// Note: we have to define the peer group even if we aren't setting any policy because it's
	// invalid OC for the neighbor to be part of a peer group that doesn't exist.
	pg1 := bgp.GetOrCreatePeerGroup(peerGrpName1)
	pg1.PeerAs = ygot.Uint32(ateAS1)
	pg1.PeerGroupName = ygot.String(peerGrpName1)

	pg2 := bgp.GetOrCreatePeerGroup(peerGrpName2)
	pg2.PeerAs = ygot.Uint32(ateAS2)
	pg2.PeerGroupName = ygot.String(peerGrpName2)

	for _, nbr := range nbrs {
		if nbr.isV4 {
			nv4 := bgp.GetOrCreateNeighbor(nbr.neighborip)
			nv4.PeerGroup = ygot.String(nbr.peerGrp)
			nv4.PeerAs = ygot.Uint32(nbr.as)
			nv4.Enabled = ygot.Bool(true)
			if nbr.neighborip == ateSrc.IPv4 { // BGP neighbor on atePort1 is RR client
				nv4RouteRef := nv4.GetOrCreateRouteReflector()
				nv4RouteRef.RouteReflectorClient = ygot.Bool(true)
				nv4RouteRef.RouteReflectorClusterId = oc.UnionString("1.1.1.1")
			}
			af4 := nv4.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST)
			af4.Enabled = ygot.Bool(true)
			af6 := nv4.GetOrCreateAfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV6_UNICAST)
			af6.Enabled = ygot.Bool(false)
		}
	}
	return ni_proto
}

// verifyBgpTelemetry checks that the dut has an established BGP session with reasonable settings.
func verifyBgpTelemetry(t *testing.T, dut *ondatra.DUTDevice) {
	ifName := dut.Port(t, "port1").Name()
	lastFlapTime := gnmi.Get(t, dut, gnmi.OC().Interface(ifName).LastChange().State())
	t.Logf("Verifying BGP state")
	statePath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp()
	nbrPath := statePath.Neighbor(ateSrc.IPv4)

	// Get BGP adjacency state.
	t.Logf("Waiting for BGP neighbor to establish...")
	_, ok := gnmi.Watch(t, dut, nbrPath.SessionState().State(), time.Minute, func(val *ygnmi.Value[oc.E_Bgp_Neighbor_SessionState]) bool {
		state, ok := val.Val()
		return ok && state == oc.Bgp_Neighbor_SessionState_ESTABLISHED
	}).Await(t)
	if !ok {
		fptest.LogQuery(t, "BGP reported state", nbrPath.State(), gnmi.Get(t, dut, nbrPath.State()))
		t.Fatal("No BGP neighbor formed")
	}
	status := gnmi.Get(t, dut, nbrPath.SessionState().State())
	t.Logf("BGP adjacency for %s: %s", ateSrc.IPv4, status)
	if want := oc.Bgp_Neighbor_SessionState_ESTABLISHED; status != want {
		t.Errorf("BGP peer %s status got %d, want %d", ateSrc.IPv4, status, want)
	}

	// Check last established timestamp.
	lestTime := gnmi.Get(t, dut, nbrPath.State()).GetLastEstablished()
	t.Logf("BGP last est time :%v, flapTime :%v", lestTime, lastFlapTime)
	if lestTime < lastFlapTime {
		t.Errorf("Bad last-established timestamp: got %v, want >= %v", lestTime, lastFlapTime)
	}

	// Check BGP Transitions.
	nbr := gnmi.Get(t, dut, statePath.State()).GetNeighbor(ateSrc.IPv4)
	estTrans := nbr.GetEstablishedTransitions()
	t.Logf("Got established transitions: %d", estTrans)
	if estTrans != 1 {
		t.Errorf("Wrong established-transitions: got %v, want 1", estTrans)
	}

	// Check BGP neighbor address from telemetry.
	addrv4 := gnmi.Get(t, dut, nbrPath.State()).GetNeighborAddress()
	t.Logf("Got ipv4 neighbor address: %s", addrv4)
	if addrv4 != ateSrc.IPv4 {
		t.Errorf("BGP v4 neighbor address: got %v, want %v", addrv4, ateSrc.IPv4)
	}

	// Check BGP neighbor address from telemetry.
	peerAS := gnmi.Get(t, dut, nbrPath.State()).GetPeerAs()
	if peerAS != ateAS1 {
		t.Errorf("BGP peerAs: got %v, want %v", peerAS, ateAS1)
	}

	// Check BGP neighbor is enabled.
	if !gnmi.Get(t, dut, nbrPath.State()).GetEnabled() {
		t.Errorf("Expected neighbor %v to be enabled", ateSrc.IPv4)
	}
}

// verifyPrefixesTelemetry confirms that the dut shows the correct numbers of installed,
// sent and received IPv4 prefixes.
func verifyPrefixesTelemetry(t *testing.T, dut *ondatra.DUTDevice, wantInstalled, wantRx, wantSent uint32) {
	statePath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp()
	prefixesv4 := statePath.Neighbor(ateDst.IPv4).AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Prefixes()
	if gotInstalled := gnmi.Get(t, dut, prefixesv4.Installed().State()); gotInstalled != wantInstalled {
		t.Errorf("Installed prefixes mismatch: got %v, want %v", gotInstalled, wantInstalled)
	}
	if !deviations.MissingPrePolicyReceivedRoutes(dut) {
		if gotRx := gnmi.Get(t, dut, prefixesv4.ReceivedPrePolicy().State()); gotRx != wantRx {
			t.Errorf("Received prefixes mismatch: got %v, want %v", gotRx, wantRx)
		}
	}
	if gotSent := gnmi.Get(t, dut, prefixesv4.Sent().State()); gotSent != wantSent {
		t.Errorf("Sent prefixes mismatch: got %v, want %v", gotSent, wantSent)
	}
}

// configureATE configures the interfaces and BGP protocols on an ATE, including
// advertising some(faked) networks over BGP.
func configureATE(t *testing.T, ate *ondatra.ATEDevice) {
	port1 := ate.Port(t, "port1")
	topo := ate.Topology().New()
	iDut1 := topo.AddInterface(ateSrc.Name).WithPort(port1)
	iDut1.IPv4().WithAddress(ateSrc.IPv4CIDR()).WithDefaultGateway(dutSrc.IPv4)

	port2 := ate.Port(t, "port2")
	iDut2 := topo.AddInterface(ateDst.Name).WithPort(port2)
	iDut2.IPv4().WithAddress(ateDst.IPv4CIDR()).WithDefaultGateway(dutDst.IPv4)

	// Setup ATE BGP route v4 advertisement.
	bgpDut1 := iDut1.BGP()
	bgpDut1.AddPeer().WithPeerAddress(dutSrc.IPv4).WithLocalASN(ateAS1).
		WithTypeInternal()

	bgpDut2 := iDut2.BGP()
	bgpDut2.AddPeer().WithPeerAddress(dutDst.IPv4).WithLocalASN(ateAS2).
		WithTypeExternal()

	bgpNeti1 := iDut2.AddNetwork("bgpNeti1")
	bgpNeti1.IPv4().WithAddress(advertisedRoutesv4CIDR).WithCount(routeCount)
	bgpNeti1.BGP().WithNextHopAddress(ateDst.IPv4).WithLocalPreference(50).
		AddExtendedCommunityColor().WithCOBits11()

	t.Logf("Pushing config to ATE and starting protocols...")
	topo.Push(t)
	topo.StartProtocols(t)
}

type bgpNeighbor struct {
	as         uint32
	neighborip string
	isV4       bool
	peerGrp    string
}

// verifyPathAttributes is to Validate Path attribute using bgp rib telemetry on ATE.
func verifyPathAttributes(t *testing.T, dut *ondatra.DUTDevice, ate *ondatra.ATEDevice) {

	at := gnmi.OC()

	rib := at.NetworkInstance(ateSrc.Name).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "0").Bgp().Rib()
	prefixPath := rib.AfiSafi(oc.BgpTypes_AFI_SAFI_TYPE_IPV4_UNICAST).Ipv4Unicast().
		NeighborAny().AdjRibInPre().RouteAny().WithPathId(0).Prefix()

	gnmi.WatchAll(t, ate, prefixPath.State(), time.Minute, func(v *ygnmi.Value[string]) bool {
		_, present := v.Val()
		return present
	}).Await(t)

	wantASPath := []uint32{ateAS2}
	wantLocPref := []uint32{}
	wantMED := []uint32{}
	wantNexthop := []string{}
	// https://github.com/openconfig/featureprofiles/issues/1683
	wantCommColor := []string{}

	// Build wantArray to compare the diff
	for i := 0; i < routeCount; i++ {
		wantLocPref = append(wantLocPref, locPref)
		wantMED = append(wantMED, bgpMED100)
		wantNexthop = append(wantNexthop, ateDst.IPv4)
		// https://github.com/openconfig/featureprofiles/issues/1683
		wantCommColor = append(wantCommColor, commColor)
	}

	_, ok := gnmi.WatchAll(t, ate, rib.AttrSetAny().AsSegmentAny().State(), 1*time.Minute, func(v *ygnmi.Value[*oc.NetworkInstance_Protocol_Bgp_Rib_AttrSet_AsSegment]) bool {
		val, present := v.Val()
		return present && cmp.Diff(val.Member, wantASPath) == ""
	}).Await(t)
	if !ok {
		t.Errorf("Obtained AS path on ATE is not as expected.")
	}

	gotMED := gnmi.GetAll(t, ate, rib.AttrSetAny().Med().State())
	if diff := cmp.Diff(wantMED, gotMED); diff != "" {
		t.Errorf("obtained MED on ATE is not as expected, got %v, want %v", gotMED, wantMED)
	}

	gotLocPref := gnmi.GetAll(t, ate, rib.AttrSetAny().LocalPref().State())
	if diff := cmp.Diff(wantLocPref, gotLocPref); diff != "" {
		t.Errorf("obtained Local Pref on ATE is not as expected, got %v, want %v", gotLocPref, wantLocPref)
	}

	gotNexthop := gnmi.GetAll(t, ate, rib.AttrSetAny().NextHop().State())
	if diff := cmp.Diff(wantNexthop, gotNexthop); diff != "" {
		t.Errorf("obtained Nexthop on ATE is not as expected, got %v, want %v", gotNexthop, wantNexthop)
	}

	// https://github.com/openconfig/featureprofiles/issues/1683
	gotCommColor := gnmi.GetAll(t, ate, rib.ExtCommunityAny().ExtCommunity().State())
	if diff := cmp.Diff(wantCommColor, gotCommColor); diff != "" {
		t.Errorf("obtained community color on ATE is not as expected, got %v, want %v", gotCommColor, wantCommColor)
	}
}

// setBgpRoutePolicy is used to configure routing policy to set BGP path attributes on DUT.
func setBgpRoutePolicy(t *testing.T, dut *ondatra.DUTDevice, d *oc.Root) {
	// Configure SetMED on DUT.
	rp := d.GetOrCreateRoutingPolicy()

	pdef1 := rp.GetOrCreatePolicyDefinition(setPathAttrPolicy)
	actions1 := pdef1.GetOrCreateStatement(aclStatement20).GetOrCreateActions()
	actions1.GetOrCreateBgpActions().SetMed = oc.UnionUint32(bgpMED100)
	actions1.GetOrCreateBgpActions().SetLocalPref = ygot.Uint32(locPref)

	gnmi.Replace(t, dut, gnmi.OC().RoutingPolicy().Config(), rp)

	// Apply setMed import policy on eBGP Peer1 - ATE Port2 - with MED 100.
	dutPolicyConfPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).
		Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP").Bgp().
		PeerGroup(peerGrpName2).ApplyPolicy().ImportPolicy()
	gnmi.Replace(t, dut, dutPolicyConfPath.Config(), []string{setPathAttrPolicy})
}

// TestRouteReflectorCapabilities is to validate BGP Route Reflector capabilities.
func TestRouteReflectorCapabilities(t *testing.T) {
	// DUT configurations.
	t.Logf("Start DUT config load.")
	dut := ondatra.DUT(t, "dut")
	ate := ondatra.ATE(t, "ate")
	d := &oc.Root{}

	// Configure interface on the DUT.
	t.Run("Configure DUT interfaces", func(t *testing.T) {
		t.Logf("Start DUT interface Config.")
		configureDUT(t, dut)
	})

	// Configure Network instance type on DUT.
	t.Run("Configure DEFAULT network instance", func(t *testing.T) {
		t.Log("Configure Network Instance type.")
		dutConfNIPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut))
		gnmi.Replace(t, dut, dutConfNIPath.Type().Config(), oc.NetworkInstanceTypes_NETWORK_INSTANCE_TYPE_DEFAULT_INSTANCE)
	})

	// Configure BGP+Neighbors on the DUT.
	dutConfPath := gnmi.OC().NetworkInstance(deviations.DefaultNetworkInstance(dut)).Protocol(oc.PolicyTypes_INSTALL_PROTOCOL_TYPE_BGP, "BGP")
	t.Run("Configure BGP Neighbors", func(t *testing.T) {
		t.Logf("Start DUT BGP Config.")
		gnmi.Delete(t, dut, dutConfPath.Config())
		dutConf := bgpCreateNbr(dutAS, ateAS1, dut)
		gnmi.Replace(t, dut, dutConfPath.Config(), dutConf)
		fptest.LogQuery(t, "DUT BGP Config", dutConfPath.Config(), gnmi.GetConfig(t, dut, dutConfPath.Config()))
	})

	t.Run("Configure route policy", func(t *testing.T) {
		setBgpRoutePolicy(t, dut, d)
	})

	// ATE Configuration.
	t.Run("configure ATE", func(t *testing.T) {
		t.Logf("Start ATE Config.")
		configureATE(t, ate)
	})

	// Verify Port Status.
	t.Run("Verify port status on DUT", func(t *testing.T) {
		t.Log("Verifying port status.")
		verifyPortsUp(t, dut.Device)
	})

	// Verify BGP telemetry.
	t.Run("Verify BGP telemetry", func(t *testing.T) {
		t.Log("Check BGP parameters.")
		verifyBgpTelemetry(t, dut)
		t.Log("Verify BGP prefix telemetry.")
		verifyPrefixesTelemetry(t, dut, routeCount, routeCount, 0)
	})

	t.Run("Verify BGP Path attributes", func(t *testing.T) {
		t.Log("Validate the BGP route/path attributes.")
		verifyPathAttributes(t, dut, ate)
	})
}
