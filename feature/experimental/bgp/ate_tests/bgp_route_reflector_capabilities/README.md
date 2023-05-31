# RT-1.9: BGP Route Reflector Capabilities

## Summary

BGP Route Reflector Capabilities

## Procedure

*   Establish BGP sessions as follows between ATE and DUT.
    *   ATE port 1 is emulating RRC peered with the DUT acting as the RR.
    *   The DUT has eBGP peering with ATE port 2 and is receiving full Internet Scale routes.
        *   DUT Port1 (AS 500) ---iBGP--- ATE Port1( AS 500)
        *   DUT Port1 (AS 500) ---eBGP---- ATE Port2( AS 200)
    *   Validate session state on ATE ports and DUT using telemetry.
    *   Validate session state and capabilities received on DUT using telemetry.
    *   Validate the BGP route/path attributes.
        *   NH
        *   Local Pref
        *   Metric
        *   Communities 
        *   Colors
## Config Parameter coverage

*   /network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/route-reflector 
*   /network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/route-reflector/config 
*   /network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/route-reflector/config/route-reflector-cluster-id 
*   /network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/route-reflector/config/route-reflector-client 

## Telemetry Parameter coverage

*   /network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/route-reflector/state/route-reflector-cluster-id 
*   /network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/route-reflector/state/route-reflector-client 

## Protocol/RPC Parameter coverage

N/A

## Minimum DUT platform requirement

N/A
