# TE-2.1.2: Mixed Prefix Decap gRIBI Entries

## Summary

Support for decap actions with mixed prefixes installed through gRIBI.

## Procedure

*   Connect ATE port-1 to DUT port-1, and ATE port-2 to DUT port-2.

*   Apply vrf_selectioin_policy_w to DUT port-1.

*   Using gRIBI, install the following gRIBI AFTs, and validate the specified behavior.

    *   Using gRIBI, install an  IPv4Entry for the prefix 192.51.100.1/24 that points to a
        NextHopGroup that contains a single NextHop that specifies decapsulating the IPv4 
        header and specifies the DEFAULT network instance. This IPv4Entry should be installed
        in the DECAP_TE_VRF.  

    *   Using gRIBI, install similar IPv4Entry-ies for the prefixes 192.55.200.3/32, and 
        192.51.129.0/22. Note that these IPv4Enty-ies should point to the same NextHopGroup
        installed above.

    *   Send both 6in4 and 4in4 packets to the DUT port-1.The outer v4 header has the destination
        addresses 192.51.100.64, 192.55.200.3, and 192.51.128.5, with source IP ad ipv_outer_src_111 Pick some inner header destination address for which there’s a route in the DEFAULT VRF. 

    *   Verify that the packets have their outer v4 header stripped, and are forwarded according to
        the route in the DEFAULT VRF that matches the inner IP address. 

    *   Repeat the test with packets with a destination address such as 192.58.200.7 that does not
        match the decap route, and verify that such packets are not decapped. 

## Protocol/RPC Parameter coverage

## Config parameter coverage

## Telemery parameter coverage
