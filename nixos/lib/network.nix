# generic networking functions for use in all of the flyingcircus Nix stuff

{ config, pkgs, lib, ... }:

with builtins;
let 
  fclib = config.fclib;
in 
rec {
  stripNetmask = cidr: head (lib.splitString "/" cidr);

  prefixLength = cidr: lib.toInt (elemAt (lib.splitString "/" cidr) 1);
  # The same as prefixLength, but returns a string not an int
  prefix = cidr: elemAt (lib.splitString "/" cidr) 1;

  netmaskFromPrefixLength = prefix:
     (ip4.fromNumber
       (((fclib.pow 2 prefix) - 1) * (fclib.pow 2 (32-prefix)))
       prefix).address;
  netmaskFromCIDR = cidr:
    netmaskFromPrefixLength (prefixLength cidr);

  isIp4 = cidr: length (lib.splitString "." cidr) == 4;
  isIp6 = cidr: length (lib.splitString ":" cidr) > 1;

  # choose correct "iptables" invocation depending on the address
  iptables = a:
    if isIp4 a then "iptables" else
    if isIp6 a then "ip6tables" else
    "ip46tables";

  # choose correct "ip" invocation depending on the address
  ip' = a: "ip " + (if isIp4 a then "-4" else if isIp6 a then "-6" else "");

  fqdn = {vlan,
          domain ? config.networking.domain,
          location ? lib.attrByPath [ "parameters" "location" ] "standalone" config.flyingcircus.enc,
          }:
      "${config.networking.hostName}.${vlan}.${location}.${domain}";

  # list IP addresses for service configuration (e.g. nginx)
  listenAddresses = iface:
    if iface == "lo"
    # lo isn't part of the enc. Hard code it here.
    then [ "127.0.0.1" "::1" ]
    else
      if hasAttr iface config.networking.interfaces
      then
        let
          interface_config = getAttr iface config.networking.interfaces;
        in
          (map (addr: addr.address) interface_config.ipv4.addresses) ++
          (map (addr: addr.address) interface_config.ipv6.addresses)
      else [];

  quoteIPv6Address = addr: if isIp6 addr then "[${addr}]" else addr;

  listServiceAddresses = service:
  (map
    (service: service.address)
    (filter
      (s: s.service == service)
      config.flyingcircus.encServices));

  listServiceIPs = service:
  (lib.flatten
    (map
      (service: service.ips)
      (filter
        (s: s.service == service)
        config.flyingcircus.encServices)));


  # Return service address (string) or null, if no service
  listServiceAddress = service:
    let
      addresses = listServiceAddresses service;
    in
      if addresses == [] then null else head addresses;

  listServiceAddressesWithPort = service: port:
    map
      (address: "${address}:${toString port}")
      (listServiceAddresses config service);

  # Generate "listen" statements for nginx.conf for all IPs
  # of the given interface with modifications.
  # E.g. nginxListenOn config ethfe "443 ssl http2"
  # NOTE: "mod" *must* must start with the port number.
  nginxListenOn  = interface: mod:
    lib.concatMapStringsSep "\n  "
      (addr: "listen ${addr}:${toString mod};")
      (listenAddressesQuotedV6 interface);


  /*
   * policy routing
   */

  # VLANS with prio < 100 are generally routable to the outside.
  routingPriorities = {
    fe = 50;
    srv = 60;
    mgm = 90;
  };

  routingPriority = vlan:
    if hasAttr vlan routingPriorities
    then routingPriorities.${vlan}
    else 100;

  # Collects a complete list of configured addresses from all networks.
  # Each address is suffixed with the netmask from its network.
  allInterfaceAddresses = networks:
    let
      addrsWithNetmask = net: addrs:
        let p = prefix net;
        in map (addr: addr + "/" + p) addrs;
    in lib.concatLists (lib.mapAttrsToList addrsWithNetmask networks);

  # A list of default gateways from a list of networks in CIDR form.
  gateways = encIface: filteredNets:
    let
      # don't generate default routes via networks that have no local addresses
      netsWithLocalAddrs = nets:
        filter
          (n: encIface.networks ? ${n} && length encIface.networks.${n} > 0)
          nets;
    in
    foldl'
      (acc: cidr:
        if hasAttr cidr encIface.gateways
        then acc ++ [encIface.gateways.${cidr}]
        else acc)
      []
      (netsWithLocalAddrs filteredNets);

  # Routes for an individual VLAN on an interface. This falls apart into two
  # blocks: (1) subnet routes for all subnets on which the interface has at
  # least one address configured; (2) gateway (default) routes for each subnet
  # where any subnet of the same AF has at least one address.
  ipRoutes = vlan: encInterface: filteredNets: verb:
    let
      prio = routingPriority vlan;
      dev' = dev vlan (encInterface.bridged or false);

      networkRoutesStr = lib.concatMapStrings
        (net: ''
          ${ip' net} route ${verb} ${net} dev ${dev'} metric ${toString prio} table ${vlan}
        '')
        filteredNets;

      common = "dev ${dev'} metric ${toString prio}";
      gatewayRoutesStr = lib.optionalString
        (100 > routingPriority vlan)
        (lib.concatMapStrings
          (gw:
          ''
            ${ip' gw} route ${verb} default via ${gw} ${common}
            ${ip' gw} route ${verb} default via ${gw} ${common} table ${vlan}
          '')
          (gateways encInterface filteredNets));
    in
    "\n# routes for ${vlan}\n${networkRoutesStr}${gatewayRoutesStr}";

  # Format additional routes passed by the 'extraRoutes' parameter.
  ipExtraRoutes = vlan: routes: verb:
    lib.concatMapStringsSep "\n"
      (route:
        let
          a = head (lib.splitString " " route);
        in
        "${ip' a} route ${verb} ${route} table ${vlan}")
      routes;

  # List of nets (CIDR) that have at least one address present which satisfies
  # `predicate`.
  networksWithAtLeastOneAddress = encNetworks: predicate:
    if (lib.any predicate (allInterfaceAddresses encNetworks))
    then filter predicate (lib.attrNames encNetworks)
    else [];

  # For each predicate (AF selector): collect nets (CIDR) in the ENC networks
  # whose AF is represented by at least one address (but not necessarily in the
  # same subnet).
  # Example: Assume two IPv4 networks A, B on an interface where A has an
  # address => then both networks are collected. But when none of the networks
  # has an address configured, no net is collected.
  # Returns the union of all nets which match this criterion for at least one AF
  # predicate present in the second argument.
  filterNetworks = encNetworks: predicates:
    lib.concatMap (networksWithAtLeastOneAddress encNetworks) predicates;

  simpleRouting =
    { vlan
    , encInterface
    , action ? "start"}:  # or "stop"
    let
      verb = if action == "start" then "add" else "del";
      filteredNets = filterNetworks encInterface.networks [ isIp4 isIp6 ];
      prio = routingPriority vlan;
      dev' = dev vlan encInterface.bridged;
      common = "dev ${dev'} metric ${toString prio}";

      # additional network routes for nets in which we don't have an address
      networkRoutesStr =
        let
          nets = filter (net: encInterface.networks.${net} == []) filteredNets;
        in
        lib.concatMapStrings
          (net: ''
            ${ip' net} route ${verb} ${net} dev ${dev'} metric ${toString prio}
          '')
          nets;

      # gateway routes only for nets in which we do have an address
      gatewayRoutesStr =
        let
          nets = filter (net: encInterface.networks.${net} != []) filteredNets;
        in
        lib.optionalString
          (100 > routingPriority vlan)
          (lib.concatMapStrings
            (gw: "${ip' gw} route ${verb} default via ${gw} ${common}\n")
            (gateways encInterface nets));
    in
    "\n# routes for ${vlan}\n${networkRoutesStr}${gatewayRoutesStr}";

  # "example.org." -> absolute name; "example" -> relative to $domain
  normalizeDomain = domain: n:
    if lib.hasSuffix "." n
    then lib.removeSuffix "." n
    else "${n}.${domain}";

  # Convert for example "172.22.48.0/22" into "172.22.48.0 255.255.252.0".
  # Note: this is IPv4 only.
  decomposeCIDR = cidr:
    let
      drvname = "cidr-${replaceStrings [ "/" ":" ] [ "_" "-" ] cidr}";
    in
    readFile (pkgs.runCommand drvname {} ''
      ${pkgs.python3.interpreter} > $out <<'_EOF_'
      import ipaddress
      i = ipaddress.ip_interface('${cidr}')
      print('{} {}'.format(i.ip, i.netmask), end="")
      _EOF_
    '');

  # Adapted 'ip' command which says what it is doing and ignores errno 2 (file
  # exists) to make it idempotent.
  relaxedIp = pkgs.writeScriptBin "ip" ''
    #! ${pkgs.stdenv.shell} -e
    echo ip "$@"
    rc=0
    ${pkgs.iproute}/bin/ip "$@" || rc=$?
    if ((rc == 2)); then
      exit 0
    else
      exit $rc
    fi
  '';

  # Taken from 
  # https://github.com/LumiGuide/lumi-example/blob/master/nix/lib.nix
  ip4 = rec {
    ip = a : b : c : d : prefixLength : {
      inherit a b c d prefixLength;
      address = "${toString a}.${toString b}.${toString c}.${toString d}";
    };

    toCIDR = addr : "${addr.address}/${toString addr.prefixLength}";
    toNetworkAddress = addr : with addr; { inherit address prefixLength; };
    toNumber = addr : with addr; a * 16777216 + b * 65536 + c * 256 + d;
    fromNumber = addr : prefixLength :
      let
        aBlock = a * 16777216;
        bBlock = b * 65536;
        cBlock = c * 256;
        a      =  addr / 16777216;
        b      = (addr - aBlock) / 65536;
        c      = (addr - aBlock - bBlock) / 256;
        d      =  addr - aBlock - bBlock - cBlock;
      in
        ip a b c d prefixLength;

    fromString = with lib; str :
      let
        splits1 = splitString "." str;
        splits2 = flatten (map (x: splitString "/" x) splits1);

        e = i : toInt (builtins.elemAt splits2 i);
      in
        ip (e 0) (e 1) (e 2) (e 3) (e 4);

    fromIPString = str : prefixLength :
      fromString "${str}/${toString prefixLength}";

    network = addr :
      let
        pfl = addr.prefixLength;
        shiftAmount = fclib.pow 2 (32 - pfl);
      in
        fromNumber ((toNumber addr) / shiftAmount * shiftAmount) pfl;
  };

  network = lib.mapAttrs'
    (vlan: interface: 
      lib.nameValuePair vlan (
      let
        priority = routingPriority vlan;
        bridged = interface.bridged;

        mtu = if hasAttr vlan config.flyingcircus.static.mtus
              then config.flyingcircus.static.mtus.${vlan}
              else 1500;
      in with fclib; rec {

        inherit vlan mtu priority bridged;

        vlan_id = config.flyingcircus.static.vlan_ids.${vlan};

        device = if bridged then bridged_device else physical_device;
        attached_devices = if bridged then [physical_device] else [];
        bridged_device = "br${vlan}";
        physical_device = "eth${vlan}";

        mac_fallback = "02:00:00:${fclib.byteToHex vlan_id}:??:??";
        mac = lib.toLower
                (lib.attrByPath [ "mac" ] mac_fallback interface);

        policy = interface.policy;

        dualstack = rec {
          # Without netmask
          addresses = map stripNetmask cidrs;
          # Without netmask, V6 quoted in []
          addresses_quoted = map quoteIPv6Address addresses;
          # as cidr
          cidrs = map (attr: "${attr.address}/${toString attr.prefixLength}") attrs;

          # as attribute sets of address/prefixLength
          attrs = lib.flatten (lib.mapAttrsToList
            (network: addresses: 
              let prefix = fclib.prefixLength network;
              in (map (address: { address = address; prefixLength = prefix; }) addresses))
            interface.networks);

          default_gateways = lib.mapAttrsToList
            (network: gateway: gateway)
            (lib.filterAttrs (network: gateway:
              (length interface.networks.${network} >= 1) &&
              (priority < 100) && (isIp4 gateway))
              interface.gateways);
        };

        v4 = {
          addresses = filter isIp4 dualstack.addresses;
          cidrs = filter isIp4 dualstack.addresses;
          attrs = filter (attr: isIp4 attr.address) dualstack.attrs;
          # Select default gateways for all networks that we have a local IP in
          default_gateways = filter isIp4 dualstack.default_gateways;
        };

        v6 = {
          addresses = filter isIp6 dualstack.addresses;
          addresses_quoted = filter isIp6 dualstack.addresses_quoted;
          cidrs = filter isIp6 dualstack.addresses;
          attrs = filter (attr: isIp6 attr.address) dualstack.attrs;
          # Select default gateways for all networks that we have a local IP in
          default_gateways = filter isIp6 dualstack.default_gateways;
        };

      }))
    (lib.attrByPath [ "parameters" "interfaces" ] {} config.flyingcircus.enc);

}
