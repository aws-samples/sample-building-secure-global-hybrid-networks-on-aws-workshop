# AWS Network Firewall Suricata Rules - Explained

```
# Allow TCP 3-way handshake
pass tcp any any -> any any (flow:to_server,not_established; sid:100001;)
```
- This rule allows the initial TCP handshake (SYN packets) from any source to any destination. The `flow:to_server,not_established` keyword ensures this only matches traffic that is going to the server and is not part of an established connection. This is necessary to allow new TCP connections to be initiated before applying more specific rules.

---

```
# Mark MySQL connection from DEV to PROD sanitized database as allowed
alert tcp $DEV_CIDR any -> $SANITIZED_PROD_DB 3306 (msg:"Allow DEV to PROD sanitized DB"; flowbits:set,allow; flow:to_server; sid:100002;)
```
- This rule identifies and marks MySQL traffic (port 3306) from the Development environment to the sanitized Production database as allowed. The `flowbits:set,allow` keyword sets a flag called "allow" on this connection, which will be checked by later rules. The `flow:to_server` ensures this only applies to traffic going from client to server. This rule uses `alert` action which means it will log the connection but still allow it to be evaluated by other rules.

---

```
# Mark TLS connection from DEV to PROD internal API as allowed
alert tls $DEV_CIDR any -> $PROD_INTERNAL_API 443 (msg:"Allow DEV to PROD internal API over TLS"; flowbits:set,allow; flow:to_server; sid:100003;)
```
- This rule identifies and marks HTTPS/TLS traffic (port 443) from the Development environment to the Production internal API as allowed. The `tls` protocol matcher specifically looks for TLS-encrypted traffic. Like the previous rule, it sets the "allow" flowbit to mark this connection as permitted, which will be referenced by later rules.

---

```
# Mark HTTP connection from DEV to PROD internal API as allowed
alert http $DEV_CIDR any -> $PROD_INTERNAL_API 80 (msg:"Allow DEV to PROD internal API over HTTP"; flowbits:set,allow; flow:to_server; sid:100004;)
```
- This rule identifies and marks HTTP traffic (port 80) from the Development environment to the Production internal API as allowed. The `http` protocol matcher specifically looks for HTTP traffic. It also sets the "allow" flowbit to mark this connection as permitted. This allows both encrypted (TLS) and unencrypted (HTTP) access to the internal API.

---

```
# Reject any other TCP connections from DEV to PROD (Send a TCP reset so it's clear the connection was blocked by firewall and not a routing issue)
reject tcp $DEV_CIDR any -> $PROD_CIDR any (msg:"UNAUTHORIZED DEV -> PROD TCP CONNECTION ATTEMPT"; flowbits:isnotset,allow; flow:to_server; sid:100005;)
```
- This rule blocks any TCP traffic from Development to Production that hasn't been marked as allowed by previous rules. The `flowbits:isnotset,allow` keyword checks if the "allow" flag has NOT been set on this connection. The `reject` action sends a TCP reset packet back to the source, which immediately terminates the connection and provides clear feedback that the connection was actively blocked (rather than silently dropped).

---

```
# Drop any other IP connections from DEV to PROD (Catch all drop rule for non TCP based protocols)
drop ip $DEV_CIDR any -> $PROD_CIDR any (msg:"UNAUTHORIZED DEV -> PROD NON-TCP CONNECTION ATTEMPT"; flowbits:isnotset,allow; flow:to_server; ip_proto: !TCP; sid:100006;)
```
- This is a catch-all rule that blocks any non-TCP traffic (UDP, ICMP, etc.) from Development to Production. The `ip_proto: !TCP` specifically matches any IP protocol that is not TCP. The `drop` action silently discards the packets without sending any notification back to the source. This rule ensures complete isolation between environments except for the specifically allowed connections.
- The `flowbits` keyword is a powerful feature in Suricata that allows rules to set, check, and toggle stateful flags on network flows. This enables rules to communicate with each other and make decisions based on previously matched traffic. For more information on using flowbits, refer to the [Suricata documentation](https://docs.suricata.io/en/latest/rules/flow-keywords.html).

In this ruleset, flowbits are used to implement an allow-list approach:
1. The first three rules mark specific allowed connections by setting the "allow" flag
2. The last two rules block any connections that don't have the "allow" flag set

This creates a default-deny policy where only explicitly allowed traffic can pass between environments, which is a security best practice for network segmentation.

---

```
# Block evasion of Route 53 Resolver (enforce the use of Route 53 Resolver DNS Firewall)
drop dns $HOME_NET any -> !$HOME_NET 53 (msg:"Drop DNS protocol outbound on port 53"; reference:url,https://attack.mitre.org/techniques/T1048/; sid:100007;)
```
- This rule blocks any DNS traffic from your internal networks (`$HOME_NET`) to any external DNS servers (`!$HOME_NET` on port `53`). It forces all DNS queries to go through the Route 53 Resolver where DNS Firewall rules can be applied. Network Firewall doesn't have visibility into queries made to the Route 53 Resolver itself, so this rule only blocks direct external DNS queries. This prevents DNS-based data exfiltration, command and control communications, and DNS tunneling attacks by ensuring all DNS traffic is subject to DNS Firewall rules.

---

```
# Port 80 can only be used for HTTP traffic
drop tcp $HOME_NET any -> any 80 (msg:"Egress Port TCP/80 but not HTTP"; app-layer-protocol:!http; flow:to_server; sid:100008;)
```
- This rule blocks any TCP traffic on port 80 that is not using the HTTP protocol. The `app-layer-protocol:!http` keyword specifically identifies traffic that doesn't match HTTP protocol patterns. This prevents attackers from using port 80 for non-HTTP traffic, such as command and control channels or data exfiltration using custom protocols.

---

```
# Outbound HTTP traffic must use port 80
drop http $HOME_NET any -> any !80 (msg:"Egress HTTP but not port TCP/80"; flow:to_server; sid:100009;)
```
- This rule blocks HTTP traffic that's not using the standard port 80. The `!80` in the destination port field matches any port except 80. This prevents applications from using non-standard ports for HTTP traffic, which is a common evasion technique to bypass security monitoring focused only on standard ports.

---

```
# Port 443 can only be used for TLS traffic
drop tcp $HOME_NET any -> any 443 (msg:"Egress Port TCP/443 but not TLS"; app-layer-protocol:!tls; flow:to_server; sid:1000010;)
```
- This rule blocks any TCP traffic on port 443 that is not using the TLS protocol. Similar to the port 80 rule, this prevents misuse of the HTTPS port for non-encrypted or custom protocol traffic, ensuring that only legitimate encrypted web traffic uses this port.

---

```
# Outbound TLS traffic must use port 443
drop tls $HOME_NET any -> any !443 (msg:"Egress TLS but not port TCP/443"; flow:to_server; sid:1000011;)
```
- This rule blocks TLS/encrypted traffic that's not using the standard port 443. This prevents applications from using TLS on non-standard ports to evade security controls, a technique often used to tunnel prohibited traffic through firewalls.

---

```
# Port 22 can only be used for SSH traffic
drop tcp $HOME_NET any -> any 22 (msg:"Egress Port TCP/22 but not SSH"; app-layer-protocol:!ssh; flow:to_server; sid:1000012;)
```
- This rule blocks any TCP traffic on port 22 that is not using the SSH protocol. This prevents misuse of the SSH port for other types of traffic, ensuring that only legitimate SSH connections are allowed on this port.

---

```
# Outbound SSH traffic must use port 22
drop ssh $HOME_NET any -> any !22 (msg:"Egress SSH but not port TCP/22"; flow:to_server; sid:1000013;)
```
- This rule blocks SSH traffic that's not using the standard port 22. This prevents SSH tunneling on non-standard ports, which is a common technique used to bypass network security controls.

---

```
# Mark MySQL connection from OnPrem to PROD sanitized database as allowed
alert tcp $ON_PREM_CIDR any -> $SANITIZED_PROD_DB 3306 (msg:"Allow OnPrem to sanitized PROD DB"; flowbits:set,allow; flow:to_server; sid:1000014;)
```
- This rule identifies and marks MySQL traffic (port 3306) from the On-premises environment to the sanitized Production database as allowed. The `flowbits:set,allow` keyword sets a flag called "allow" on this connection, which will be checked by later rules. The `flow:to_server` ensures this only applies to traffic going from client to server. This rule uses `alert` action which means it will log the connection but still allow it to be evaluated by other rules.

---

```
# Mark TLS connection from OnPrem to PROD internal API as allowed
alert tls $ON_PREM_CIDR any -> $PROD_INTERNAL_API 443 (msg:"Allow OnPrem to PROD internal API over TLS"; flowbits:set,allow; flow:to_server; sid:1000015;)
```
- This rule identifies and marks HTTPS/TLS traffic (port 443) from the On-premises environment to the Production internal API as allowed. The `tls` protocol matcher specifically looks for TLS-encrypted traffic. Like the previous rule, it sets the "allow" flowbit to mark this connection as permitted, which will be referenced by later rules.

---

```
# Mark HTTP connection from OnPrem to PROD internal API as allowed
alert http $ON_PREM_CIDR any -> $PROD_INTERNAL_API 80 (msg:"Allow OnPrem to PROD internal API over HTTP"; flowbits:set,allow; flow:to_server; sid:1000016;)
```
- This rule identifies and marks HTTP traffic (port 80) from the On-premises environment to the Production internal API as allowed. The `http` protocol matcher specifically looks for HTTP traffic. It also sets the "allow" flowbit to mark this connection as permitted. This allows both encrypted (TLS) and unencrypted (HTTP) access to the internal API.

---

```
# Reject any other TCP connections from OnPrem to PROD (Send a TCP reset so it's clear the connection was blocked by firewall and not a routing issue)
reject tcp $ON_PREM_CIDR any -> $PROD_CIDR any (msg:"UNAUTHORIZED OnPrem -> PROD TCP CONNECTION ATTEMPT"; flowbits:isnotset,allow; flow:to_server; sid:1000017;)
```
- This rule blocks any TCP traffic from On-premises to Production that hasn't been marked as allowed by previous rules. The `flowbits:isnotset,allow` keyword checks if the "allow" flag has NOT been set on this connection. The `reject` action sends a TCP reset packet back to the source, which immediately terminates the connection and provides clear feedback that the connection was actively blocked (rather than silently dropped).

---

```
# Drop any other IP connections from OnPrem to PROD (Catch all drop rule for non TCP based protocols)
drop ip $ON_PREM_CIDR any -> $PROD_CIDR any (msg:"UNAUTHORIZED OnPrem -> PROD NON-TCP CONNECTION ATTEMPT"; flowbits:isnotset,allow; flow:to_server; ip_proto: !TCP; sid:1000018;)
```
- This is a catch-all rule that blocks any non-TCP traffic (UDP, ICMP, etc.) from On-premises to Production. The `ip_proto: !TCP` specifically matches any IP protocol that is not TCP. The `drop` action silently discards the packets without sending any notification back to the source. This rule ensures complete isolation between environments except for the specifically allowed connections.


