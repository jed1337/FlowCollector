# Flow Collector
## Information
This tool is used to extract various flow-based features from pcap data. The tool cannot extract features while captures are ongoing.

A flow is a set of packets the following common elements: source IP, source port, destination IP, destination port, and protocol.

The first packet in the flow determines the direction. Packets in the flow that have the same source IP and port as the first packet are treated as being in the forward direction. On the other hand, packets in the flow whose destination IP and port are the same as the first packet's source IP and port are treated as being in the backward direction.

The tool has the option of using both uni-directional and bi-directional flows. The differences between them are explained in [Network Flow: Uni-Directional VS Bi-Directional](http://geek00l.blogspot.com/2008/01/network-flow-uni-directional-vs-bi.html).

If uni-directional flows are used, all flows will automatically be in the forward direction. Since some of the features have a `direc_func` parameter indicating what direction to use, the value of those features will return 0 if `directions.backward` is given as the parameter (since there are no flows in the backward direction).

## Directions
These are stored in `Scripts/Attributes/directions.py`. These are used in conjunction with the [Direction based features](###-Direction-based-Features). The possible values are:

Direction | Description
--- | ---
Forward        | Only consider packets in the forward direction
Backward       | Only consider packets in the backward direction
Bi directional | Consider all packets (packets from either direction) in creating the feature

## Aggregate functions
These are stored in  `Scripts/Attributes/aggregate_functions.py`. These are used with the [Meta features](###-Meta-Features). The possible values are:

Aggregate function | Description
--- | ---
Max  | Get the maximum
Min  | Get the minimum
Mean | Get the mean
Std  | Get the standard deviation
Var  | Get the variance
No aggregate  | Do not perform any aggregate functions


## Features
### Basic Features
These features are not reliant on any direction. They can be found by simply aggregating the packets into a flow.

Feature | Description | Example
--- | --- | ---
Src IP                 | The source IP | '172.16.15.3'
Src port               | The source port | 49622
Dst IP                 | The destination IP | '152.14.13.11'
Dst port               | The destination port | 80
Proto number           | The protocol number  | 6 (for TCP), 17 (for UDP)
Packet count           | The number of packets in the flow | 21
Duration               | The flow's duration calculated by end time - start time | 5.5573811531066895
Cumulative or of flags | Returns N/A if the protocol is not TCP. If the Protocol is TCP, it returns the cumulative OR of the flags. | "FSPA" (FIN, SYN, PSH, and ACK flags in the flow)

### Direction-based Features
These features rely on a `direc_func` parameter to properly determine what direction it will extract the particular feature from.

Feature | Description | Example
--- | --- | ---
Bytes in direction                    | The total bytes in the flow (Including the packet headers) | 1748
Packets per second in direction       | The packets per second in a given direction. Calculated by dividing the total packet sizes by the flow duration | 1.979359336221774
Bytes per second in direction         | The bytes per second in a given direction. Calculated by dividing the total packet sizes by the flow duration | 314.5381927014237
Ratio of forward and backward packets | Calculated by dividing the number of forward packets by the number of backward packets. | 1.1
Ratio of forward and backward bytes   | Calculated by dividing the number of forward bytes by the number of backward packets. | 0.20133609767334715


### Meta Features
These features take a `reduce_func` parameter in addition to the `direc_func` parameter. The goal of the  `reduce_func` parameter is to reduce the results into a single value by aggregating them depending on the value given.

The word *meta* was used since I couldn't think of a better name.

Feature | Description | Example
--- | --- | ---
Meta packet size         | Returns the aggregated packet size in a given direction | 158.9090909090909
Meta inter arrival times | The inter arrival time is the time between two consecutive packets. This returns the aggregated inter arrival time in a given direction. | 0.5557353734970093

### Other Features
These features are placed here since the parameters they take are unrelated to one another.

Feature | Additional parameter | Description | Example
--- | --- | --- | ---
Flag count in direction | `flag_bit` | Returns the number of instances that the value passed in `flag_bit` occurs in the flow in a given direction | 10