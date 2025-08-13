# Install System Prerequisites

Note: Vivado and VitisNet P4 are build tools that are required to
compile udplb. You will need to separately download Vivado and
VitisNet P4 in order to work with this software.

```
sudo pip3 install scapy
sudo apt install tshark
```

# Install wireshark/tshark dissectors for udp-lb and evio6-seg protocol headers

```
mkdir -p ~/.local/lib/wireshark/plugins
cat protocols/{udp-lb,evio6-seg}.lua > ~/.local/lib/wireshark/plugins/jlab-stack.lua
```

The awkward concatenaton of the two dissectors is to fix the non-deterministic order that wireshark/tshark uses to load plugins.

# Set up the vivado tools environment

```
source /tools/Xilinx/Vivado/2023.2/settings64.sh
```

# Simulate the P4 pipeline

**Note**: All simulation instructions are relative to the `sim` subdirectory.

```
make sim
```

This takes care of all of these steps for you:
  - generate a set of simulation input packets (`packets_in.pcap`)
  - compile (using p4c-vitisnetp4) your p4 program into the IR (`p4-udplb.json`) required by the simulator
  - run the p4 behavioural model controlled by a script (`runsim.txt`) which will
    - preload pipleine table entries
	- read input packets (`packets_in.pcap`) and metadata (`packets_in.meta`)
	- run your p4 program on each packet
  - captures output packets (`packets_out.pcap`) and metadata (`packets_out.meta`)
  - captures output log files (`log_cli.txt` and `log_model.txt`)

## Displaying the simulation input packets (optional)

You can display information about the simulated input packets using `capinfos` and `tshark`.

```
capinfos packets_in.pcap
tshark -r packets_in.pcap -O udplb,evio6seg
```

## Display the output packets (optional)

```
capinfos packets_out.pcap
tshark -r packets_out.pcap -O ip,ipv6,udp,udplb,evio6seg -o ip.check_checksum:TRUE -o udp.check_checksum:TRUE
```

# Copyright Notice

ESnet-JLab FPGA Accelerated Transport (data plane) [EJFAT (udplb)] Copyright (c) 2025, Malleable Networks Inc, Apical Networks Inc, and 12574861 Canada Inc. All rights reserved.

If you have questions about your rights to use or distribute this software,
please contact Berkeley Lab's Intellectual Property Office at
IPO@lbl.gov.

NOTICE.  This Software was developed under funding from the U.S. Department
of Energy and the U.S. Government consequently retains certain rights.  As
such, the U.S. Government has been granted for itself and others acting on
its behalf a paid-up, nonexclusive, irrevocable, worldwide license in the
Software to reproduce, distribute copies to the public, prepare derivative 
works, and perform publicly and display publicly, and to permit others to do so.
