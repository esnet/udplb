# Install System Prerequisites

Note: Vivado and VitisNet P4 are build tools that are required to
compile udplb. You will need to separately download Vivado and
VitisNet P4 in order to work with this software.

```
sudo pip3 install scapy robotframework
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

# Use robot and the p4bm behavioural model to simulate the p4 pipeline

**Note**: All instructions in this section are relative to the root of the git repo.

Compile the p4 program to
 - use the p4c-vitisnet to compile your p4 program into the IR (`udplb.json`) required by the p4bm simulator

```
make -s -C p4 compile
```

Run the robot test suite to
 - run the p4 behavioural model (p4bm)
 - configure p4 tables
 - generate and inject packets into the p4bm simulator
 - validate the internal p4 pipeline state after each test
 - capture and validate any output packets produced by each test
```
robot \
  --variable P4_HW_ENV:p4bm-sim \
  --pythonpath=esnet-smartnic-hw/test/library/p4_robot_p4bm \
  --pythonpath=esnet-smartnic-hw/test/library/p4_robot \
  --pythonpath=esnet-smartnic-hw/test/library/packet_robot \
  --pythonpath=robot-tests/library/lb_robot \
  --pythonpath=robot-tests/library/packet_lb_robot \
  -d robot-output/ \
  robot-tests/p4-tests.robot
```

The test results are stored under the `robot-output` directory.  A test-specific directory under that tree contains the input and output packets and metadata produced by the test.

## Displaying the simulation input and output packets (optional)

You can display information about the simulated input packets using `capinfos` and `tshark`.

Input packets
``` bash
export TEST_NAME="LB0_Random_UDP_Ports_UDPLBv3_IPv6_Test"

capinfos robot-output/${TEST_NAME}/packets_in.pcap

tshark \
  -X lua_script:protocols/ejfat-stack.lua \
  -r robot-output/${TEST_NAME}/packets_in.pcap \
  -o 'udp.check_checksum:True' \
  -o 'ip.check_checksum:True' \
  -O ejfatlb,ejfatlbv2,ejfatlbv3,e2sarseg
```

Output packets
``` bash
export TEST_NAME="LB0_Random_UDP_Ports_UDPLBv3_IPv6_Test"

capinfos robot-output/${TEST_NAME}/packets_out.pcap

tshark \
  -X lua_script:protocols/ejfat-stack.lua \
  -r robot-output/${TEST_NAME}/packets_out.pcap \
  -o 'udp.check_checksum:True' \
  -o 'ip.check_checksum:True' \
  -O ejfatlb,ejfatlbv2,ejfatlbv3,e2sarseg
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
