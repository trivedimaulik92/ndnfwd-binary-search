ndnfwd-binary-search
=============================================

## Overview

ndnfwd-binary-search is a longest name prefix lookup engine runs on general purpose
multicore platforms using [DPDK](http://www.dpdk.org) as the underlying packet IO
and multicore framework.

This repository includes:

- ndn_sc: longest name prefix lookup using a single core.
- ndn_mc: longest name prefix lookup using multiple cores.
- ndn: longest name prefix lookup with real network traffic.
- pktgen: modified based on [Pktgen-DPDK](https://github.com/Pktgen/Pktgen-DPDK/) to generates packets that carry names.
- traces: contains sample testing traces.

## Requirements

DPDK version 1.7.1

## Build

- Build DPDK, as explained in http://dpdk.org/doc/guides/linux_gsg/build_dpdk.html

- Configure large pages
  - Edit the `/etc/default/grub` file to configure large pages
  - Run 'sudo update-grub' and then reboot the machine
  - Mount the huge pages by running `mkdir /mnt/huge` and `sudo mount -t hugetlbfs nodev /mnt/huge`
  - Load the kernel module by running `sudo modprobe uio` and `sudo insmod build/kmod/igb_uio.ko`
  - Bind the device to the driver using the `dpdk_nic_bind.py` program provided by DPDK

- Build the ndnfwd application
  ```
  export RTE_SDK=$HOME/DPDK
  export RTE_TARGET=x86_64-native-linuxapp-gcc
  make
  ```

  - Reference: http://dpdk.org/doc/guides/linux_gsg/build_sample_apps.html

## Issue Report

Please report issues via [github](https://github.com/WU-ARL/ndnfwd-binary-search/issues) or email at hyuan@wustl.edu.
