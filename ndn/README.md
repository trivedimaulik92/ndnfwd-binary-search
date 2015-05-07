## ndn: longest name prefix lookup with real network traffic

## Scripts

- Similar as in `ndn_mc`, scripts are provided to help run the experiments.

- `run.sh`: one worker thread runs on core 2, one IO thread runs on core 0

  Usage: `sudo ./run.sh trace_file_name number_of_name_prefixes`

  Example: `sudo ./run.sh ../traces/7comp_1k 1000`

- `run2.sh`: two worker threads run on core 4 and 6, one IO thread runs on core 2

- `run2_rss.sh`: two worker threads run on core 4 and 6, two IO threads run on core 0 and 2, packets are sent to core 0 and 2 using the multiqueue feature available on the NIC.

## Traffic generation

- Modify the `../pktgen/app/pktgen-main.c` source file to specify the lookup file name
