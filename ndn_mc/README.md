## ndn_mc: longest name prefix lookup with multiple cores

## Scripts

- `run.sh`: 1 worker thread runs on core 2

  Usage: `sudo ./run.sh trace_file_name number_of_name_prefixes`

  Example: `sudo ./run.sh ../traces/7comp_1k 1000`

- `run2.sh`: 2 worker threads run on core 4 and 6

- `run4.sh`: 4 worker threads run on core 4, 6, 8, 10

- `run4_2.sh`: 4 worker threads run on core 3, 5, 7, 9

- `run8.sh`: 8 worker threads run on core 3, 4, 5, 6, 7, 8, 9, 10
