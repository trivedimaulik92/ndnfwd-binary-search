ndn_sc: longest name prefix lookup using a single core

## Configuration

- Most configuration options, such as hash function selection, string matching strategy, and prefetching strategy, are listed in `forwarding.h`.

- The `MAX_BLOCK` in `forwarding.c` needs to be updated when larger datasets are used.

- Both `hash_table.c` and `forwarding.h` need to be updated to enable/disable hugepages (via `RTE_HUGEPAGE`).

- The `fwd_info.h` and `forwarding.h` need to be updated when switching between datasets with seven name components and 15 name components.
