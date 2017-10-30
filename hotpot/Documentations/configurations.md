# Hotpot Configurations

All configurable options are within `dsnvm-common.h`, which is shared by both kernel modules and userspace CD. If you want to change the configuration, you `must` change all of the hotpot nodes and CD at the same time. Otherwise an error message will be printed to indicate mismatched configurations.

## Generic Options
### Number of Maximum Hotpot Nodes
Option: `DSNVM_MAX_NODE`  
Expanation: This determins the number of maximum hotpot nodes can be connected at the same time.  

## Data Options
### Data Region Size
Option: `DR_PAGE_NR_SHIFT`  
Explanation: This option determines the size of a data region. Since Hotpot currently only supports 4KB page size, so if you set DR_PAGE_NR_SHIFT to 10, that will make the region size to 4MB. The math is: `Data_Region_Size = PAGE_SIZE * (1 << DR_PAGE_NR_SHIFT)`.  

### Maximum Dataset (File) Size
Option: `DSNVM_MAX_REGIONS_SHIFT`  
Explanation: This option determins the maximum size of a hotpot dataset (or file). A hotpot dataset consists of multiple data regions. And the number of data regions equals to `1 << DSNVM_MAX_REGIONS_SHIFT`. Do note that the file concept is used by hotpot to reuse the posix file APIs.

### Maximum Number of Datasets (Files)
Option: `NR_DSNVM_FILE`  
Explanation: This determins how many hotpot datasets (or files) can be opened at the same time in one machine. Since we target applications that only use a few large datasets, the typical number of datasets should be small.

### Transation Mode
The following code snippt controls what transaction model hotpot is using. The current version only supports one transaction model at one time. We have per-file transaction model which not reliable, so we decide to push it out in next version. To enable MRSW, change `#if 0` to `#if 1`. To enable MRMW, keep `#if 0`.

```c
/**
 * MRSW or MRMW mode bit
 * Comment this out to disable MRSW:
 */
#if 0
#define DSNVM_MODE_MRSW
#define DSNVM_MODE_MRSW_IN_KERNEL
#endif
```

#### MRSW Master Node
Option: `DSNVM_MRSW_MASTER_NODE`  
Explanation: MRSW need a master node to handle all transaction requests. Currently, master node is not allowed to run any transactions. This means if want two hotpot nodes to run transaction, you will have to have three hotpot nodes, one of them is dedicated to be used as master node.
