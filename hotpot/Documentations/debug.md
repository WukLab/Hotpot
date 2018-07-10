# Hotpot Debug/Trace Options
This file describes how applications writers can debug and trace various activies within Hotpot. All Hotpot's runtime information is exported through two `/proc` files. Generic information is expored through `/proc/dsnvm`, and various events counting are exported through `/proc/dsnvm-event`(Love this feature!). You are also able to control Hotpot internal behaviour by writing to `/proc/dsnvm`.

## /proc/dsnvm
### Generic Information
This file export three different kind of information. The first is `generic system information`, the second is `transaction runtime information`, and the last part presents information of `persiste memory allocator`. It is highly recommened to check the `DSNVM Local ID`, `Region size`, `DSNVM file size`, `Transaction Model` during each run, to see if those match your expectations.

For example, `cat /proc/dsnvm`:
```
Online Clients:            1-2
NR of Online Clients:      2
DSNVM Local ID:            1
Region size:               4 MB
Regions per file:          2048
DSNVM file size:           8 GB
Total NVM pages:           1048576
+ NVM pages for metadata:  69168
   -pages for map:         14336
   -pages for filemap:     51961
   -pages for logmap:      257
   -pages for onmap:       1837
   -pages for replicamap:  777
+ Usable NVM pages:        979408
Entries of wait table:     4096
Bits of wait table:        12
Barrier Counter:           0
PFN range:               [       1048576 -       2097152]
DSNVM_PFN range:         [             0 -       1048576]
Physical range:          [ 0x0000000100000000 - 0x0000000200000000 ]
Virtual range:           [ 0xffffc9002a013000 - 0xffffc9012a013000 ]
Transaction Model:         Multiple Readers Multiple Writers (MRMW)
CPU has PCOMMIT:           No
CPU has CLWB:              No
CPU has CLFLUSH_OPT:       No
DSNVM State:               Normal Context
Migration:                 off

------ Active Log Info ------
Active log list:

------ Replica Region Info ------
Replica_Region list:
Index    DR_NO    FLAG    OWNER_ID    PF-NODE01    PF-NODE02

------ Owner Region Info ------
Owner_Region list:
DR_NO  FLAG  PGX  PF01  Commit01  Commit-B01  PF02  Commit02  Commit-B02

------ DSNVM Buddy Allocator ------
nr_total_pages: 979408
nr_free_pages:  979408

  Free Area lists:
           nr_free_areas
Order 0                0
Order 1                0
Order 2           244852

  PCP Lists:
         Batch    High    Count
CPU00       31     186        0
CPU01       31     186        0
....
```

### Control
We build a write handler for `/proc/dsnvm`, and users are able to control Hotpot via writing commands to it. A detailed list of commands can be found [here](https://github.com/WukLab/Hotpot/blob/master/hotpot/proc.c#L342). Here we list some simple ones:

```
/*
 * echo dbgmask=1 > /proc/dsnvm
 * 	Change dbgmask to 1
 *
 * echo dump_pg=12340 > /proc/dsnvm
 * 	Dump dsnvm page info of dsnvm_pfn 12340
 *
 * echo dbgmask=64,migrate,dr_no=3,nid=2 > /proc/dsnvm
 *	Change dbgmask to 64, migrate ON chunk dr_no 3 to node 2
 */
```

## /proc/dsnvm-event
This file exports different kinds of events happening within Hotpot. Events are grouped together to ease reading. For example, VM stats group records all virtual memory related activies, XACT groups presents all transaction related details. Most of the lines self explain the meaning.

For example, `cat /proc/dsnvm-event`:
```
------ VM Stats ------: 0
nr_page_fetch_retry: 0
pgfault (total): 0
pgfault (read): 0
pgfault (write): 0
....
------ Replica ------: 0
REPLICA_REGION created: 0
------ ON ------: 0
ON_REGION created: 0
page-fetch (total): 0
page-fetch (non-coherent): 0
page-fetch (coherent): 0
------ Swap ------: 0
kswapdrun: 0
directrun: 0
pgreclaim_kswapd: 0
...
------ IB ------: 0
IB Requests (total): 1
IB Requests (send): 0
...
------ XACT ------: 0
nr_commit: 0
nr_mrsw_commit: 0
nr_mrmw_commit: 0
....
------ Migration ------: 0
migratedrun: 39
nr_regions_migrated_out: 0
nr_pages_migrated_out: 0
.....

```
