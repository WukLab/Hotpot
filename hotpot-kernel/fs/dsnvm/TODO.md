Things we MUST do for open source:

## CD Heartbeat Messages
We said in the paper that CD will send heartbeat messages to Hotpot node
periodically to detect node failure.

## CD Replication
We said in the paper that CD's metadata can be reconstructed from all the other
hotpot nodes, this is hard, right? We don't we use ZooKeeper to replicate CD's
medadata, which will be much easier and people will not question about this.

## `dsnvm_xact_log`
Currently, `dsnvm_xact_log` is reusing the buffers from IB, and store that
virtual addresses into log. However, this is not acceptable and is BUG.
We MUST allocate pages in NVM and store the allocated addresses into the log.
