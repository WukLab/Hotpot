# KNOWN-ISSUES

Last Updated: 02/03/2018

# Hotpot-kernel
This section describes issues related to hotpot-kernel, our modified version of `Linux 3.11.1` kernel.

## [1.1] Fail to boot with XFS
We found hotpot-kernel fail to boot when `XFS` is used as the root filesystem. The message printed by kernel indicates there is an issue related to `XFS`. We also found vanilla `Linux-3.11.1` kernel will fail at the same place. Since our modification to the vanilla kernel is limited to several VM related code, this issue is not introduced by us, it is an issue related to `Linux-3.11.1` itself.

Currently, the only working setting we know of is to boot hotpot-kernel with `ext4`. We still can't find a solution to solve this. Sorry for the inconvenience.
