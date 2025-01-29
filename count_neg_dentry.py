# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
import os
from typing import Optional, Union

from drgn import Path, NULL, Program, IntegerLike
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.fs import for_each_mount, mount_src, mount_dst, mount_fstype
from list_lru import list_lru_for_each_entry

def count_new_dentry(
    prog: Program,
    *,
    dst: Optional[Path] = None,
    fstype: Optional[Union[str, bytes]] = None,
    verbose: Optional[IntegerLike] = None,
) -> None:
    """
    Walks the mounted filesystems (optional by mount point or fstype) and
    counts the dentry and negative deentry in the filesytem,
    Uses proposed drgn-tool list_lru module.
    """
    for mnt in for_each_mount(
        prog,
        src=None,
        dst=dst,
        fstype=fstype,
    ):
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        sb = mnt.mnt.mnt_sb
        lru = sb.s_dentry_lru
        d_cnt = 0
        d_negcnt = 0
        for dentry in list_lru_for_each_entry(
            prog, "struct dentry", lru.address_of_(), "d_lru"
                    ):
            d_cnt = d_cnt + 1
            if (dentry.d_inode == NULL(prog, 'struct inode *')) :
                d_negcnt = d_negcnt + 1
        print(f"mntpt {mnt_dst} dentry {d_cnt} neg dentries {d_negcnt}")
