# Copyright (c) 2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
"""
Count the number of dentry and negative dentry entries on a filesystem.
Filesystems can be specified by name (dst='<MOUNT POINT>'), by
filesystem type (fstype='<FS TYPE>').
The dentry pointer and filename can optionally displayed when the
verbose arguement is supplied.
"""
import os
from typing import Optional
from typing import Union

from drgn import IntegerLike
from drgn import NULL
from drgn import Path
from drgn import Program

from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.fs import for_each_mount
from drgn.helpers.linux.fs import mount_fstype
from drgn.helpers.linux.fs import mount_dst
from drgn.helpers.linux.fs import mount_src

from drgn_tools.dentry import dentry_path_any_mount
from drgn_tools.list_lru import list_lru_for_each_entry

def count_neg_dentry(
    prog: Program,
    *,
    dst: Optional[Path] = None,
    fstype: Optional[Union[str, bytes]] = None,
    verbose: Optional[IntegerLike] = None,
) -> None:
    """
    Walks the mounted filesystems (optional by mount point or fstype) and
    counts the dentry and negative deentry in the filesytem.
    verbose == 1 returns all negative dentries.
    verbose == 2 returns the dentry and negative dentrry counts per
    NUMA nodeid/memcg.
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
        dcnt = 0
        d_cnt = {}
        d_nid = {}
        d_mcg = {}
        dnegcnt = 0
        d_negcnt = {}
        d_negnid = {}
        d_negmcg = {}
        for nid, memcg, dentry in list_lru_for_each_entry(
            "struct dentry", lru.address_of_(), "d_lru"
        ):
            tpl = (nid, memcg)
            dcnt = dcnt + 1
            if tpl not in d_cnt:
                d_cnt[tpl] = 1
            else:
                d_cnt[tpl] = d_cnt[tpl] + 1
            if nid not in d_nid:
                d_nid[nid] = 1
            else:
                d_nid[nid] = d_nid[nid] + 1
            if memcg not in d_mcg:
                d_mcg[memcg] = 1
            else:
                d_mcg[memcg] = d_mcg[memcg] + 1
            if (dentry.d_inode == NULL(prog, 'struct inode *')) :
                dnegcnt = dnegcnt + 1
                if tpl not in d_negcnt:
                    d_negcnt[tpl] = 1
                else:
                    d_negcnt[tpl] = d_negcnt[tpl] + 1
                if nid not in d_negnid:
                    d_negnid[nid] = 1
                else:
                    d_negnid[nid] = d_negnid[nid] + 1
                if memcg not in d_negmcg:
                    d_negmcg[memcg] = 1
                else:
                    d_negmcg[memcg] = d_negmcg[memcg] + 1
                if verbose == 1:
                    dname = dentry_path_any_mount(dentry)
                    print(f"mntpt {mnt_dst} dentry {hex(dentry)} name {dname}")
        print(f"mntpt {mnt_dst} dentry {dcnt} neg dentries {dnegcnt}")
        if verbose == 2:
            print(f"    dentrys by nid/memcg {d_cnt}")
            print(f"    dentrys by nid {d_nid}")
            print(f"    dentrys by memcg {d_mcg}")
            print(f"    neg dentries by nid/memcg {d_negcnt}")
            print(f"    neg dentrys by nid {d_negnid}")
            print(f"    neg dentrys by memcg {d_negmcg}")
