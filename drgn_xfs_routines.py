# Copyright (c) 2024,2025, Oracle and/or its affiliates.
# Licensed under the Universal Permissive License v 1.0 as shown at https://oss.oracle.com/licenses/upl/
#
#  The XFS drgn routine catagories:
#    inode fork extent walking.
#     this could be extended to compare COW and data forks
#    busy extents in per AG and in a transaction
#     the CIL code also displays the busy extents in the delay log
#    simple XFS mount points
#     displays the xfs_mount for each XFS
#       for_each_mount() args are different for Linux 3.10 vrs 4.14
#       so, I used the most common version.
#    XFS log delay log (CIL) and AIL
#     These are huge dump and would be advance user calls
#     Print the iclog state and tail lsn (converted from big endian)
#     The CIL also dumps all the CTX (push contexts) that are outstanding
#      and also the busy extents in the CTX
#    Misc -- ignore the buffer code, not working with Linux 4.14 because
#      bt_lru uses a different kind of list (list_lru)
#     print all the active xfs_inodes and xfs_buf that are active
#      (huge dump). The idea is if I am looking for a kind of inode or
#      buffer. I still have not decided what to print for information
#      or if these are just templates.
#

import os
from ctypes import c_uint64
from stat import S_ISREG, S_ISDIR, S_ISLNK
from typing import Optional

from drgn import cast, Path, container_of, NULL, Object, Program
from drgn.helpers.common.format import escape_ascii_string
from drgn.helpers.linux.cpumask import for_each_online_cpu
from drgn.helpers.linux.fs import for_each_mount, mount_src, mount_dst
from drgn.helpers.linux.list import list_empty, list_for_each_entry
from drgn.helpers.linux.mm import decode_page_flags, page_to_virt, page_to_phys
from drgn.helpers.linux.percpu import per_cpu_ptr
from drgn.helpers.linux.radixtree import radix_tree_for_each
from drgn.helpers.linux.rbtree import rbtree_inorder_for_each_entry

from drgn_tools.util import has_member
from drgn_tools.list_lru import list_lru_for_each_entry

__all__ = (
    "xfs_init_iext_cur",
    "xfs_iext_find_first_leaf",
    "xfs_iext_first",
    "xfs_iext_find_last_leaf",
    "xfs_iext_last",
    "xfs_iext_valid",
    "xfs_iext_next",
    "xfs_iext_prev",
    "xfs_iext_find_level",
    "xfs_iext_get",
    "xfs_iext_lookup_extent",
    "xfs_iext_get_extent",
    "xfs_print_perag",
    "xfs_print_extents",
    "xfs_trans_busy_extents",
    "xfs_print_all_perags",
    "xfs_print_mounts",
    "xfs_print_log_item",
    "xfs_print_ail",
    "xfs_print_all_ails",
    "xfs_print_cil_ctx",
    "xfs_print_cil",
    "xfs_print_all_cils",
    "xfs_print_iclog",
    "xfs_print_all_iclogs",
    "xfs_print_xlog",
    "xfs_print_all_xlogs",
    "xfs_print_sb_inode",
    "xfs_print_all_inodes",
    "xfs_print_bufs",
    "xfs_print_all_bufs",
)

# --- XFS inode fork extent routines
# Inode extent cursor
class XFS_iext_cursor:
    def __init__(self, leaf, pos) :
        self.leaf = leaf
        self.pos = pos

# Inode internal bmbt extent record
class XFS_bmbt_irec :
    def __init__(self, soff, sblk, bcnt, state) :
        self.br_startoff = soff
        self.br_startblock = sblk
        self.br_blockcount = bcnt
        self.br_state = state

# create a new, empty extent cursor
def xfs_init_iext_cur(prog: Program) -> Object :
    """
    Initalize a new cursor.

    :param prog: Kernel being debugged
    :returns: cursor Object
    """
    return XFS_iext_cursor(Object(prog, "struct xfs_iext_leaf *", 0), 0)


KEYS_PER_NODE = 16  # 256 / (sizeof(uint64_t) + sizeof(void *))
RECS_PER_LEAF = 15  # (256 - (2 * sizeof(*)) / sizeof(struct xfs_iext_rec)

# find the lowest startoff leaf
def xfs_iext_find_first_leaf(prog: Program, ifp: Object) -> Object :
    """
    Return the lowest offset xfs_ifork internal extent btree leaf

    :param prog: Kernel being debugged
    :param ifp: ``struct xfs_ifork *``
    :returns: ``struct xfs_iext_leaf *`` Object
    """
    # uek7 and before have if_u1 union
    if has_member(ifp, "if_u1") :
        iroot = ifp.if_u1.if_root
    else :
        iroot = ifp.if_data
    node = cast("struct xfs_iext_node *", iroot)
    if ifp.if_height == 0:
      return Object(prog, "struct xfs_iext_leaf *", 0)
    # loop through the lowest non-leaf nodes
    for i in range(ifp.if_height-1) :
        node = cast("struct xfs_iext_node *", node.ptrs[0])
    return Object(prog, "struct xfs_iext_leaf *", node)

# set the cursor to the first extent
def xfs_iext_first(prog: Program, ifp: Object, cur: Object) -> None :
    """
    Set cur to point to the lowest offset extent

    :param prog: Kernel being debugged
    :param ifp: ``struct xfs_ifork *``
    :param cur: Cursor will return first extent
    """
    cur.leaf = xfs_iext_find_first_leaf(prog, ifp)
    cur.pos = 0

# find the highest startoff leaf
def xfs_iext_find_last_leaf(prog: Program, ifp: Object) -> Object :
    """
    Return the largest offset xfs_ifork internal extent btree leaf

    :param prog: Kernel being debugged
    :param ifp: ``struct xfs_ifork *``
    :returns: ``struct xfs_iext_leaf`` Object
    """
    # uek7 and before have if_u1 union
    if has_member(ifp, "if_u1") :
        iroot = ifp.if_u1.if_root
    else :
        iroot = ifp.if_data
    node = cast("struct xfs_iext_node *", iroot)
    if ifp.if_height == 0:
      return Object(prog, "struct xfs_iext_leaf *", 0)
    # loop through the entries to find the last non-zero entry in non-leaf
    for h in range(ifp.if_height-1) :
        i = 1
        stop = 0
        while i < KEYS_PER_NODE and stop == 0:
            if node.ptrs[i] == NULL(prog, "void *") :
                stop = 1
            else :
                i = i + 1
        node = cast("struct xfs_iext_node *", node.ptrs[i-1])
    return Object(prog, "struct xfs_iext_leaf *", node)

# set the cursor to the last extent
def xfs_iext_last(prog: Program, ifp: Object, cur: Object) -> None :
    """
    Set cur to point to the highest offset extent

    :param prog: Kernel being debugged
    :param ifp: ``struct xfs_ifork *``
    :param cur: Cursor will return last extent
    """
    cur.leaf = xfs_iext_find_last_leaf(prog, ifp)
    # Error finding the highest offset leaf
    if cur.leaf == NULL(prog, "void *") :
        cur.pos = 0
        return
    # look for the last valid entry in this leaf
    if ifp.if_height == 1 :
        maxrec = ifp.if_bytes / 0x10
    else :
        maxrec = RECS_PER_LEAF
    maxrec = maxrec - 1
    for i in range(maxrec) :
        rec = cur.leaf.recs[i+1]
        # first non-valid entry, use the entry before this one
        if rec.hi == 0 :
            cur.pos = i
            return
    cur.pos = i

# Does the cursor point to a legal extent
def xfs_iext_valid(prog: Program, ifp: Object, cur: Object) -> bool :
    """
    Return True if the cur points to a valid extent

    :param prog: Kernel being debugged
    :param ifp: ``struct xfs_ifork *``
    :param cur: Cursor being tested
    :returns: validity of cursor item
    """
    # invalid leaf ptr
    if cur.leaf == NULL(prog, "void *") :
        return False
    # look for invalid pos
    if ifp.if_height == 1 :
        maxrec = ifp.if_bytes / 0x10
    else :
        maxrec = RECS_PER_LEAF
    if cur.pos < 0 or cur.pos >= maxrec :
        return False
    # look for an invalid record (0 length)
    rec = cur.leaf.recs[cur.pos]
    if rec.hi == 0 :
        return False
    return True

# Advance cursor to next extent. cur may be invalid at end of extent list
def xfs_iext_next(prog: Program, ifp: Object, cur: Object) -> None :
    """
    Advance the cursor to next extent.
    May return an invalid cursor.

    :param prog: Kernel being debugged
    :param ifp: ``struct xfs_ifork *``
    :param cur: attempt to advance the cursor to next extent
    :returns: the cursor points to a valid extent after advance
    """
    if cur.leaf == NULL(prog, "void *") :
        xfs_iext_first(prog, ifp, cur)
        return
    # add one to the pos and go to the next leaf on overflow
    cur.pos = cur.pos + 1
    if (ifp.if_height > 1 and xfs_iext_valid(prog, ifp, cur) == False and
            cur.leaf.next != NULL(prog, "void *")) :
        cur.leaf = cur.leaf.next
        cur.pos = 0

# Advance cursor to the previous extent. cur may be invalid
def xfs_iext_prev(prog: Program, ifp: Object, cur: Object) -> None :
    """
    Advance the cursor to previous extent.
    May return an invalid cursor.

    :param prog: Kernel being debugged
    :param ifp: ``struct xfs_ifork *``
    :param cur: attempt to advance the cursor back one extent
    :returns: the cursor points to a valid extent after moving cursor back
    """
    if cur.leaf == NULL(prog, "void *") :
        xfs_iext_last(prog, ifp, cur)
        return
    # subtract one from pos and go to end  of previous leaf looking for
    # first valid entry
    while True :
        while cur.pos > 0 :
            cur.pos = cur.pos - 1
            if xfs_iext_valid(prog, ifp, cur) == True :
                return
        if ifp.if_height > 1 and cur.leaf.prev != NULL(prog, "void *") :
            cur.leaf = cur.leaf.prev
            cur.pos = RECS_PER_LEAF
        else :
            return

# Locate the leaf holding the requested startoff
def xfs_iext_find_level(prog: Program, ifp: Object, offset: int) -> Object :
    """
    Return the leaf of btree that holds the offset

    :param prog: Kernel being debugged
    :param ifp: ``struct xfs_ifork *``
    :param offset: start offset of extent
    :returns: ``struct xfs_iext_leaf`` Object
    """
    # uek7 and before have if_u1 union
    if has_member(ifp, "if_u1") :
        iroot = ifp.if_u1.if_root
    else :
        iroot = ifp.if_data
    node = cast("struct xfs_iext_node *", iroot)
    if ifp.if_height == 0:
      return Object(prog, "struct xfs_iext_node *", 0)
    for height in range(ifp.if_height-1) :
        i = 1
        while i < KEYS_PER_NODE :
            if node.keys[i] > offset :
                break
            i = i + 1
        node = cast("struct xfs_iext_node *", node.ptrs[i - 1])
        if node == NULL(prog, "void *") :
            break
    return Object(prog, "struct xfs_iext_leaf *", node)

# Convert the internal extent into a bmbt record
def xfs_iext_get(prog: Program, irec: Object, rec: Object) -> None :
    """
    Convert the internal extent to a bmbt extent type

    :param prog: Kernel being debugged
    :param irec: Return bmbt irec Object updated
    :param rec: ``struct xfs_iext_rec *``
    """
    irec.br_startoff = rec.lo & 0x3fffffffffffff
    irec.br_blockcount = rec.hi & 0x1fffff
    irec.br_startblock = rec.lo >> 54
    irec.br_startblock |= (rec.hi & 0xfffffc0000000000) >> (22 - 10)
    if rec.hi & 0x200000 :
        irec.br_state = 1
    else :
        irec.br_state = 0
    return

# Set the cur and bmbt to the extent at offet
def xfs_iext_lookup_extent(prog: Program, ifp: Object, offset: int, cur: Object, bmbt: Object) -> bool :
    """
    Return the node of btree that is equal or greater to the requested offset
    Return True if found a valid entry

    :param prog: Kernel being debugged
    :param ifp: ``struct xfs_ifork *``
    :param offset: start offset of extent
    :param cur: Update the Cursor object
    :param bmbt: update bmbt irec Object
    :returns: true if an extent is found at or beyond the offset
    """
    cur.leaf = xfs_iext_find_level(prog, ifp, offset)
    # check for no extents
    if cur.leaf == NULL(prog, "void *") :
        cur.pos = 0
        return False
    # in the correct leaf, now find the entry
    if ifp.if_height == 1 :
        maxrec = ifp.if_bytes / 0x10
    else :
        maxrec = RECS_PER_LEAF
    for cur.pos in range(maxrec) :
        rec = cur.leaf.recs[cur.pos]
        if rec.hi == 0 :
            break
        rec_startoff = rec.lo & 0x3fffffffffffff
        rec_length = rec.hi & 0x1fffff
        if (rec_startoff > offset) or (rec_startoff + rec_length) > offset :
            xfs_iext_get(prog, bmbt, cur.leaf.recs[cur.pos])
            return True
    # no entry greater than or equal to offset, look for a greater offset
    # in the next higher leaf
    if (ifp.if_height == 1) or (cur.leaf.next == NULL(prog, "void *")) :
        return False
    cur.leaf = cur.leaf.next
    cur.pos = 0
    if xfs_iext_valid(prog, ifp, cur) == False :
        return False
    xfs_iext_get(prog, bmbt, cur.leaf.recs[cur.pos])
    return True

# If the cursor is valid then return the extent in bmbt
def xfs_iext_get_extent(prog: Program, ifp: Object, cur: Object, bmbt: Object) -> bool :
    """
    If the cursor is valid then return the extent in bmbt.
    Return True if the cursor points to a valid extent.

    :param prog: Kernel being debugged
    :param ifp: ``struct xfs_ifork *``
    :param cur: cursor points to item
    :param bmbt: update bmbt irec Object
    :returns: true if the extent is valid
    """
    # make sure the cursor points to a valid extent
    if xfs_iext_valid(prog, ifp, cur) == False :
        return False
    # return the extent pointed by cursor in bmbt
    xfs_iext_get(prog, bmbt, cur.leaf.recs[cur.pos])
    return True

# walk the entire extent list
def xfs_print_extents(prog: Program, ifp: Object) -> None :
    """
    My walking the extent list loop

    :param ifp: ``struct xfs_ifork *``
    """
    cur = xfs_init_iext_cur(prog)
    bmbt = XFS_bmbt_irec(0, 0, 0, 0)
    offset = 0
    hole = 0
    cont = True
    # start at offset 0 and add the previous length to the offset
    cont = xfs_iext_lookup_extent(prog, ifp, offset, cur, bmbt)
    while cont == True :
        if offset != bmbt.br_startoff :
            hole = bmbt.br_startoff - offset
            print(f"hole soff {offset} cnt {hole}")
        print(f"soff {bmbt.br_startoff.value_()} sblk {bmbt.br_startblock.value_()} cnt {bmbt.br_blockcount.value_()} state {bmbt.br_state}")
        # calculate the next extent to see if there is a hole
        offset = bmbt.br_startoff + bmbt.br_blockcount
        # use the cursor to find next extent
        xfs_iext_next(prog, ifp, cur)
        cont = xfs_iext_get_extent(prog, ifp, cur, bmbt)

# --- XFS Busy extent per AG and transaction
# --- The LOG code has the CIL Busy extents.
def xfs_print_perag(prog: Program, perag: Object, verbose=None) -> None :
    """
    Print the busy extents for the specified xfs perag

    :param prog: Kernel being debugged
    :param perag ``struct xfs_perag *``
    """
    # uek7 and before
    if has_member(perag, "pag_agno") :
        agno = perag.pag_agno
    else :
        agno = perag.pag_group.xg_gno
    print(f"xfs_perag: 0x{perag.value_():x} agno: {agno.value_()} flcnt: {perag.pagf_flcount.value_()} freeblks: {perag.pagf_freeblks.value_()}")
    # print the inodes know to the AG
    if verbose == 2 :
        for _, ino in radix_tree_for_each(perag.pag_ici_root.address_of_()) :
            ip = cast("struct xfs_inode *", ino)
            print(f"xfsino 0x{ip.value_():x} inum 0x{ip.i_ino.value_():x} iflgs 0x{ip.i_flags.value_():x}")
    # print the busy extents for this AG
    if verbose is not None :
        # uek7 and before
        if has_member(perag, "pagb_tree") :
            for bext in rbtree_inorder_for_each_entry(
                "struct xfs_extent_busy",
                perag.pagb_tree.address_of_(),
                "rb_node",
            ):
                # uek7 and before
                if has_member(bext, "agno") :
                    bagno = bext.agno
                else :
                    bagno = bext.group.xg_gno
                print(f"agno: {bagno.value_()} agbno: {bext.bno.value_()} len: {bext.length.value_()} flgs: {bext.flags.value_()}")
        else :
            print(f"fix the new code")

# walk a transaction"s busy_extent list
def xfs_trans_busy_extents(prog: Program, trans: Object) -> None :
    """
    Print the busy extents for the specified xfs transaction

    :param prog: Kernel being debugged
    :param trans: ``struct xfs_trans *``
    """
    for bext in list_for_each_entry("struct xfs_extent_busy",
      trans.t_busy.address_of_(), "list") :
        # uek7 and before
        if has_member(bext, "agno") :
            bagno = bext.agno
        else :
            bagno = bext.group.xg_gno
        print(f"agno: {bagno.value_()} agbno: {bext.bno.value_()} len: {bext.length.value_()} flgs: {bext.flags.value_()}")

#
def xfs_print_all_perags(prog: Program, dst: Optional[Path]=None, verbose=None) -> None :
    """
    Print the xfs ail of a given namespace. The arguments are the same
    as :func:`for_each_mount()`.

    :param prog: Kernel being debugged
    :param dst: Optional mount point
    """
    for mnt in for_each_mount(prog, dst = dst, fstype = "xfs") :
        mnt_src = escape_ascii_string(mount_src(mnt), escape_backslash=True)
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        mp = cast("struct xfs_mount *", mnt.mnt.mnt_sb.s_fs_info)
        print(
          f"{mnt_src} {mnt_dst} ({mp.type_.type_name()})0x{mp.value_():x}")
        # uek7 and before have m_perag_tree
        if has_member(mp, "m_perag_tree") :
            xa = mp.m_perag_tree
        else :
            # uek8 has m_perags
            if has_member(mp, "m_perags") :
                xa = mp.m_perags
            else :
                xa = mp.m_groups[0].xa
        for _, entry in radix_tree_for_each(xa.address_of_()) :
            m_perag = cast("struct xfs_perag *", entry)
            if not m_perag.value_() :
                continue
            xfs_print_perag(prog, m_perag, verbose)

# --- XFS Mounts
# list the mount point information for XFS filesystems
# taken from the mounts code
def xfs_print_mounts(prog: Program, dst: Optional[Path] = None) -> None :
    """
    Print all or selected xfs device, mount point and xfs_mount pointer.
    :param prog: Kernel being debugged
    :param dst: Optional mount point
    """
    for mnt in for_each_mount(prog, dst = dst, fstype = "xfs") :
        mnt_src = escape_ascii_string(mount_src(mnt), escape_backslash=True)
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        mp = cast("struct xfs_mount *", mnt.mnt.mnt_sb.s_fs_info)
        print(
          f"{mnt_src} {mnt_dst} ({mp.type_.type_name()})0x{mp.value_():x}")

# --- XFS buffers
# print fields on a xfs_buf. Used by buf log item and buffer printing
def xfs_print_verbose_buf(prog: Program, bp: Object) -> None :
    """
    Verbose print of a XFS buf

    :param prog: Kernel being debugged
    :param bp: ``struct xfs_buf *``:
    """
    # uek8 and before
    if has_member(bp.b_pag, "pag_agno") :
        agno = bp.b_pag.pag_agno
    else :
        agno = bp.b_pag.pag_group.xg_gno
    # uek7 and before
    if has_member(bp, "bp.b_bn") :
        print(f"bp 0x{bp.value_():x} bno 0x{bp.b_bn.value_():x} flgs 0x{bp.b_flags.value_():x} ag {agno.value_()}")
    else :
        print(f"bp 0x{bp.value_():x} bno 0x{bp.b_maps[0].bm_bn.value_():x} flgs 0x{bp.b_flags.value_():x} ag {agno.value_()}")
    # look for magic xfs_bug b_addr data
    if bp.b_addr != NULL(prog, "void *") :
        p = cast("char  *", bp.b_addr)
        # Look for a upper or lower case letter for "magic"
        if ((p[0].value_() >= 65 and p[0].value_() <= 90) or
            (p[0].value_() >= 97 and p[0].value_() <= 122)) :
            print(f"{p}")

# Print all the LRU bufs in the buftarg for Linux 4.14.
# May need a for_each_lru_entry MM helper, I forced it for now.
def xfs_print_bufs(prog: Program, mp: Object) -> None :
    """
    Print all the active inodes for a XFS filesystem

    :param prog: Kernel being debugged
    :param mp: ``struct xfs_mount *``:
    """
    btarg = mp.m_ddev_targp
    lru = btarg.bt_lru
    for _, _, bp in list_lru_for_each_entry(
        "struct xfs_buf", lru.address_of_(), "b_lru"
    ):
        # check to make sure this buffer is really for this device
        if bp.b_target == btarg :
            xfs_print_verbose_buf(prog, bp)

# Iterate over all the XFS mounts and print LRU cached xfs_buf
def xfs_print_all_bufs(prog: Program, dst: Optional[Path]=None) -> None :
    """
    Print the xfs ail of a given namespace. The arguments are the same
    as :func:`for_each_mount()`.

    :param prog: Kernel being debugged
    :param dst: Optional mount point
    """
    for mnt in for_each_mount(prog, dst = dst, fstype = "xfs") :
        mnt_src = escape_ascii_string(mount_src(mnt), escape_backslash=True)
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        mp = cast("struct xfs_mount *", mnt.mnt.mnt_sb.s_fs_info)
        print(
          f"{mnt_src} {mnt_dst} ({mp.type_.type_name()})0x{mp.value_():x}")
        xfs_print_bufs(prog, mp)

# --- XFS LOG (AIL and CIL)
def xfs_print_log_item(prog: Program, li: Object, verbose=None) -> None :
    """
    Print a log_item by type

    :param prog: Kernel being debugged
    :param li: ``struct xfs_log_item *``
    :param verbose: Verbose printing
    """
#       match/case statements require Python 3.10
    if li.li_type == 0x1236:
        eli = cast("struct xfs_efi_log_item *", li)
        print(f"0x1236 efi log item efi 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            efi = eli.efi_format
            print(f"next 0x{efi.efi_nextents.value_():x} eid 0x{efi.efi_id.value_():x}")
            for i in range(efi.efi_nextents) :
                efp = efi.efi_extents[i]
                print(f"start 0x{efp.ext_start.value_():x} len 0x{efp.ext_len.value_():x}")
    #
    if li.li_type == 0x1237:
        eld = cast("struct xfs_efd_log_item *", li)
        print(f"0x1237 efd log item efd 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            efd = eld.efd_format
            print(f"next 0x{efd.efd_nextents.value_():x} eid 0x{efd.efd_efi_id.value_():x}")
            for i in range(efd.efd_nextents) :
                efp = efd.efd_extents[i]
                print(f"start 0x{efp.ext_start.value_():x} len 0x{efp.ext_len.value_():x}")
    #
    if li.li_type == 0x1238:
        print(f"0x1238 unlink log item 0x{li.value_():x lsn 0x{li.li_lsn.value_():x}}")
    #
    if li.li_type == 0x123b:
        ili = cast("struct xfs_inode_log_item *", li)
        print(f"0x123b inode log item 0x{li.value_():x} inode: 0x{ili.ili_inode.value_():x} inun 0x{ili.ili_inode.i_ino.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            print(f"ili_fields 0x{ili.ili_fields.value_():x}")
    #
    if li.li_type == 0x123c:
        bli = cast("struct xfs_buf_log_item *", li)
        print(f"0x123c buf log item buf 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            xfs_print_verbose_buf(prog, bli.bli_buf)
            blf = bli.bli_formats
            print(f"0x123c buf log item len 0x{blf.blf_len.value_():x} mpsz 0x{blf.blf_map_size.value_():x}")
            for i in range(blf.blf_map_size) :
                print(f"map[{i}] 0x{blf.blf_data_map[i].value_():x}")
    #
    if li.li_type == 0x123d:
        qli = cast("struct xfs_dq_logitem *", li)
        print(f"0x123d dquot log item 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            dqut = qli.qli_dquot
            print("type 0x{dqut.q_type.value_():x} id 0x{dqut.q_id.value_():x} blkno 0x{dqut.q_blkno.value_():x} foff 0x{dqut.fileoffset.value_():x}")
    #
    if li.li_type == 0x123e:
        print(f"0x123e quotaoff log item 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
    #
    if li.li_type == 0x123f:
        print(f"0x123f icreate log item 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            icli = cast("struct xfs_icreate_item *", li)
            icl = icli.ic_format
            print(f"ag {icl.icl_ag} agbno 0x{icl.icl_agbno.value_():x} cnt 0x{icl.icl_count.value_():x} isz 0x{icl.icl_isize.value_():x} len 0x{icl.icl_length.value_():x} gen 0x{icl.icl_gen.value_():x}")
    #
    if li.li_type == 0x1240:
        print(f"0x1240 rui log item 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            rui = cast("struct xfs_rui_log_item *", li)
            print(f"refcnt 0x{rui.rui_refcount.value_():x} next 0x{rui.rui_format.bui_nextents.value_():x}")
            ruf = rui.rui_format
            for i in range(ruf.rui_nextents) :
                emp = ruf.rui_extents[i]
                print(f"owner 0x{emp.me_owner.value_():x} sblk 0x{emp.me_startblock.value_():x} soff 0x{emp.me_startoff.value_():x} len 0x{emp.me_len.value_():x} flgs 0x{emp.me_flags.value_():x}")
    #
    if li.li_type == 0x1241:
        print(f"0x1241 rud log item 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            rud = cast("struct xfs_rud_log_item *", li)
            ruf = rud.rud_format
            print(f"rid 0x{ruf.rud_rui_id.value_():x}")
    #
    if li.li_type == 0x1242:
        print(f"0x1242 cui log item 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            cui = cast("struct xfs_cui_log_item *", li)
            cuf = cui.cui_format
            print(f"next 0x{cuf.cui_nextents.value_():x} cid 0x{cuf.cui_id.value_():x}")
            for i in range(cuf.cui_nextents) :
                cpe = cui.cui_extents[i]
                print(f"sblk 0x{cpe.pe_startblock.value_():x} len 0x{cpe.pe_len.value_():x} flgs 0x{cpe.pe_flags.value_():x}")
    #
    if li.li_type == 0x1243:
        print(f"0x1243 cud log item 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            cud = cast("struct xfs_cud_log_item *", li)
            cuf = cud.cud_format
            print(f"cid 0x{cuf.cud_cui_id.value_():x}")
    #
    if li.li_type == 0x1244:
        print(f"0x1244 bui log item 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            bui = cast("struct xfs_bui_log_item *", li)
            buf = bui.bui_format
            print(f"next 0x{buf.bui_nextents.value_():x} bid 0x{buf.bui_id.value_():x}")
            for i in range(buf.bui_nextents) :
                emp = bui.bui_format.bui_extents[i]
                print(f"owner 0x{emp.me_owner.value_():x} sblk 0x{emp.me_startblock.value_():x} soff 0x{emp.me_startoff.value_():x} len 0x{emp.me_len.value_():x} flgs 0x{emp.me_flags.value_():x}")
    #
    if li.li_type == 0x1245:
        print(f"0x1245 bud log item 0x{li.value_():x} lsn 0x{li.li_lsn.value_():x}")
        if verbose is not None :
            bud = cast("struct xfs_bud_log_item *", li)
            print(f"bid 0x{bui.bui_format.bud_bui_id.value_():x} lsn 0x{li.li_lsn.value_():x}")

def xfs_print_ail(prog: Program, ail: Object, verbose=None) -> None :
    """
    Print the AIL of the filesystem pointed by ail

    :param prog: Kernel being debugged
    :param ail: ``struct xfs_ail *``
    :param verbose: Optional verbose log_item print
    """
    # uek8 has the ail head at ail_head
    if has_member(ail, "xa_ail") :
        lh = ail.xa_ail
    else :
        lh = ail.ail_head
    for li in list_for_each_entry("struct xfs_log_item", lh.address_of_(),
       "li_ail") :
        xfs_print_log_item(prog, li, verbose=verbose)

def xfs_print_all_ails(prog: Program, dst: Optional[Path]=None, verbose=None) -> None :
    """
    Print the xfs ail of a given namespace. The arguments are the same as
    :func:`for_each_mount()`.

    :param prog: Kernel being debugged
    :param dst: Optional mount point
    :param verbose: Optional verbose log_item print
    """
    for mnt in for_each_mount(prog, dst = dst, fstype = "xfs") :
        mnt_src = escape_ascii_string(mount_src(mnt), escape_backslash=True)
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        mp = cast("struct xfs_mount *", mnt.mnt.mnt_sb.s_fs_info)
        print(
          f"{mnt_src} {mnt_dst} ({mp.type_.type_name()})0x{mp.value_():x}")
        xfs_print_ail(prog, mp.m_ail, verbose=verbose)

# work in progress
def xfs_print_cil_ctx(prog: Program, ctx: Object, verbose=None) -> None :
    """
    Print the cil ctx

    :param prog: Kernel being debugged
    :param ctx: ``struct xfs_cil_ctx *``
    :param verbose: Optional verbose log_item print
    """
    # List the busy extents
    # uek8 changed extent_list from a list to a structure.
    if has_member(ctx.busy_extents, "extent_list") :
        li = ctx.busy_extents.extent_list
    else :
        li = ctx.busy_extents
    if not list_empty(li.address_of_()) :
        print("Busy extents:")
        for bext in list_for_each_entry("struct xfs_extent_busy",
          ctx.busy_extents.address_of_(), "list") :
            # uek7 and before
            if has_member(bext, "agno") :
                bagno = bext.agno
            else :
                bagno = bext.group.xg_gno
            print(f"agno: {bagno.value_()} agbno: {bext.bno.value_()} len: {bext.length.value_()} flgs: {bext.flags.value_()}")
    # List the CTX lv_chain
    # uek8 convert the ctx.lv_chain to a list
    if has_member(ctx.lv_chain, "next") :
        if not list_empty(ctx.lv_chain.address_of_()) :
            print(f"log vector chain for ctx {ctx.sequence}")
            for lv in list_for_each_entry("xfs_lov_vec",
               ctx.lv_chain.address_of_(), "lv_list") :
                li = lv.lv_item
                if li != NULL(prog, "void *") :
                    xfs_print_log_item(prog, li, verbose=verbose)
    else :
        # uek7 and older lv_chain is a linked list
        lv  = ctx.lv_chain
        if lv != NULL(prog, "void *") :
            print(f"log vector chain for ctx {ctx.sequence}")
            while lv != NULL(prog, "void *") :
                li = lv.lv_item
                if li != NULL(prog, "void *") :
                    xfs_print_log_item(prog, li, verbose=verbose)
                lv = lv.lv_next

def xfs_print_cil(prog: Program, xfs_cil: Object, verbose=None) -> None :
    """
    Print the CIL of the filesystem pointed by xfs_cil

    :param prog: Kernel being debugged
    :param xfs_cil: ``struct xfs_cil *``
    :param verbose: Optional verbose log_item print
    """
    # walk the uncommitted CIL list
    print("Uncommitted CIL log items")
    if has_member(xfs_cil, "xc_cil") :
        for li in list_for_each_entry("struct xfs_log_item",
           xfs_cil.xc_cil.address_of_(), "li_cil") :
            xfs_print_log_item(prog, li, verbose=verbose)
    else :
        for cpu in for_each_online_cpu(prog) :
            pcp = cast("struct xlog_cil_pcp *", per_cpu_ptr(xfs_cil.xc_pcp, cpu))
            if not list_empty(pcp.log_items.address_of_()) :
                print(f'log items on cpu {cpu}')
                for li in list_for_each_entry("struct xfs_log_item",
                    pcp.log_items.address_of_(), "li_cil") :
                     xfs_print_log_item(prog, li, verbose=verbose)
            if not list_empty(pcp.busy_extents.address_of_()) :
                 print(f'busy extents on cpu {cpu}')
            for bext in list_for_each_entry("struct xfs_extent_busy",
                pcp.busy_extents.address_of_(), "list") :
                # uek7 and before
                if has_member(bext, "agno") :
                    bagno = bext.agno
                else :
                    bagno = bext.group.xg_gno
                print(f"agno: {bagno.value_()} agbno: {bext.bno.value_()} len: {bext.length.value_()} flgs: {bext.flags.value_()}")
    xfs_ctx = xfs_cil.xc_ctx
    xfs_print_cil_ctx(prog, xfs_ctx)
    print("CIL commiting chains")
    for xfs_ctx in list_for_each_entry("struct xfs_cil_ctx",
       xfs_cil.xc_committing.address_of_(), "committing") :
        xfs_print_cil_ctx(prog, xfs_ctx, verbose=verbose)

def xfs_print_all_cils(prog: Program, dst: Optional[Path]=None, verbose=None) -> None :
    """
    Print the xfs ail of a given namespace. The arguments are the same as
    :func:`for_each_mount()`.

    :param prog: Kernel being debugged
    :param dst: Optional mount point
    :param verbose: Optional verbose log_item print
    """
    for mnt in for_each_mount(prog, dst = dst, fstype = "xfs") :
        mnt_src = escape_ascii_string(mount_src(mnt), escape_backslash=True)
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        mp = cast("struct xfs_mount *", mnt.mnt.mnt_sb.s_fs_info)
        print(
          f"{mnt_src} {mnt_dst} ({mp.type_.type_name()})0x{mp.value_():x}")
        xfs_print_cil(prog, mp.m_log.l_cilp, verbose=verbose)

# Convert big endian to little endian for on disk log lsn
def swap_endian64(value: c_uint64) -> c_uint64 :
    """
    Endian swap a 64 bit number.

    :param value: uint64 to be converted
    :returns: the endian converted uint64
    """
    res = (value & 0x000000ff) << 56
    res = res | (value & 0x000000000000ff00) << 40
    res = res | (value & 0x0000000000ff0000) << 24
    res = res | (value & 0x00000000ff000000) << 8
    res = res | (value & 0x000000ff00000000) >> 8
    res = res | (value & 0x0000ff0000000000) >> 24
    res = res | (value & 0x00ff000000000000) >> 40
    res = res | (value & 0xff00000000000000) >> 56
    return res

# Print the state of the incore log buffers.
def xfs_print_iclog(prog: Program, xlog: Object) -> None :
    """
    Print all the iclog states for a XFS filesystem

    :param prog: Kernel being debugged
    :param mp: ``struct xlog *``:
    """
    icstate = ["XLOG_STATE_ACTIVE", "XLOG_STATE_WANT_SYNC",
         "XLOG_STATE_SYNCING", "XLOG_STATE_DONE_SYNC",
         "XLOG_STATE_DO_CALLBACK", "XLOG_STATE_DO_CALLBACK",
         "XLOG_STATE_DIRTY"]
    iclog1 = xlog.l_iclog
    iclog = iclog1
    stop = 0
    while stop == 0 :
        icl2 = iclog.ic_data.hic_header
        i = 0
        j = 1
        # find the index in the state name array. The state is in a power of 2.
        while j < iclog.ic_state :
            j = j * 2
            i = i + 1
        tail_lsn = swap_endian64(icl2.h_tail_lsn)
        lsn = swap_endian64(icl2.h_lsn)
        print(f"iclog sz {iclog.ic_size.value_()} offset {iclog.ic_offset.value_()} state {icstate[i]} lsn {hex(lsn)} tail_lsn {hex(tail_lsn)}")
        iclog = iclog.ic_next
        if iclog == iclog1 :
            stop = 1

# Print iclogs for all (or selected) XFS filesystems
def xfs_print_all_iclogs(prog: Program, dst: Optional[Path]=None) -> None :
    """
    Print the iclogs for all (or selected) XFS filesystems

    :param prog: Kernel being debugged
    :param dst: Optional mount point
    """
    for mnt in for_each_mount(prog, dst = dst, fstype = "xfs") :
        mnt_src = escape_ascii_string(mount_src(mnt), escape_backslash=True)
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        mp = cast("struct xfs_mount *", mnt.mnt.mnt_sb.s_fs_info)
        print(
          f"{mnt_src} {mnt_dst} ({mp.type_.type_name()})0x{mp.value_():x}")
        xfs_print_iclog(prog, mp.m_log)

def xfs_print_xlog(prog: Program, mp: Object, verbose=None) -> None :
    """
    Print the xlog of the filesystem pointed by mp

    :param prog: Kernel being debugged
    :param mp: ``struct xfs_mount *``
    :param verbose: Optional verbose log_item print
    """
    # print the xlog information and the the ail and cil
    xlog = mp.m_log
    # uek5
    if has_member(xlog, "l_flags") :
        print(f'xlog flags {hex(xlog.l_flags)} lsz {xlog.l_logsize}')
    # uek 7+
    if has_member(xlog, "l_opstate") :
        print(f'xlog opstate {hex(xlog.l_opstate)} lsz {xlog.l_logsize}')
    print(f'c_cycle {hex(xlog.l_curr_cycle)} p_cycle {hex(xlog.l_prev_cycle)} c_blk {hex(xlog.l_curr_block)} p_blk {hex(xlog.l_prev_block)}')
    # the grant head values are atomic64_t and the low bits are in bytes not blks
    print(f'reserve head {hex(xlog.l_reserve_head.grant.counter)} write head {hex(xlog.l_write_head.grant.counter)}')
    # print the xlog information here
    xfs_print_iclog(prog, xlog)
    xfs_print_ail(prog, mp.m_ail, verbose=verbose)
    xfs_print_cil(prog, xlog.l_cilp, verbose=verbose)

def xfs_print_all_xlogs(prog: Program, dst: Optional[Path]=None, verbose=None) -> None :
    """
    Print the xfs xlog of a given namespace. The arguments are the same as
    :func:`for_each_mount()`.

    :param prog: Kernel being debugged
    :param dst: Optional mount point
    :param verbose: Optional verbose log_item print
    """
    for mnt in for_each_mount(prog, dst = dst, fstype = "xfs") :
        mnt_src = escape_ascii_string(mount_src(mnt), escape_backslash=True)
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        mp = cast("struct xfs_mount *", mnt.mnt.mnt_sb.s_fs_info)
        print(
          f"{mnt_src} {mnt_dst} ({mp.type_.type_name()})0x{mp.value_():x}")
        xfs_print_xlog(prog, mp, verbose=verbose)

# --- Misc Print active xfs_inode and xfs_buf
# Print all the pages in an inode
def xfs_print_sb_inode(prog: Program, mp: Object, verbose = None,
   pgverbose = None) -> None :
    """
    Print all the active inodes for a XFS filesystem

    :param prog: Kernel being debugged
    :param mp: ``struct xfs_mount *``:
    :param verbose: Optional verbose printing of inode
    :param pgverbose: Optional printing of active pages on inode
    """
    sb = mp.m_super
    # get the file type - not currently interested in devices
    for ino in list_for_each_entry("struct inode",
       sb.s_inodes.address_of_(), "i_sb_list") :
        # find the xfs_inode holding the inode
        ip = container_of(ino, "struct xfs_inode", "i_vnode")
        type = "other"
        if S_ISREG(int(ino.i_mode)) :
            type = "reg"
            if verbose is not None :
                xfs_print_extents(prog, ip.i_df)
        if S_ISDIR(int(ino.i_mode)) :
            type = "dir"
        if S_ISLNK(int(ino.i_mode)) :
            type = "slink"
        print(f"ino 0x{ino.value_():x} xfsino 0x{ip.value_():x} inum 0x{ino.i_ino.value_():x} type {type} dfsz {ip.i_df.if_bytes.value_():x}")
        # Optionally, print the pages active in the inode
        if pgverbose is not None :
            # uek5 and older have address_space.page_tree
            if has_member(ino.i_mapping, "page_tree") :
                xarry = ino.i_mapping.page_tree
            else :
                xarry = ino.i_mapping.i_pages
            for _, p in radix_tree_for_each(xarry.address_of_()) :
                page = cast("struct page *", p)
                print(f'page 0x{page.value_():x} phys 0x{page_to_phys(page).value_():x} virt 0x{page_to_virt(page).value_():x} flags {decode_page_flags(page)}')

# Print all the active inodes
def xfs_print_all_inodes(prog: Program, dst: Optional[Path]=None, verbose = None,
   pgverbose = None) -> None :
    """
    Print the active xfs inodes of a given namespace. The arguments
    are the same as :func:`for_each_mount()`.

    :param prog: Kernel being debugged
    :param dst: Optional mount point
    :param verbose: Optional verbose printing of inode
    :param pgverbose: Optional printing of active pages on inode
    """
    for mnt in for_each_mount(prog, dst = dst, fstype = "xfs") :
        mnt_src = escape_ascii_string(mount_src(mnt), escape_backslash=True)
        mnt_dst = escape_ascii_string(mount_dst(mnt), escape_backslash=True)
        mp = cast("struct xfs_mount *", mnt.mnt.mnt_sb.s_fs_info)
        print(
          f"{mnt_src} {mnt_dst} ({mp.type_.type_name()})0x{mp.value_():x}")
        xfs_print_sb_inode(prog, mp, verbose, pgverbose)
