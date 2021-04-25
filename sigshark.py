#!/usr/bin/env python3

# sigshark
#
# Copyright (c) 2021 Tobias Engel <tobias@sternraute.de>
# All Rights Reserved

version="0.5"

import csv, sys, os, struct, argparse

def getopts():
    parser = argparse.ArgumentParser()
    parser.add_argument("read_file",
                        help = "input pcap filename (*not* pcap-ng!)")
    parser.add_argument("write_file",
                        help="output pcap filename")
    parser.add_argument("--flatten", "-f",
                        action = "store_true",
                        help = "save each sctp chunk in its own sctp packet. "
                        "This *must* be performed for transaction sorting to "
                        "work, but can be skipped to save time if the pcap "
                        "file is already flat")
    parser.add_argument("--sort", "-s",
                        dest='own_ip',
                        metavar='OWN_IP',
                        help = "sort pcap file by tcap transactions. Specify "
                        "the (start of) the ip address of the node the "
                        "traffic was captured from, e.g.: '192.168.23'")
    parser.add_argument("--display-filter", "-Y",
                        help = "Wireshark display filter: the resulting pcap "
                        "will contain all transactions that contain at least "
                        "one message for which the filter matches, e.g.: "
                        "'gsm_old.localValue == 2' will result in the output "
                        "containing all updateLocation transactions")
    parser.add_argument("--drop-ip", "-d",
                        action = "append",
                        help = "(start of) ip address of packets that "
                        "should not be considered for transaction analysis, "
                        "e.g.: '10. 192.168.23.42' (can be specified multiple "
                        "times)")
    parser.add_argument("--version", "-V",
                        action = "version",
                        version = "sigshark v" + version)
    return parser.parse_args()

def filter_pcap(pcap_fn, filter_exp):
    with os.popen("tshark -Tfields -Eseparator=, -Eoccurrence=a -Eaggregator=- "
                  "-e frame.number "
                  "-Y '" + filter_exp + "' "
                  "-r " + pcap_fn) as fh:
        frames = [int(frame) - 1 for frame in fh] # -1 to make it start at 0
        print(len(frames), "matching pkts")
        return set(frames)

def get_pcap_transactions(pcap_fn, own_ip, drop_ips):
    tas_done = []
    all_pkts = 0
    dropped_ip_pkts = 0
    dropped_pkts = 0
    non_tcap_pkts = 0

    with os.popen("tshark -Tfields -Eseparator=, -Eoccurrence=a -Eaggregator=- "
                  "-e frame.number "
                  "-e ip.src "
                  "-e ip.dst "
                  "-e sccp.calling.digits "
                  "-e sccp.called.digits "
                  "-e tcap.otid "
                  "-e tcap.dtid "
                  "-e tcap.begin_element "
                  "-e tcap.continue_element "
                  "-e tcap.end_element "
                  "-e tcap.abort_element "
                  "-r " + pcap_fn) as fh:

        FRAME  =  0
        IP_SRC =  1
        IP_DST =  2
        CGPA   =  3
        CDPA   =  4
        OTID   =  5
        DTID   =  6
        BEGIN  =  7
        CONT   =  8
        END    =  9
        ABORT  = 10

        tas = {}
        remote_begins = {}
        rem_to_loc_tids = {}

        for pkt in csv.reader(fh):

            if len("".join([pkt[BEGIN], pkt[CONT], pkt[END], pkt[ABORT]])) > 1:
                raise Exception("pcap contains more than one chunk per sctp "
                                "packet - run again with --flatten")

            all_pkts += 1
            if all_pkts % 10000 == 0:
                print(str(all_pkts), "pkts processed...")

            if drop_ips:
                drop=False
                for drop_ip in drop_ips:
                    if pkt[IP_SRC].startswith(drop_ip) or \
                       pkt[IP_DST].startswith(drop_ip):
                        drop=True
                        dropped_ip_pkts += 1
                        break
                if drop:
                    continue

            frame = int(pkt[FRAME]) - 1 # -1 to make it start at 0
            outbound = True if pkt[IP_DST].startswith(own_ip) else False
            if pkt[BEGIN]:
                if outbound:
                    tas[pkt[OTID]] = [frame]
                else:
                    remote_begins[pkt[CGPA] + "_" + pkt[OTID]] = frame
            elif pkt[CONT]:
                if outbound:
                    local_tid = pkt[OTID]
                    if local_tid in tas:
                        tas[local_tid].append(frame)
                    else:
                        key = pkt[CDPA] + "_" + pkt[DTID]
                        if key in remote_begins:
                            tas[local_tid] = [remote_begins[key], frame]
                            del remote_begins[key]
                            rem_to_loc_tids[key] = local_tid
                        else:
                            #print(f"cannot find transaction for {pkt} - dropping")
                            dropped_pkts += 1
                else:
                    local_tid = pkt[DTID]
                    if local_tid in tas:
                        tas[local_tid].append(frame)
                        rem_to_loc_tids[pkt[CGPA] + "_" + pkt[OTID]] = local_tid
                    else:
                        #print(f"cannot find transaction for {pkt} - dropping")
                        dropped_pkts += 1
            elif pkt[END] or pkt[ABORT]:
                if outbound:
                    key = pkt[CDPA] + "_" + pkt[DTID]
                    if key in remote_begins:
                        tas_done.append([remote_begins[key], frame])
                        del remote_begins[key]
                    elif key in rem_to_loc_tids:
                        local_tid = rem_to_loc_tids[key]
                        del rem_to_loc_tids[key]
                        if local_tid in tas:
                            tas_done.append(tas[local_tid] + [frame])
                            del tas[local_tid]
                        else:
                            #print(f"cannot find transaction for {pkt} - dropping")
                            dropped_pkts += 1
                else:
                    local_tid = pkt[DTID]
                    if local_tid in tas:
                        tas_done.append(tas[local_tid] + [frame])
                        del tas[local_tid]
                    else:
                        #print(f"cannot find transaction for {pkt} - dropping")
                        dropped_pkts += 1
            else:
                non_tcap_pkts += 1

    print(f"\ntotal number of pkts read: {all_pkts}\n"
          f"dropped non-tcap pkts: {non_tcap_pkts}\n"
          f"pkts dropped due to missing begin of transaction: {dropped_pkts}\n"
          f"transactions dropped due to missing end: ", len(tas), "\n"
          f"pkts dropped by ip filter: {dropped_ip_pkts}\n"
          "number of completed transactions found:", len(tas_done))
    return tas_done

def flatten_sctp(ldlt, pkt):
    try:
        # get header len
        lih, = struct.unpack("!B", pkt[ldlt:(ldlt + 1)])
        lih = (lih & 0xf) * 4
        # length of pkt, according to ip header
        lp, = struct.unpack("!H", pkt[(ldlt + 2):(ldlt + 4)])
        lp += ldlt
        # get protocol
        prot, = struct.unpack("!B", pkt[(ldlt + 9):(ldlt + 10)])
        # if sctp
        if prot == 132:
            # calc length from start of pkt up to end of sctp hdr
            lp_sctp = ldlt + lih + 12
            # get len of first chunk (2 = chunk len field pos)
            lc1, = struct.unpack("!H", pkt[(lp_sctp + 2):(lp_sctp + 4)])
            # add padding bytes to len (if any)
            lc1 += (4 - (lc1 % 4)) if (lc1 % 4) else 0
            # calc len of pkt from start to end of first chunk
            lp_c1 = lp_sctp + lc1
            # check if pkt is longer than that, i.e. contains 2nd chunk
            if lp > lp_c1:
                # ip header up until len field
                pkt_start = pkt[0:(ldlt + 2)]
                # save complete pkt with first chunk and new ip length
                pkts_out = [pkt_start +
                            struct.pack("!H", lp_c1 - ldlt) +
                            pkt[(ldlt + 4):lp_c1]]
                # pkt from after ip len field up to end of sctp header
                pkt_sctp = pkt[(ldlt + 4):lp_sctp]
                # remember previous (1st) chunk end position in pkt
                lp_old_cx = lp_c1
                while True:
                    # get len of next chunk (2 = chunk length field pos)
                    lcx, = struct.unpack("!H", pkt[(lp_old_cx + 2):
                                                   (lp_old_cx + 4)])
                    # add padding bytes to len (if any)
                    lcx += (4 - (lcx % 4)) if (lcx % 4) else 0
                    # calc end position of current chunk
                    lp_cx = lp_old_cx + lcx
                    # save pkt with current chunk
                    pkts_out.append(pkt_start +
                                    struct.pack("!H", lp_sctp - ldlt + lcx) +
                                    pkt_sctp +
                                    pkt[lp_old_cx:lp_cx])
                    # if pkt doesn't contain another chunk, exit
                    if lp <= lp_cx:
                        break
                    # remember previous chunk end position in pkt
                    lp_old_cx = lp_cx
                return pkts_out
    except struct.error:
        print("corrupt pkt - cannot flatten")
    return [pkt]

def read_pcap(pcap_fn, flatten):
    PCAP_GLOBAL_HDR_LEN = 24
    PCAP_PKT_HDR_LEN = 16
    MAX_PKT_LEN = 32768
    dlt_map = {0:   (lambda p: pkt[0:4]   == b'\x02\x00\x00\x00',  4),
               1:   (lambda p: pkt[12:14] == b'\x08\x00',         14),
               109: (lambda p: pkt[0:4]   == b'\x02\x00\x00\x00', 12),
               113: (lambda p: pkt[14:16] == b'\x08\x00',         16)}

    pcap_hdr = None
    frames = []

    with open(args.read_file, "rb") as ifh:
        pcap_hdr = ifh.read(PCAP_GLOBAL_HDR_LEN)
        if len(pcap_hdr) != PCAP_GLOBAL_HDR_LEN:
            raise Exception("cannot read header - file too short?")

        endian = None
        if pcap_hdr[0:4] == b'\xd4\xc3\xb2\xa1':
            endian = '<'
        elif pcap_hdr[0:4] == b'\xa1\xb2\xc3\xd4':
            endian = '>'
        else:
            raise Exception("not a pcap file (pcap-ng is not supported!)")

        ver_maj, ver_min, tz, sigfigs, snaplen, dlt = \
            struct.unpack(endian + "2H4I", pcap_hdr[4:])
        print(f"pcap version: {ver_maj}.{ver_min}, tz offset: {tz}, "
              f"snaplen: {snaplen}, dlt: {dlt}")

        if tz != 0:
            raise Exception("timezone offset other than 0 not supported")

        frame = 0
        while True:
            pkt_hdr = ifh.read(PCAP_PKT_HDR_LEN)
            if len(pkt_hdr) != PCAP_PKT_HDR_LEN:
                break

            frame += 1

            ts_sec, ts_usec, pkt_len, orig_len = struct.unpack(endian + "4I",
                                                               pkt_hdr)
            pkt = ifh.read(pkt_len)
            if len(pkt) != pkt_len:
                raise Exception("premature eof")

            if flatten:
                if dlt in dlt_map:
                    if dlt_map[dlt][0](pkt):
                        pkts = flatten_sctp(dlt_map[dlt][1], pkt)
                        frames.extend(map(lambda p: struct.pack(endian + "4I",
                                                                ts_sec,
                                                                ts_usec,
                                                                len(p),
                                                                len(p)) + p,
                                          pkts))
                    else:
                        print("non-ipv4 packet type not supported - skipping")
                        frames.append(pkt_hdr + pkt)
                else:
                    print(f"dlt {dlt} not supported - skipping")
                    frames.append(pkt_hdr + pkt)
            else:
                frames.append(pkt_hdr + pkt)

        print(f"read {frame} pkts")

    return pcap_hdr, frames

def write_pcap(pcap_fn, pcap_hdr, frames):
    with open(pcap_fn, "wb") as ofh:
        if ofh.write(pcap_hdr) != len(pcap_hdr):
            raise Exception("write failure (pcap header)")

        frames_written = 0
        for frame in frames:
            frames_written += 1
            if ofh.write(frame) != len(frame):
                raise Exception("write failure (frame " + frame + ")")

        print(f"wrote {frames_written} pkts")

def write_sorted_pcap(tas_done, pcap_fn, pcap_hdr, frames, match_frames):
    with open(pcap_fn, "wb") as ofh:
        if ofh.write(pcap_hdr) != len(pcap_hdr):
            raise Exception("write failure (pcap header)")

        frames_written = 0
        tas_written = 0
        for ta in tas_done:
            write_ta = False
            if match_frames:
                for ta_frame in ta:
                    if ta_frame in match_frames:
                        write_ta = True
                        break
            else:
                write_ta = True
            if write_ta:
                tas_written += 1
                for ta_frame in ta:
                    frames_written += 1
                    if ofh.write(frames[ta_frame]) != len(frames[ta_frame]):
                        raise Exception("write failure (frame " + frame + ")")

        print(f"wrote {frames_written} pkts\nwrote {tas_written} transactions")


args = getopts()
ifn = args.read_file
ofn = args.write_file

if args.flatten or args.own_ip:

    print(f"\n== reading pcap file '{ifn}'")
    pcap_hdr, frames = read_pcap(ifn, args.flatten)

    if args.flatten:
        print(f"\n== writing flattened pcap file '{ofn}'")
        write_pcap(ofn, pcap_hdr, frames)
        ifn = ofn

    if args.own_ip:
        print(f"\n== getting transactions from pcap '{ifn}'")
        tas_done = get_pcap_transactions(ifn, args.own_ip, args.drop_ip)

        match_frames = None
        if args.display_filter:
            print("\n== applying display filter")
            match_frames = filter_pcap(ifn, args.display_filter)

        print(f"\n== writing sorted pcap file '{ofn}'")
        write_sorted_pcap(tas_done, ofn, pcap_hdr, frames, match_frames)

    print(f"\n== '{ofn}' done")

else:
    print("nothing to do. specify --flatten and/or --sort")
