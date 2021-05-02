#!/usr/bin/env python3

# sigshark
#
# Copyright (c) 2021 Tobias Engel <tobias@sternraute.de>
# All Rights Reserved

version="0.8"

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
                        action = "store_true",
                        help = "sort pcap file by tcap and diameter "
                        "transactions.")
    parser.add_argument("--display-filter", "-Y",
                        help = "Wireshark display filter: the resulting pcap "
                        "will contain all transactions that contain at least "
                        "one message for which the filter matches, e.g.: "
                        "'gsm_old.localValue == 2' will result in the output "
                        "containing all updateLocation transactions")
    parser.add_argument("--incomplete", "-i",
                        action = "store_true",
                        help = "Also store transactions whose start or end "
                        "are missing.")
    parser.add_argument("--dummy", "-d",
                        action = "store_true",
                        help = "Insert a dummy packet between transactions "
                        "so it is easier to see where transactions start and "
                        "end. Note: the dummy packets will be shown as "
                        "'Malformed Packet' in Wireshark")
    parser.add_argument("--exclude-ip", "-x",
                        action = "append",
                        help = "(start of) ip address of packets that "
                        "should be excluded from transaction analysis, "
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

def ta_done(ta, last_frames, tas_done):
    tas_done.setdefault(ta['start_ts'], [])
    tas_done[ta['start_ts']].append(ta['frames'] + last_frames)

def get_pcap_transactions(pcap_fn, drop_ips, include_incomplete):
    tas_done = {}
    all_pkts = 0
    dropped_ip_pkts = 0
    dropped_pkts = 0
    unsupported_pkts = 0
    completed_tas = 0

    with os.popen("tshark -Tfields -Eseparator=, -Eoccurrence=a -Eaggregator=- "
                  "-e frame.number "
                  "-e frame.time_epoch "
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
                  "-e diameter.flags.request "
                  "-e diameter.hopbyhopid "
                  "-e diameter.endtoendid "
                  "-e sctp.fragment "
                  "-r " + pcap_fn) as fh:

        FRAME  =  0
        EPOCH  =  1
        IP_SRC =  2
        IP_DST =  3
        CGPA   =  4
        CDPA   =  5
        OTID   =  6
        DTID   =  7
        BEGIN  =  8
        CONT   =  9
        END    = 10
        ABORT  = 11
        DIAREQ = 12
        DIAHBH = 13
        DIAE2E = 14
        FRAGS  = 15

        tas = {}
        map_tids = {}

        for pkt in csv.reader(fh):

            if len("".join([pkt[BEGIN], pkt[CONT], pkt[END], pkt[ABORT],
                            pkt[DIAREQ]])) > 1:
                raise Exception("pcap contains more than one chunk per sctp "
                                "packet - run again with --flatten")

            src_ips = pkt[IP_SRC].split('-')
            dst_ips = pkt[IP_DST].split('-')

            all_pkts += 1
            if all_pkts % 10000 == 0:
                print(str(all_pkts), "pkts processed...")

            if drop_ips:
                drop=False
                for drop_ip in drop_ips:
                    for ip in src_ips + dst_ips:
                        if ip.startswith(drop_ip):
                            drop=True
                            dropped_ip_pkts += 1
                            break
                if drop:
                    continue

            frames = []
            if pkt[FRAGS]:
                # -1 to make it start at 0
                frames = list(map(lambda f: int(f) - 1, pkt[FRAGS].split('-')))
                #print("using fragments", str(frames), "instead of",
                #      int(pkt[FRAME]) - 1)
            else:
                frames = [int(pkt[FRAME]) - 1] # -1 to make it start at 0

            if pkt[BEGIN]:
                tas['_'.join([pkt[CGPA], pkt[OTID]])] = {'start_ts': pkt[EPOCH],
                                                         'frames': frames}
            elif pkt[CONT]:
                okey = '_'.join([pkt[CGPA], pkt[OTID]])
                dkey = '_'.join([pkt[CDPA], pkt[DTID]])
                if okey in tas:
                    tas[okey]['frames'].extend(frames)
                    map_tids[dkey] = okey
                    map_tids[okey] = dkey
                elif dkey in tas:
                    tas[dkey]['frames'].extend(frames)
                    map_tids[dkey] = okey
                    map_tids[okey] = dkey
                else:
                    #print(f"cannot find transaction for {pkt} - dropping")
                    dropped_pkts += 1
                    if include_incomplete:
                        tas[okey] = {'start_ts': pkt[EPOCH],
                                     'frames': frames}
                        map_tids[dkey] = okey
                        map_tids[okey] = dkey
            elif pkt[END] or pkt[ABORT]:
                key = '_'.join([pkt[CDPA], pkt[DTID]])
                if key in tas:
                    ta_done(tas[key], frames, tas_done)
                    del tas[key]
                    if key in map_tids:
                        del map_tids[map_tids[key]], map_tids[key]
                    completed_tas += 1
                elif key in map_tids:
                    key2 = map_tids[key]
                    ta_done(tas[key2], frames, tas_done)
                    del tas[key2], map_tids[key], map_tids[key2]
                    completed_tas += 1
                else:
                    #print(f"cannot find transaction for {pkt} - dropping")
                    dropped_pkts += 1
                    if include_incomplete:
                        ta_done({'start_ts': pkt[EPOCH], 'frames': frames}, [],
                                tas_done)
            elif pkt[DIAHBH]:
                key = "_".join([pkt[DIAHBH], pkt[DIAE2E]])
                if int(pkt[DIAREQ]):
                    tas[key] = {'start_ts': pkt[EPOCH], 'frames': frames}
                elif key in tas:
                    ta_done(tas[key], frames, tas_done)
                    del tas[key]
                    completed_tas += 1
                else:
                    #print(f"cannot find dia transaction for {pkt} - dropping")
                    dropped_pkts += 1
                    if include_incomplete:
                        ta_done({'start_ts': pkt[EPOCH], 'frames': frames}, [],
                                tas_done)
            else:
                unsupported_pkts += 1

        if include_incomplete:
            for key in tas:
                ta_done(tas[key], [], tas_done)

    print(f"\ntotal number of pkts read: {all_pkts}\n"
          f"dropped non-supported pkts: {unsupported_pkts}\n"
          f"pkts dropped due to missing begin of transaction: {dropped_pkts}\n"
          f"transactions dropped due to missing end: ", len(tas), "\n"
          f"pkts dropped by ip filter: {dropped_ip_pkts}\n"
          f"number of tcap/diameter transactions saved: {completed_tas}")
    return tas_done

def flatten_sctp(ldlt, pkt):
    try:
        # length of header before current ip header (e.g. dlt and
        # previous ip header)
        lbef = ldlt
        # iterate over multiple ip headers in case of ip-in-ip
        while True:
            # get ip header len
            lih, = struct.unpack("!B", pkt[lbef:(lbef + 1)])
            lih = (lih & 0xf) * 4
            # get protocol
            prot, = struct.unpack("!B", pkt[(lbef + 9):(lbef + 10)])
            # if it's not ip-in-ip, exit the loop
            if prot != 4:
                break
            # add ip header length to "before" header length
            lbef += lih
        # if sctp
        if prot == 132:
            # length of pkt, according to ip header
            lp, = struct.unpack("!H", pkt[(lbef + 2):(lbef + 4)])
            lp += lbef
            # calc length from start of pkt up to end of sctp hdr
            lp_sctp = lbef + lih + 12
            # get len of first chunk (2 = chunk len field pos)
            lc1, = struct.unpack("!H", pkt[(lp_sctp + 2):(lp_sctp + 4)])
            # add padding bytes to len (if any)
            lc1 += (4 - (lc1 % 4)) if (lc1 % 4) else 0
            # calc len of pkt from start to end of first chunk
            lp_c1 = lp_sctp + lc1
            # check if pkt is longer than that, i.e. contains 2nd chunk
            if lp > lp_c1:
                # ip header up until len field
                pkt_start = pkt[0:(lbef + 2)]
                # save complete pkt with first chunk and new ip length
                pkts_out = [pkt_start +
                            struct.pack("!H", lp_c1 - lbef) +
                            pkt[(lbef + 4):lp_c1]]
                # pkt from after ip len field up to end of sctp header
                pkt_sctp = pkt[(lbef + 4):lp_sctp]
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
                                    struct.pack("!H", lp_sctp - lbef + lcx) +
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

def write_sorted_pcap(tas_done, pcap_fn, pcap_hdr, frames, match_frames, dummy):
    with open(pcap_fn, "wb") as ofh:
        if ofh.write(pcap_hdr) != len(pcap_hdr):
            raise Exception("write failure (pcap header)")

        frames_written = 0
        tas_written = 0
        for start_ts in sorted(tas_done):
            for ta in tas_done[start_ts]:
                write_ta = False
                if match_frames and len(match_frames):
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
                            raise Exception(f"write failure (frame {frame})")
                    if dummy:
                        ofh.write(b'\x00' * 16)

        print(f"wrote {frames_written} pkts\nwrote {tas_written} transactions")


args = getopts()
ifn = args.read_file
ofn = args.write_file

if args.flatten or args.sort:

    print(f"\n== reading pcap file '{ifn}'")
    pcap_hdr, frames = read_pcap(ifn, args.flatten)

    if args.flatten:
        print(f"\n== writing flattened pcap file '{ofn}'")
        write_pcap(ofn, pcap_hdr, frames)
        ifn = ofn

    if args.sort:
        print(f"\n== getting transactions from pcap '{ifn}'")
        tas_done = get_pcap_transactions(ifn, args.exclude_ip, args.incomplete)

        match_frames = None
        if args.display_filter:
            print("\n== applying display filter")
            match_frames = filter_pcap(ifn, args.display_filter)

        print(f"\n== writing sorted pcap file '{ofn}'")
        write_sorted_pcap(tas_done, ofn, pcap_hdr, frames, match_frames,
                          args.dummy)

    print(f"\n== '{ofn}' done")

else:
    print("nothing to do. specify --flatten and/or --sort")
