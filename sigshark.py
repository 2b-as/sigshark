#!/usr/bin/env python3

# sigshark
#
# Copyright (c) 2021 Tobias Engel <tobias@sternraute.de>
# All Rights Reserved

import csv, sys, os, struct, argparse

def getopts():
    parser = argparse.ArgumentParser()
    parser.add_argument("read_file",
                        help = "input pcap filename (*not* pcap-ng!)")
    parser.add_argument("write_file",
                        help="output pcap filename")
    parser.add_argument("own_ip",
                        help = "(start of) the ip address of the node the "
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
    return parser.parse_args()

def filter_pcap(pcap_fn, filter_exp):
    with os.popen("tshark -Tfields -Eseparator=, -Eoccurrence=a -Eaggregator=- "
                  "-e frame.number "
                  "-Y '" + filter_exp + "' "
                  "-r " + pcap_fn) as fh:
        frames = []
        for frame in fh:
            frames.append(int(frame))
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
            all_pkts += 1

            drop=False
            for drop_ip in drop_ips:
                if pkt[IP_SRC].startswith(drop_ip) or \
                   pkt[IP_DST].startswith(drop_ip):
                    drop=True
                    dropped_ip_pkts += 1
                    break
            if drop:
                continue

            frame = int(pkt[FRAME])
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
                            print(f"cannot find transaction for {pkt} - dropping")
                            dropped_pkts += 1
                else:
                    local_tid = pkt[DTID]
                    if local_tid in tas:
                        tas[local_tid].append(frame)
                        rem_to_loc_tids[pkt[CGPA] + "_" + pkt[OTID]] = local_tid
                    else:
                        print(f"cannot find transaction for {pkt} - dropping")
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
                            print(f"cannot find transaction for {pkt} - dropping")
                            dropped_pkts += 1
                else:
                    local_tid = pkt[DTID]
                    if local_tid in tas:
                        tas_done.append(tas[local_tid] + [frame])
                        del tas[local_tid]
                    else:
                        print(f"cannot find transaction for {pkt} - dropping")
                        dropped_pkts += 1
            else:
                non_tcap_pkts += 1

    print(f"total number of pkts read: {all_pkts}\n"
          f"dropped non-tcap pkts: {non_tcap_pkts}\n"
          f"dropped due to incomplete transaction: {dropped_pkts}\n"
          f"dropped by ip filter: {dropped_ip_pkts}\n"
          "number of transactions found:", len(tas_done))
    return tas_done

def read_pcap(pcap_fn):
    PCAP_GLOBAL_HDR_LEN = 24
    PCAP_PKT_HDR_LEN = 16
    MAX_PKT_LEN = 32768

    pcap_hdr = None
    frames = [None] # tshark frame numbers start at 1, not 0

    with open(args.read_file, "rb") as ifh:
        pcap_hdr = ifh.read(PCAP_GLOBAL_HDR_LEN)
        if len(pcap_hdr) != PCAP_GLOBAL_HDR_LEN:
            raise Exception("cannot read header - file too short?")

        endianness = None
        if pcap_hdr[0:4] == b'\xd4\xc3\xb2\xa1':
            endianness = '<'
        elif pcap_hdr[0:4] == b'\xa1\xb2\xc3\xd4':
            endianness = '>'
        else:
            raise Exception("not a pcap file (pcap-ng is not supported!)")

        ver_maj, ver_min, tz, sigfigs, snaplen, dlt = \
            struct.unpack(endianness + "2H4I", pcap_hdr[4:])
        print(f"pcap version: {ver_maj}.{ver_min}, tz offset: {tz}, "
              f"snaplen: {snaplen}, dlt: {dlt}")

        if tz != 0:
            raise Exception("timezone offset other than 0 not supported")

        frame = 0
        while True:
            pkt = ifh.read(PCAP_PKT_HDR_LEN)
            if len(pkt) != PCAP_PKT_HDR_LEN:
                break

            frame += 1

            ts_sec, ts_usec, pkt_len, orig_len = struct.unpack(endianness +
                                                               "4I", pkt)
            pkt += ifh.read(pkt_len)
            if len(pkt) != (PCAP_PKT_HDR_LEN + pkt_len):
                raise Exception("premature eof")

            frames.append(pkt)

        print(f"read {frame} pkts")

    return pcap_hdr, frames

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

print("== getting transactions from pcap")
tas_done = get_pcap_transactions(args.read_file, args.own_ip, args.drop_ip)

print("\n== parsing pcap file")
pcap_hdr, frames = read_pcap(args.read_file)

match_frames = None
if args.display_filter:
    print("\n== applying display filter")
    match_frames = filter_pcap(args.read_file, args.display_filter)

print("\n== writing sorted pcap file")
write_sorted_pcap(tas_done, args.write_file, pcap_hdr, frames, match_frames)

print(f"\n== {args.write_file} done")
