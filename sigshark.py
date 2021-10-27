#!/usr/bin/env python3

# sigshark
#
# Copyright (c) 2021 Tobias Engel <tobias@sternraute.de>
# All Rights Reserved

version="0.9.10"

import csv, sys, os, struct, argparse, ipaddress

log_level = 'n'

def getopts():
    global log_level

    parser = argparse.ArgumentParser()
    parser.add_argument("read_file",
                        help = "input pcap filename (*not* pcap-ng!)")
    parser.add_argument("write_file",
                        help="output pcap filename")
    parser.add_argument("--flatten", "-f",
                        action = "store_true",
                        help = "save each sctp chunk in its own sctp packet. "
                        "this *must* be performed for transaction tracking to "
                        "work, but can be skipped to save time if the pcap "
                        "file has already been flattened")
    parser.add_argument("--track", "-t",
                        action = "store_true",
                        help = "enable transaction tracking to sort or filter "
                        "based on tcap or diameter transactions")
    parser.add_argument("--sort", "-s",
                        action = "store_true",
                        help = "sort pcap file by tcap and diameter "
                        "transactions (implies --track)")
    parser.add_argument("--display-filter", "-Y",
                        help = "wireshark display filter: the resulting pcap "
                        "will contain all transactions that contain at least "
                        "one message for which the filter matches, e.g.: "
                        "'gsm_old.localValue == 2' will result in the output "
                        "containing all updateLocation transactions (requires "
                        "--track or --sort)")
    parser.add_argument("--incomplete", "-i",
                        action = "store_true",
                        help = "also store transactions whose start or end "
                        "are missing. (requires --track or --sort)")
    parser.add_argument("--dummy", "-d",
                        action = "store_true",
                        help = "insert a dummy packet between transactions "
                        "so it is easier to see where transactions start and "
                        "end. note: the dummy packets will be shown as "
                        "'Malformed Packet' in wireshark (only with --sort)")
    parser.add_argument("--exclude-ip", "-x",
                        action = "append",
                        help = "ip addresses or networks of packets that "
                        "should be excluded from transaction analysis, "
                        "e.g.: '10.0.0.0/8' (can be specified multiple "
                        "times, requires --track or --sort)")
    parser.add_argument("--verbose", "-v",
                        action = "store_true",
                        help = "more output")
    parser.add_argument("--quiet", "-q",
                        action = "store_true",
                        help = "less output")
    parser.add_argument("--version", "-V",
                        action = "version",
                        version = f"sigshark v{version}")

    args = parser.parse_args()
    if args.sort:
        args.track = True

    if(args.quiet and args.verbose):
        log('q', "only one of --quiet or --verbose can be specified")
        sys.exit(1)
    if args.quiet:
        log_level = 'q'
    elif args.verbose:
        log_level = 'v'

    if not args.flatten and not args.track:
        log('q', "nothing to do. specify --flatten and/or --track and/or --sort")
        sys.exit(1)

    if not args.track and (args.display_filter or
                           args.incomplete or
                           args.exclude_ip):
        log('q', "--display-filter, --incomplete and --exclude-ip can only be "
            "used in combination with --track or --sort")
        sys.exit(1)

    if not args.sort and args.dummy:
        log('q', "--dummy can only be used in combination with --sort")
        sys.exit(1)

    log('n',
        f"\n== parameters"
        f"\ninput file:                   {args.read_file}"
        f"\noutput file:                  {args.write_file}"
        f"\nflatten:                      {'yes' if args.flatten else 'no'}"
        f"\ntransaction tracking:         {'yes' if args.track else 'no'}"
        f"\nsort by transaction:          {'yes' if args.sort else 'no'}")

    if args.track:
        log('n',
            f"display filter:               {args.display_filter or '-'}"
            f"\nincl incomplete transactions: {'yes' if args.incomplete else 'no'}"
            f"\ninsert dummy packets:         {'yes' if args.dummy else 'no'}"
            f"\nexclude ip addresses:         {str(args.exclude_ip).lower()}"
            f"\nverbose ouput:                {'yes' if args.verbose else 'no'}")

    return args

def log(lvl, *args):
    if (lvl == 'q') or \
       (lvl == 'n' and (log_level == 'n' or log_level == 'v')) or \
       (lvl == 'v' and log_level == 'v') or \
       (lvl[1:2] == '!' and (lvl[0:1] == log_level)):
        print(*args)

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
        log('v', " flatten_sctp: corrupt/unexpected pkt", str(pkt))
    return [pkt]

def read_pcap(pcap_fn, flatten):
    PCAP_GLOBAL_HDR_LEN = 24
    PCAP_PKT_HDR_LEN = 16
    MAX_PKT_LEN = 32768
    dlt_map = {0:   (lambda p: p[0:4]   == b'\x02\x00\x00\x00',  4), # NULL
               1:   (lambda p: p[12:14] == b'\x08\x00',         14), # EN10MB
               109: (lambda p: p[0:4]   == b'\x02\x00\x00\x00', 12), # ENC
               113: (lambda p: p[14:16] == b'\x08\x00',         16), # LINUX_SLL
               276: (lambda p: p[0:2]   == b'\x08\x00',         20)} # LINUX_SLL2

    pcap_hdr = None
    frames = []

    with open(args.read_file, "rb") as ifh:
        pcap_hdr = ifh.read(PCAP_GLOBAL_HDR_LEN)
        if len(pcap_hdr) != PCAP_GLOBAL_HDR_LEN:
            raise Exception("read_pcap: cannot read header - file too short?")

        endian = None
        if pcap_hdr[0:4] == b'\xd4\xc3\xb2\xa1':
            endian = '<'
        elif pcap_hdr[0:4] == b'\xa1\xb2\xc3\xd4':
            endian = '>'
        else:
            raise Exception("read_pcap: not a pcap file (pcap-ng is not "
                            "supported!)")

        ver_maj, ver_min, tz, sigfigs, snaplen, dlt = \
            struct.unpack(endian + "2H4I", pcap_hdr[4:])
        log('n', f" read_pcap: version: {ver_maj}.{ver_min}, tz offset: {tz}, "
            f"snaplen: {snaplen}, dlt: {dlt}")

        if flatten and dlt not in dlt_map:
            raise Exception(f"read_pcap: dlt {dlt} not supported")

        frame = 0
        while True:
            pkt_hdr = ifh.read(PCAP_PKT_HDR_LEN)
            if len(pkt_hdr) != PCAP_PKT_HDR_LEN:
                break

            frame += 1

            ts_sec, ts_usec, pkt_len, orig_len = struct.unpack(endian + "4I",
                                                               pkt_hdr)
            pkt = ifh.read(pkt_len)
            if len(pkt) == pkt_len:
                if flatten:
                    if dlt_map[dlt][0](pkt):
                        pkts = flatten_sctp(dlt_map[dlt][1], pkt)
                        frames.extend(map(lambda p: struct.pack(endian + "4I",
                                                                ts_sec,
                                                                ts_usec,
                                                                len(p),
                                                                len(p)) + p,
                                          pkts))
                    else:
                        log('v', " read_pcap: flattening of non-ipv4 packet "
                            f"{frame} not supported")
                        frames.append(pkt_hdr + pkt)
                else:
                    frames.append(pkt_hdr + pkt)
            else:
                log('n', " read_pcap: premature eof")

        log('n', f" read_pcap: read {frame} pkts")

    return pcap_hdr, frames

def write_pcap(pcap_fn, pcap_hdr, frames):
    with open(pcap_fn, "wb") as ofh:
        if ofh.write(pcap_hdr) != len(pcap_hdr):
            raise Exception("write_pcap: write failure (header)")

        num_frames = 0
        for frame in frames:
            num_frames += 1
            if ofh.write(frame) != len(frame):
                raise Exception("write_pcap: write failure (frame "
                                f"{num_frames})")

        log('n', f" write_pcap: wrote {num_frames} pkts")

def ta_done(ta, last_frames, tas_done):
    tas_done.setdefault(ta['start_ts'], [])
    tas_done[ta['start_ts']].append(ta['frames'] + last_frames)

def get_pcap_tas(pcap_fn, drop_ips, include_incomplete):
    tas_done = {}
    all_pkts = 0
    dropped_ip_pkts = 0
    dropped_pkts = 0
    unsupported_pkts = 0
    saved_tas = 0

    with os.popen("tshark -Tfields -Eseparator=, -Eoccurrence=a -Eaggregator=- "
                  "-e frame.encap_type "
                  "-e frame.number "
                  "-e frame.time_epoch "
                  "-e ip.src "
                  "-e ip.dst "
                  "-e sccp.calling.ssn "
                  "-e sccp.calling.digits "
                  "-e sccp.called.ssn "
                  "-e sccp.called.digits "
                  "-e sccp.msg.fragment "
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
                  "-e sctp "
                  f"-r '{pcap_fn}'") as fh:

        ENCAP  =  0
        FRAME  =  1
        EPOCH  =  2
        IP_SRC =  3
        IP_DST =  4
        CGSSN  =  5
        CGPA   =  6
        CDSSN  =  7
        CDPA   =  8
        SEGS   =  9
        OTID   = 10
        DTID   = 11
        BEGIN  = 12
        CONT   = 13
        END    = 14
        ABORT  = 15
        DIAREQ = 16
        DIAHBH = 17
        DIAE2E = 18
        FRAGS  = 19
        SCTP   = 20

        tas = {}
        map_tids = {}

        for pkt in csv.reader(fh):

            if not pkt[SCTP] and not pkt[ENCAP] in ['42', '43', '75', '101']:
                continue

            if len("".join([pkt[BEGIN], pkt[CONT], pkt[END], pkt[ABORT],
                            pkt[DIAREQ]])) > 1:
                raise Exception("get_pcap_tas: pcap contains more than one "
                                "chunk per sctp packet - run again with "
                                "--flatten")

            src_ips = pkt[IP_SRC].split('-')
            dst_ips = pkt[IP_DST].split('-')

            all_pkts += 1
            if all_pkts % 10000 == 0:
                log('q', f" get_pcap_tas: {str(all_pkts)} pkts processed...")

            if drop_ips:
                drop=False
                for drop_ip in drop_ips:
                    for ip in map(ipaddress.IPv4Network, src_ips + dst_ips):
                        if ip.subnet_of(drop_ip):
                            drop=True
                            dropped_ip_pkts += 1
                            break
                if drop:
                    continue

            frames = []
            if pkt[SEGS] or pkt[FRAGS]:
                flist = []
                if pkt[SEGS]:
                    flist += pkt[SEGS].split('-')
                if pkt[FRAGS]:
                    flist += pkt[FRAGS].split('-')
                # -1 to make it start at 0
                frames = list(map(lambda f: int(f) - 1, flist))
            else:
                frames = [int(pkt[FRAME]) - 1] # -1 to make it start at 0

            if pkt[BEGIN]:
                tas['_'.join([pkt[CGSSN], pkt[CGPA], pkt[OTID]])] \
                    = {'start_ts': pkt[EPOCH], 'frames': frames}
            elif pkt[CONT]:
                okey = '_'.join([pkt[CGSSN], pkt[CGPA], pkt[OTID]])
                dkey = '_'.join([pkt[CDSSN], pkt[CDPA], pkt[DTID]])
                if okey in tas:
                    tas[okey]['frames'].extend(frames)
                    if okey not in map_tids:
                        map_tids[okey] = dkey
                        map_tids[dkey] = okey
                elif dkey in tas:
                    tas[dkey]['frames'].extend(frames)
                    if okey not in map_tids:
                        map_tids[okey] = dkey
                        map_tids[dkey] = okey
                else:
                    if include_incomplete:
                        log('v', " get_pcap_tas: cannot find transaction for "
                            f"{pkt}")
                        tas[okey] = {'start_ts': pkt[EPOCH], 'frames': frames}
                        map_tids[dkey] = okey
                        map_tids[okey] = dkey
                    else:
                        log('v', " get_pcap_tas: cannot find transaction for "
                            f"{pkt} - dropping")
                        dropped_pkts += 1
            elif pkt[END] or pkt[ABORT]:
                key = '_'.join([pkt[CDSSN], pkt[CDPA], pkt[DTID]])
                if key in tas:
                    ta_done(tas[key], frames, tas_done)
                    del tas[key]
                    if key in map_tids:
                        del map_tids[map_tids[key]], map_tids[key]
                    saved_tas += 1
                elif key in map_tids:
                    key2 = map_tids[key]
                    ta_done(tas[key2], frames, tas_done)
                    del tas[key2], map_tids[key], map_tids[key2]
                    saved_tas += 1
                else:
                    if include_incomplete:
                        log('v', " get_pcap_tas: cannot find transaction for "
                            f"{pkt}")
                        ta_done({'start_ts': pkt[EPOCH], 'frames': frames}, [],
                                tas_done)
                        saved_tas += 1
                    else:
                        log('v', " get_pcap_tas: cannot find transaction for "
                            f"{pkt} - dropping")
                        dropped_pkts += 1
            elif pkt[DIAHBH]:
                key = "_".join([pkt[DIAHBH], pkt[DIAE2E]])
                if int(pkt[DIAREQ]):
                    tas[key] = {'start_ts': pkt[EPOCH], 'frames': frames}
                elif key in tas:
                    ta_done(tas[key], frames, tas_done)
                    del tas[key]
                    saved_tas += 1
                else:
                    if include_incomplete:
                        log('v', " get_pcap_tas: cannot find transaction for "
                            f"{pkt}")
                        ta_done({'start_ts': pkt[EPOCH], 'frames': frames}, [],
                                tas_done)
                        saved_tas += 1
                    else:
                        log('v', " get_pcap_tas: cannot find transaction for "
                            f"{pkt} - dropping")
                        dropped_pkts += 1
            else:
                unsupported_pkts += 1

        if include_incomplete:
            for key in tas:
                ta_done(tas[key], [], tas_done)
            tas = {}

    log('q',
        f" total number of pkts read: {all_pkts}\n"
        f" dropped non-supported pkts: {unsupported_pkts}\n"
        f" pkts dropped due to missing begin of transaction: {dropped_pkts}\n"
        f" transactions dropped due to missing end: {len(tas)}\n"
        f" pkts dropped by ip filter: {dropped_ip_pkts}\n"
        f" number of tcap/diameter transactions saved: {saved_tas}")
    return tas_done

def filter_pcap(pcap_fn, filter_exp, tas_done):
    with os.popen("tshark -Tfields -Eseparator=, -Eoccurrence=a -Eaggregator=- "
                  "-e frame.number "
                  f"-Y '{filter_exp}' "
                  f"-r '{pcap_fn}'") as fh:
        frames = [int(frame) - 1 for frame in fh] # -1 to make it start at 0
        log('q', f" filter_pcap: {len(frames)} matching pkts")

        tas_filtered = {}
        num_tas = 0
        for start_ts in tas_done:
            for ta in tas_done[start_ts]:
                for ta_frame in ta:
                    if ta_frame in frames:
                        tas_filtered.setdefault(start_ts, [])
                        tas_filtered[start_ts].append(ta)
                        num_tas += 1
                        break
        log('n', f" filter_pcap: {num_tas} matching transactions")
        return tas_filtered

def sort_tas(tas_done, frames, dummy):
    sorted_frames = []
    num_frames = 0
    num_tas = 0

    for start_ts in sorted(tas_done):
        for ta in tas_done[start_ts]:
            sorted_frames += map(lambda p: frames[p], ta)
            num_frames += len(ta)
            num_tas += 1
            if dummy:
                sorted_frames.append(b'\x00' * 16)

    log('v', f" sort_tas: {num_frames} pkts\n"
        f" sort_tas: {num_tas} transactions")
    return sorted_frames

def unsorted_tas(tas_done, frames):
    return map(lambda p: frames[p],
               sorted([z for x in list(tas_done.values()) for y in x for z in y]))


args = getopts()
ifn = args.read_file
ofn = args.write_file

log('n', f"\n== reading pcap file '{ifn}'")
log('q!', "Flattening")
pcap_hdr, frames = read_pcap(ifn, args.flatten)

if args.flatten:
    log('n', f"\n== writing flattened pcap file '{ofn}'")
    write_pcap(ofn, pcap_hdr, frames)
    ifn = ofn

if args.track:
    log('n', f"\n== finding transactions from pcap '{ifn}'")
    log('q!', "Finding transactions")
    exclude_ips = list(map(ipaddress.IPv4Network, args.exclude_ip)) \
        if args.exclude_ip else None
    tas_done = get_pcap_tas(ifn, exclude_ips, args.incomplete)

    if args.display_filter:
        log('n', "\n== applying display filter")
        log('q!', "Applying filter")
        tas_done = filter_pcap(ifn, args.display_filter, tas_done)

    if args.sort:
        log('n', f"\n== sorting transactions")
        log('q!', "Sorting transactions")
        frames = sort_tas(tas_done, frames, args.dummy)
    else:
        frames = unsorted_tas(tas_done, frames)

    log('n', f"\n== writing processed pcap file '{ofn}'")
    write_pcap(ofn, pcap_hdr, frames)

log('n', f"\n== '{ofn}' done")
