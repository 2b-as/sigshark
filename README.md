# sigshark

Sigshark makes working with SS7 TCAP (MAP/CAP) and Diameter signaling
pcap files easier. Its features include "flattening" (putting each
SCTP chunk in its own packet) and transaction sorting/grouping.

## Features

### "Flattening" of pcap files

Multiple MAP, CAP or Diameter messages are often bundled together into
one SCTP packet. Sigshark can put each SCTP chunk into its own SCTP
packet, preserving all other properties of the packet
(e.g. timestamp).

### Sorting a pcap file by its TCAP and Diameter transactions

If you look at pcap files captured from signaling nodes, there are
many transactions running in parallel. This makes it difficult to
follow the outcome of transactions.

While it is possible to set a Wireshark filter for the transaction IDs
of a single transaction, it can become quite cumbersome if many
transactions are to be examined, since it has to be done sequentially,
for every transaction. If it is a large pcap file, it will take a long
time to set / clear each filter.

Sigshark can output a pcap file in which the packets are grouped by
transaction, i.e. the file will contain the corresponding `Begin (->
Continue ...) -> End/Abort` or `Request -> Answer` packets next to
each other, followed by the same for subsequent transactions, while
preserving the original timestamps of the packets.

Please note that Sigshark doesn't currently support Diameter over
TCP. Non-SCTP packets will be ignored.

### Applying filters to transactions instead of messages

If you set a filter in Wireshark, it applies only to the matching
messages. But it might make sense to also see the other messages in
the same TCAP or Diameter transaction.

For example, when setting a filter for `updateLocation` messages, it
might make sense to not only see the `updateLocation invoke`, but the
whole transaction, including `insertSubscriberData` messages or the
returned error, if any.

Similarly, when filtering for the IMSI or MSISDN of a subscriber to
look for an issue, it is often necessary to see all messages included
in the transaction. For example, for `forwardSM`,
`provideRoamingNumber`, `updateLocation` etc, it is often desirable to
not only see the initial message, but also the outcome of the
procedure.

Sigshark will include all transactions which contain at least one
message for which the Wireshark filter matches in the resulting pcap
file.

## Installation

No installation is necessary, just execute `sigshark.py`.

Sigshark uses `tshark` for sorting and filtering and expects to find
it in your path for these operations. Flattening alone does _not_
require any external tools.

## Usage

```
usage: sigshark.py [-h] [--flatten] [--track] [--sort]
                   [--display-filter DISPLAY_FILTER] [--incomplete] [--dummy]
                   [--exclude-ip EXCLUDE_IP] [--verbose] [--quiet] [--version]
                   read_file write_file

positional arguments:
  read_file             input pcap filename (*not* pcap-ng!)
  write_file            output pcap filename

optional arguments:
  -h, --help            show this help message and exit
  --flatten, -f         save each sctp chunk in its own sctp packet. this
                        *must* be performed for transaction tracking to work,
                        but can be skipped to save time if the pcap file has
                        already been flattened
  --track, -t           enable transaction tracking to sort or filter based on
                        tcap or diameter transactions
  --sort, -s            sort pcap file by tcap and diameter transactions
                        (implies --track)
  --display-filter DISPLAY_FILTER, -Y DISPLAY_FILTER
                        wireshark display filter: the resulting pcap will
                        contain all transactions that contain at least one
                        message for which the filter matches, e.g.:
                        'gsm_old.localValue == 2' will result in the output
                        containing all updateLocation transactions (requires
                        --track or --sort)
  --incomplete, -i      also store transactions whose start or end are
                        missing. (requires --track or --sort)
  --dummy, -d           insert a dummy packet between transactions so it is
                        easier to see where transactions start and end. note:
                        the dummy packets will be shown as 'Malformed Packet'
                        in wireshark (only with --sort)
  --exclude-ip EXCLUDE_IP, -x EXCLUDE_IP
                        ip addresses or networks of packets that should be
                        excluded from transaction analysis, e.g.: '10.0.0.0/8'
                        (can be specified multiple times, requires --track or
                        --sort)
  --verbose, -v         more output
  --quiet, -q           less output
  --version, -V         show program's version number and exit
```

## Examples

SS7 MAP pcap, as displayed in Wireshark, **without** using Sigshark:
![MAP pcap displayed in Wireshark without Sigshark](https://github.com/2b-as/i/raw/master/map-pcap-without-sigshark.png)

The same pcap, after using `sigshark.py --flatten`:
![MAP pcap displayed in Wireshark with flattening](https://github.com/2b-as/i/raw/master/map-pcap-with-sigshark-flatten.png)

And again the same pcap, after using `sigshark.py --flatten --sort
--dummy` (transaction sorting with dummy packets inserted between
transactions):
![MAP pcap displayed in Wireshark with transaction sorting](https://github.com/2b-as/i/raw/master/map-pcap-with-sigshark-transaction-sort.png)
