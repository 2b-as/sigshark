# sigshark

A tshark wrapper which adds TCAP (MAP/CAP) transaction tracking

## Problems sigshark tries to solve

### Sorting a pcap file by TCAP transactions

If you look at pcap files captured from signaling nodes, there are
many transactions running in parallel. This makes it difficult to
follow the outcome of transactions.

While it is possible to set a Wireshark filter for the transaction IDs
of a single transaction, it can become quite cumbersome if many
transactions are to be examined, since it has to be done sequentially,
for every transaction. If it is a large pcap file, it will take a long
time to set / clear each filter.

Sigshark will output a pcap file in which the packets are grouped by
transaction, i.e. the file will contain the corresponding `Begin (->
Continue ...) -> End/Abort` packets next to each other, followed by
the same for subsequent transactions, while preserving the original
timestamps of the packets.

### Applying filters to transactions instead of messages

If you set a filter in Wireshark, it applies only to the matching
messages. But it might make sense to also see the other messages in
the same TCAP transaction.

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

## Caveats

sigshark is still under development. It currently has the following
limitations:

- The transaction tracking currently only works for pcaps that contain
  traffic for a single endpoint, or more precisely, for a single
  TCAP-transaction-ID generating entity (which can talk to any number
  of other nodes). The IP address of that node, as found in the pcap,
  must be specified on the command line. __This means that traffic that
  was captured on STPs or gateways which only forward traffic but do
  not terminate transactions themselves can currently not be processed
  by sigshark__

- Messages belonging to transactions that are only included partially
  in the pcap file (i.e. missing `Begin` and/or `End/Abort`) will not
  be included in the resulting pcap

- The IP address matching is currently done with string prefixes,
  e.g. if your own nodes operating in loadshare mode are at
  192.168.1.10 and 192.168.1.11, you can specify 192.168.1.1, but that
  will also match 192.168.1.1, 192.168.1.12, 192.168.1.100 and so on.

- Currently support for SS7 TCAP (used for MAP/CAP) only. Diameter
  will be added in the future, GTP probably not

- There are likely bugs :)

## Usage

```
usage: sigshark.py [-h] [--flatten] [--sort OWN_IP] [--display-filter DISPLAY_FILTER]
                   [--drop-ip DROP_IP] [--version]
                   read_file write_file

positional arguments:
  read_file             input pcap filename (*not* pcap-ng!)
  write_file            output pcap filename

optional arguments:
  -h, --help            show this help message and exit
  --flatten, -f         save each sctp chunk in its own sctp packet. This *must* be performed for
                        transaction sorting to work, but can be skipped to save time if the pcap
                        file is already flat
  --sort OWN_IP, -s OWN_IP
                        sort pcap file by tcap transactions. Specify the (start of) the ip
                        address of the node the traffic was captured from, e.g.: '192.168.23'
  --display-filter DISPLAY_FILTER, -Y DISPLAY_FILTER
                        Wireshark display filter: the resulting pcap will contain all
                        transactions that contain at least one message for which the filter
                        matches, e.g.: 'gsm_old.localValue == 2' will result in the output
                        containing all updateLocation transactions
  --drop-ip DROP_IP, -d DROP_IP
                        (start of) ip address of packets that should not be considered for
                        transaction analysis, e.g.: '10. 192.168.23.42' (can be specified
                        multiple times)
  --version, -V         show program's version number and exit
```
