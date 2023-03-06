# Easy Cloudtrail

Easy to use command line tool to quickly query cloudtrail events using filter lists. 

# Usage 

## Write History queries

The following query will return all write cloudtrail events excluding those performed by `jason` or by users containing `peter12` for the last 72 hours. The events returned contain the `eu-west-1` events as well as the global AWS events from `us-east-1`:

```bash
easycloudtrail write-history --since 72h --region eu-west-1 -i peter12*,jason
```

The following query will display the events in a raw format:

```bash
easycloudtrail write-history --since 72h --region eu-west-1 -i peter12*,jason --raw
```

For further information, see the `--help` option.

# Installation

Currently, `easycloudtrail` is only available as self built binary.

Prerequisites:
- `GOPATH` environment variable is set
- `GOBIN` environment variable is set and `GOBIN` is in your system's `PATH`

Installation:

```
make install
```
