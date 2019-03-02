# Beacon-challenge

Beacon-state transition implementation by @protolambda.

Submission for Twitter-bounty by Justin Drake:
[Twitter link](https://twitter.com/drakefjustin/status/1100809667528278016)
[Archived tweet](https://web.archive.org/web/20190227193001/https://twitter.com/drakefjustin/status/1100809667528278016)

> @drakefjustin:
>
> The phase 0 spec (even not fully polished) is slick!
>
> 10 ETH bounty to the first person to write in Go (MIT license) the full state transition function (BeaconState, BeaconBlock) -> (BeaconState, Error) in 1,024 lines or less.


Challenge accepted.

Git ref of beacon spec used for this challenge: [8df7de150e68408b78d6488a6f4c9cf8e18c4405](https://github.com/ethereum/eth2.0-specs/blob/8df7de150e68408b78d6488a6f4c9cf8e18c4405/specs/core/0_beacon-chain.md) (Current dev branch at the time of starting the challenge).

## Counting lines

```
bash linecount.bash
```

Yes this is bad. But fun, and code golfing = more scrutiny towards spec, we look more at the necessity of functions.
 I.e. the spec improves in the process.

In the future this codebase aims to provide an "executable spec": the specced state transition should be runnable,
 and the compiling process already helps enforce consistency in the spec (and typing of Go helps as well)

## License

MIT. Container types are adapted from CC0-licensed types in original ETH 2.0 specification doc.

