# Beacon-challenge

**Code golfed** Beacon-state transition implementation by @protolambda.

It's in Go, 1024 lines, challenge over!

*Even with an absurd line limit, the spec can be implemented in Go.*

Let's get back to work making an awesome spec, that is readable, modular and can be tested well.

Thanks to all ETH 2.0 researchers and implementers for designing such a powerful but minimal specification.

```
proto beacon-challenge (master)$ bash linecount.bash 
file                                    brackets       comments       blanks         not-counting   counting       full           
./challenge/constants.go                0              14             12             26             39             65             
./challenge/containers.go               28             85             32             145            149            294            
./challenge/crypto_util.go              8              5              5              18             25             43             
./challenge/data_types.go               19             11             13             43             58             101            
./challenge/math_util.go                9              1              5              15             22             37             
./challenge/shuffling.go                9              35             5              49             36             85             
./challenge/ssz_util.go                 24             47             10             81             104            185            
./challenge/transition.go               250            201            115            566            598            1164           
total counting lines: 1031
concatenate the files, and you get 1024 (reduce package name lines for 7/8 files)
```


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

