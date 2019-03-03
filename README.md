# Beacon-challenge

**Code golfed** Beacon-state transition implementation by @protolambda.

Submission for Twitter-bounty by Justin Drake:
[Twitter link](https://twitter.com/drakefjustin/status/1100809667528278016)
[Archived tweet](https://web.archive.org/web/20190227193001/https://twitter.com/drakefjustin/status/1100809667528278016)

> @drakefjustin:
>
> The phase 0 spec (even not fully polished) is slick!
>
> 10 ETH bounty to the first person to write in Go (MIT license) the full state transition function (BeaconState, BeaconBlock) -> (BeaconState, Error) in 1,024 lines or less.

## Work

27 Feb. 7pm: [Challenge accepted](https://twitter.com/protolambda/status/1100819044951908352). (\*insert challenge_accepted.jpeg\*)

3 Mar.: Done :tada:
 - ~8h of spec python->go porting & interpretation of non-code parts
 - ~8h of discussion in chats and GH issues; cutting edges for line limit + going through spec requirements.

## Result
 
The result: a monstrously looking (blame codegolf requirement) but complete spec implementation, in formatted Go.
 
*Even with an absurd line limit, the spec can be implemented.*

Now let's get back to work writing (and implementing) an awesome spec. 
One that is more readable, modular, testable, and useful to the community :octocat:

Thanks to all ETH 2.0 researchers and implementers for designing such a powerful but minimal specification.

## Future plans

The original intention was to create a transition that is:
 
- written in Go
    - types
    - low-level code benefits for speed
    - more real-world use-case
    - formal-ish & readable -> easier to verify behavior
- executable (alike to previous Python work)
    - good for testing
    - catch inconsistencies easily with IDE
- fast enough for new experiments
    - fuzzing
    - benchmark different possible extensions/modifications to the spec
- minimal
    - making changes to the spec should be easy
       - no dependencies, externals, etc.
       - clear definitions
    - a spec should not be too big in any case

Some of these intentions had to be ignored to make the line-limit work at the end,
 hence we are thinking about starting over, without prioritizing code-golfing. 

However, the line was also good for some things:

- Found several parts in the spec with small inconsistencies / poor wording
- Submitted a PR to fix some things, more to come.
- Scrutinized the necessity of helper functions. Some of the bigger reductions in line count may actually be welcome in the spec.
- Worked out the non-pseudocode parts of the spec. Some parts of the spec look simple,
    but actually require lots of data joins and lookups, which we want to avoid.
    Some PRs may follow out of this to make the spec more implementers friendly.

Further project ideas/goals will be discussed on EthCC, suggestions welcome!


## line count for bounty

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
concatenate the files, and you get 1024 (reduce package name lines for 7/8 files) (or less, if you reduce duplicate imports)
```


Git ref of beacon spec used for this challenge: [8df7de150e68408b78d6488a6f4c9cf8e18c4405](https://github.com/ethereum/eth2.0-specs/blob/8df7de150e68408b78d6488a6f4c9cf8e18c4405/specs/core/0_beacon-chain.md) (Current dev branch at the time of starting the challenge).

### Counting lines

```
bash linecount.bash
```

Yes this is bad. But fun, and code golfing = more scrutiny towards spec, we look more at the necessity of functions.
 I.e. the spec improves in the process.

## License

MIT. Container types are adapted from CC0-licensed types in original ETH 2.0 specification doc.

