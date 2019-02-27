package beacon_challenge

import (
	"errors"
	"fmt"
)

// interface required by Justin Drake for challenge.
func StateTransition(preState *BeaconState, block *BeaconBlock) (res *BeaconState, err error) {
	// We work on a copy of the input state. If the block is invalid, or input is re-used, we don't have to care.
	state := preState.Copy()
	// happens at the start of every slot
	for i := state.slot; i <= block.slot; i++ {
		SlotTransition(state)
	}
	// happens at every block
	if err := ApplyBlock(state, block); err != nil {
		return nil, err
	}
	// "happens at the end of the last slot of every epoch "
	if (state.slot + 1) % SLOTS_PER_EPOCH == 0 {
		EpochTransition(state)
		// State root verification
		if block.state_root != hash_tree_root(state) {
			return nil, errors.New("block has invalid state root")
		}
	}
	return state, nil
}

func ApplyBlock(state *BeaconState, block *BeaconBlock) error {
	// Verify slot
	if block.slot != state.slot {
		return errors.New("cannot apply block to pre-block-state at different slot")
	}

	// Block signature
	proposer := state.validator_registry[get_beacon_proposer_index(state, state.slot)]
	proposal := Proposal{slot: block.slot, shard: BEACON_CHAIN_SHARD_NUMBER, block_root: signed_root(block, "signature"), signature: block.signature}
	if !bls_verify(proposer.pubkey, signed_root(proposal, "signature"), proposal.signature, get_domain(state.fork, state.Epoch(), DOMAIN_PROPOSAL)) {
		return errors.New("block signature invalid")
	}


	// RANDAO
	if !bls_verify(proposer.pubkey, hash_tree_root(state.Epoch()), block.randao_reveal, get_domain(state.fork, state.Epoch(), DOMAIN_RANDAO)) {
		return errors.New("randao invalid")
	}
	state.latest_randao_mixes[state.Epoch() % LATEST_RANDAO_MIXES_LENGTH] = xorBytes32(get_randao_mix(state, state.Epoch()), hash(block.randao_reveal))

	// Eth1 data
	// If there exists an eth1_data_vote in state.eth1_data_votes for which eth1_data_vote.eth1_data == block.eth1_data (there will be at most one), set eth1_data_vote.vote_count += 1.
	// Otherwise, append to state.eth1_data_votes a new Eth1DataVote(eth1_data=block.eth1_data, vote_count=1).
	found := false
	for i, vote := range state.eth1_data_votes {
		if vote.eth1_data == block.eth1_data {
			state.eth1_data_votes[i].vote_count += 1
			found = true
			break
		}
	}
	if !found {
		state.eth1_data_votes = append(state.eth1_data_votes, Eth1DataVote{eth1_data: block.eth1_data, vote_count: 1})
	}

	// Transactions
	// START ------------------------------

	// Proposer slashings
	if len(block.body.proposer_slashings) > MAX_PROPOSER_SLASHINGS {
		return errors.New("too many proposer slashings")
	}
	for i, proposer_slashing := range block.body.proposer_slashings {
		proposer := state.validator_registry[proposer_slashing.proposer_index]
		if !(proposer_slashing.proposal_1.slot == proposer_slashing.proposal_2.slot &&
			proposer_slashing.proposal_1.shard == proposer_slashing.proposal_2.shard &&
			proposer_slashing.proposal_1.block_root != proposer_slashing.proposal_2.block_root &&
			proposer.slashed == false &&
			bls_verify(proposer.pubkey, signed_root(proposer_slashing.proposal_1, "signature"), proposer_slashing.proposal_1.signature, get_domain(state.fork, proposer_slashing.proposal_1.slot.ToEpoch(), DOMAIN_PROPOSAL)) &&
			bls_verify(proposer.pubkey, signed_root(proposer_slashing.proposal_2, "signature"), proposer_slashing.proposal_2.signature, get_domain(state.fork, proposer_slashing.proposal_2.slot.ToEpoch(), DOMAIN_PROPOSAL))) {
			return errors.New(fmt.Sprintf("proposer slashing %d is invalid", i))
		}
		slash_validator(state, proposer_slashing.proposer_index)
	}

	// Attester slashings
	for i, attester_slashing := range block.body.attester_slashings {
		slashable_attestation_1 := &attester_slashing.slashable_attestation_1
		slashable_attestation_2 := &attester_slashing.slashable_attestation_2
		// verify the attester_slashing
		if !(slashable_attestation_1.data != slashable_attestation_2.data &&
			(is_double_vote(&slashable_attestation_1.data, &slashable_attestation_2.data) ||
				is_surround_vote(&slashable_attestation_1.data, &slashable_attestation_2.data)) &&
			verify_slashable_attestation(state, slashable_attestation_1) &&
			verify_slashable_attestation(state, slashable_attestation_2)) {
			return errors.New(fmt.Sprintf("attester slashing %d is invalid", i))
		}
		// keep track of effectiveness
		slashedAny := false
		// run slashings where applicable
		ValLoop: for _, v1 := range slashable_attestation_1.validator_indices {
			for _, v2 := range slashable_attestation_1.validator_indices {
				if v1 == v2 && !state.validator_registry[v1].slashed {
					slash_validator(state, v1)
					slashedAny = true
					// continue to look for next validator in outer loop (because there are no duplicates in attestation)
					continue ValLoop
				}
			}
		}
		// "Verify that len(slashable_indices) >= 1."
		if !slashedAny {
			return errors.New(fmt.Sprintf("attester slashing %d is not effective, hence invalid", i))
		}
	}

	// Attestations
	// TODO

	// Deposits
	// TODO

	// Voluntary exits
	// TODO

	// Transfers
	// TODO

	// END ------------------------------

	return nil
}

func SlotTransition(state *BeaconState) {
	state.slot += 1.

	// Let previous_block_root be the hash_tree_root of the previous beacon block processed in the chain.
	state.latest_block_roots[(state.slot - 1) % LATEST_BLOCK_ROOTS_LENGTH] = state.latest_block_roots[(state.slot - 2) % LATEST_BLOCK_ROOTS_LENGTH]
	if state.slot % LATEST_BLOCK_ROOTS_LENGTH == 0 {
		state.batched_block_roots = append(state.batched_block_roots, merkle_root(state.latest_block_roots))
	}
}

func EpochTransition(state *BeaconState) {
	current_epoch := state.Epoch()
	previous_epoch := state.Epoch()
	next_epoch := current_epoch + 1

	// TODO more helper stuff

	// Eth1 Data

	// Justification and finalization
	// > Justification
	// > Finalization

	// Crosslinks

	// Rewards & Penalties

	// > Justification and finalization
	// >> case 1
	// >> case 2

	// > Attestation inclusion

	// > Crosslinks

	// > Ejections

	// Validator registry and shuffling data

	// > update registry

	// > process slashings

	// > process exit queue

	// > final updates

}

func verify_slashable_attestation(state *BeaconState, attestation *SlashableAttestation) bool {
	// TODO
	return false
}

func is_double_vote(a *AttestationData, b *AttestationData) bool {
	// TODO
	return false
}


func is_surround_vote(a *AttestationData, b *AttestationData) bool {
	// TODO
	return false
}

func slash_validator(state *BeaconState, index ValidatorIndex) {
	// TODO
}

func get_randao_mix(state *BeaconState, epoch Epoch) Bytes32 {
	// TODO
	return Bytes32{}
}

func get_domain(fork Fork, epoch Epoch, dom BlsDomain) BlsDomain {
	// TODO
	return 0
}

func get_beacon_proposer_index(state *BeaconState, slot Slot) ValidatorIndex {
	// TODO
	return 0
}