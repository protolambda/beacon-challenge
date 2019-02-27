package beacon_challenge

import (
	"encoding/binary"
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
	if len(block.body.attester_slashings) > MAX_ATTESTER_SLASHINGS {
		return errors.New("too many attester slashings")
	}
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
	if len(block.body.attestations) > MAX_ATTESTATIONS {
		return errors.New("too many attestations")
	}
	for i, attestation := range block.body.attestations {

		justified_epoch := state.previous_justified_epoch
		if (attestation.data.slot + 1).ToEpoch() >= state.Epoch() {
			justified_epoch = state.justified_epoch
		}
		blockRoot, blockRootErr := get_block_root(state, attestation.data.justified_epoch.GetStartSlot())
		if !(attestation.data.slot >= GENESIS_SLOT &&
			attestation.data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot &&
			state.slot < attestation.data.slot + SLOTS_PER_EPOCH &&
			attestation.data.justified_epoch == justified_epoch &&
			(blockRootErr == nil && attestation.data.justified_block_root == blockRoot) &&
			(state.latest_crosslinks[attestation.data.shard] == attestation.data.latest_crosslink ||
				state.latest_crosslinks[attestation.data.shard] == Crosslink{crosslink_data_root: attestation.data.crosslink_data_root, epoch: attestation.data.slot.ToEpoch()})) {
			return errors.New(fmt.Sprintf("attestation %d is not valid", i))
		}
		// Verify bitfields and aggregate signature

		// phase 0 only:
		if !(attestation.custody_bitfield.IsZero() && attestation.aggregation_bitfield.IsZero()) {
			return errors.New(fmt.Sprintf("attestation %d has non-zero bitfields, illegal in phase 0", i))
		}

		crosslink_committees := get_crosslink_committees_at_slot(state, attestation.data.slot, false)
		crosslink_committee := CrosslinkCommittee{}
		for _, committee := range crosslink_committees {
			if committee.Shard == attestation.data.shard {
				crosslink_committee = committee
				break
			}
		}
		// TODO spec is weak here: it's not very explicit about length of bitfields.
		//  Let's just make sure they are the size of the committee
		if attestation.aggregation_bitfield.Length == uint64(len(crosslink_committee.Committee)) ||
			attestation.custody_bitfield.Length == uint64(len(crosslink_committee.Committee)) {
			return errors.New(fmt.Sprintf("attestation %d has bitfield(s) with incorrect size", i))
		}
		// phase 0 only
		if !attestation.aggregation_bitfield.IsZero() || !attestation.custody_bitfield.IsZero() {
			return errors.New(fmt.Sprintf("attestation %d has non-zero bitfield(s)", i))
		}

		participants := get_attestation_participants(state, &attestation.data, &attestation.aggregation_bitfield)
		custody_bit_1_participants := get_attestation_participants(state, &attestation.data, &attestation.custody_bitfield)
		custody_bit_0_participants := make([]ValidatorIndex, 0, len(crosslink_committee.Committee) - len(custody_bit_1_participants))
		// Get the opposite of the custody_bit_1_participants: the remaining validators in the committee
		for _, i := range crosslink_committee.Committee {
			found := false
			for _, j := range custody_bit_1_participants {
				if i == j {
					found = true
					break
				}
			}
			if !found {
				custody_bit_0_participants = append(custody_bit_0_participants, i)
			}
		}

		// get lists of pubkeys for both 0 and 1 custody-bits
		custody_bit_0_pubkeys := make([]BLSPubkey, len(custody_bit_0_participants))
		for i, v := range custody_bit_0_participants {
			custody_bit_0_pubkeys[i] = state.validator_registry[v].pubkey
		}
		custody_bit_1_pubkeys := make([]BLSPubkey, len(custody_bit_1_participants))
		for i, v := range custody_bit_1_participants {
			custody_bit_1_pubkeys[i] = state.validator_registry[v].pubkey
		}
		// aggregate each of the two lists
		pubKeys := []BLSPubkey{
			bls_aggregate_pubkeys(custody_bit_0_pubkeys),
			bls_aggregate_pubkeys(custody_bit_1_pubkeys),
		}
		// hash the attestation data with 0 and 1 as bit
		hashes := []Root{
			hash_tree_root(AttestationDataAndCustodyBit{attestation.data, false}),
			hash_tree_root(AttestationDataAndCustodyBit{attestation.data, true}),
		}
		// now verify the two
		if !bls_verify_multiple(pubKeys, hashes, attestation.aggregate_signature,
			get_domain(state.fork, attestation.data.slot.ToEpoch(), DOMAIN_ATTESTATION)) {
			return errors.New(fmt.Sprintf("attestation %d has invalid aggregated BLS signature", i))
		}

		// phase 0 only:
		if attestation.data.crosslink_data_root != ZERO_HASH {
			return errors.New(fmt.Sprintf("attestation %d has invalid crosslink: root must be 0 in phase 0", i))
		}
	}

	// Deposits
	if len(block.body.deposits) > MAX_DEPOSITS {
		return errors.New("too many deposits")
	}
	for i, dep := range block.body.deposits {
		if dep.index != state.deposit_index {
			return errors.New(fmt.Sprintf("deposit %d has index %d that does not match with state index %d", i, dep.index, state.deposit_index))
		}
		// Let serialized_deposit_data be the serialized form of deposit.deposit_data.
		// It should be 8 bytes for deposit_data.amount
		//  followed by 8 bytes for deposit_data.timestamp
		//  and then the DepositInput bytes.
		// That is, it should match deposit_data in the Ethereum 1.0 deposit contract
		//  of which the hash was placed into the Merkle tree.
		dep_input_bytes := ssz_encode(dep.deposit_data.deposit_input)
		serialized_deposit_data := make([]byte, 8 + 8 + len(dep_input_bytes), 8 + 8 + len(dep_input_bytes))
		binary.LittleEndian.PutUint64(serialized_deposit_data[0:8], uint64(dep.deposit_data.amount))
		binary.LittleEndian.PutUint64(serialized_deposit_data[8:16], uint64(dep.deposit_data.timestamp))
		copy(serialized_deposit_data[16:], dep_input_bytes)

		// verify the deposit
		if !verify_merkle_branch(hash(serialized_deposit_data), dep.branch, DEPOSIT_CONTRACT_TREE_DEPTH,
			uint64(dep.index), state.latest_eth1_data.deposit_root) {
			return errors.New(fmt.Sprintf("deposit %d has merkle proof that failed to be verified", i))
		}
		process_deposit(state, &dep)
		state.deposit_index += 1
	}

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

func process_deposit(state *BeaconState, dep *Deposit) {
	// TODO
}

func get_attestation_participants(state *BeaconState, data *AttestationData, bitfield *Bitfield) []ValidatorIndex {
	// TODO implement spec function, instead of shortcut
	res := make([]ValidatorIndex, 0)
	// Phase 0: bitfields will be 0, so output list will be empty.
	return res
}

type CrosslinkCommittee struct {
	Committee []ValidatorIndex
	Shard Shard
}

// Return the list of (committee, shard) tuples for the slot.
//
// Note: There are two possible shufflings for crosslink committees for a
//  slot in the next epoch -- with and without a registryChange
func get_crosslink_committees_at_slot(state *BeaconState, slot Slot, registryChange bool) []CrosslinkCommittee {
	/* TODO port to Go
    epoch = slot_to_epoch(slot)
    current_epoch = get_current_epoch(state)
    previous_epoch = get_previous_epoch(state)
    next_epoch = current_epoch + 1

    assert previous_epoch <= epoch <= next_epoch

    if epoch == current_epoch:
        committees_per_epoch = get_current_epoch_committee_count(state)
        seed = state.current_shuffling_seed
        shuffling_epoch = state.current_shuffling_epoch
        shuffling_start_shard = state.current_shuffling_start_shard
    elif epoch == previous_epoch:
        committees_per_epoch = get_previous_epoch_committee_count(state)
        seed = state.previous_shuffling_seed
        shuffling_epoch = state.previous_shuffling_epoch
        shuffling_start_shard = state.previous_shuffling_start_shard
    elif epoch == next_epoch:
        current_committees_per_epoch = get_current_epoch_committee_count(state)
        committees_per_epoch = get_next_epoch_committee_count(state)
        shuffling_epoch = next_epoch

        epochs_since_last_registry_update = current_epoch - state.validator_registry_update_epoch
        if registry_change:
            seed = generate_seed(state, next_epoch)
            shuffling_start_shard = (state.current_shuffling_start_shard + current_committees_per_epoch) % SHARD_COUNT
        elif epochs_since_last_registry_update > 1 and is_power_of_two(epochs_since_last_registry_update):
            seed = generate_seed(state, next_epoch)
            shuffling_start_shard = state.current_shuffling_start_shard
        else:
            seed = state.current_shuffling_seed
            shuffling_start_shard = state.current_shuffling_start_shard

    shuffling = get_shuffling(
        seed,
        state.validator_registry,
        shuffling_epoch,
    )
    offset = slot % SLOTS_PER_EPOCH
    committees_per_slot = committees_per_epoch // SLOTS_PER_EPOCH
    slot_start_shard = (shuffling_start_shard + committees_per_slot * offset) % SHARD_COUNT

    return [
        (
            shuffling[committees_per_slot * offset + i],
            (slot_start_shard + i) % SHARD_COUNT,
        )
        for i in range(committees_per_slot)
    ]
	 */
}

// Return the block root at a recent slot.
func get_block_root(state *BeaconState, slot Slot) (Root, error) {
	if !(state.slot <= slot + LATEST_BLOCK_ROOTS_LENGTH && slot < state.slot) {
		return ZERO_HASH, errors.New("slot is not a recent slot, cannot find block root")
	}
	return state.latest_block_roots[slot % LATEST_BLOCK_ROOTS_LENGTH], nil
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