package challenge

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

// StateTransition interface required by Justin Drake for challenge.

// transition requirement: the pre-state latest_blocks[parent block's slot] should be loaded with the root of the parent block.
func StateTransition(preState *BeaconState, block *BeaconBlock) (res *BeaconState, err error) {
	if preState.slot >= block.slot {
		return nil, errors.New("cannot handle block on top of pre-state with equal or higher slot than block")
	}
	// We work on a copy of the input state. If the block is invalid, or input is re-used, we don't have to care.
	state := preState.Copy()
	// happens at the start of every slot
	for i := state.slot; i < block.slot; i++ {
		// Verified earlier, before calling StateTransition:
		// > The parent block with root `block.parent_root` has been processed and accepted
		// Hence, we can update latest block roots with the parent block root
		SlotTransition(state, block.parent_root)
	}
	// happens at every block
	if err := ApplyBlock(state, block); err != nil {
		return nil, err
	}
	// "happens at the end of the last slot of every epoch "
	if (state.slot+1)%SLOTS_PER_EPOCH == 0 {
		EpochTransition(state)
	}
	// State root verification
	if block.state_root != hash_tree_root(state) {
		return nil, errors.New("block has invalid state root")
	}
	return state, nil
}

func ApplyBlock(state *BeaconState, block *BeaconBlock) error {
	// Verify slot
	if block.slot != state.slot {
		return errors.New("cannot apply block to pre-block-state at different slot")
	}

	proposer := state.validator_registry[get_beacon_proposer_index(state, state.slot)]
	// Block signature
	{
		proposal := Proposal{slot: block.slot, shard: BEACON_CHAIN_SHARD_NUMBER, block_root: signed_root(block, "signature"), signature: block.signature}
		if !bls_verify(proposer.pubkey, signed_root(proposal, "signature"), proposal.signature, get_domain(state.fork, state.Epoch(), DOMAIN_PROPOSAL)) {
			return errors.New("block signature invalid")
		}
	}

	// RANDAO
	{
		if !bls_verify(proposer.pubkey, hash_tree_root(state.Epoch()), block.randao_reveal, get_domain(state.fork, state.Epoch(), DOMAIN_RANDAO)) {
			return errors.New("randao invalid")
		}
		state.latest_randao_mixes[state.Epoch()%LATEST_RANDAO_MIXES_LENGTH] = xorBytes32(get_randao_mix(state, state.Epoch()), hash(block.randao_reveal[:]))
	}

	// Eth1 data
	{
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
	}

	// Transactions
	// START ------------------------------

	// Proposer slashings
	{
		if len(block.body.proposer_slashings) > MAX_PROPOSER_SLASHINGS {
			return errors.New("too many proposer slashings")
		}
		for i, ps := range block.body.proposer_slashings {
			if !is_validator_index(state, ps.proposer_index) {
				return errors.New("invalid proposer index")
			}
			proposer := state.validator_registry[ps.proposer_index]
			if !(ps.proposal_1.slot == ps.proposal_2.slot && ps.proposal_1.shard == ps.proposal_2.shard &&
				ps.proposal_1.block_root != ps.proposal_2.block_root && proposer.slashed == false &&
				bls_verify(proposer.pubkey, signed_root(ps.proposal_1, "signature"), ps.proposal_1.signature, get_domain(state.fork, ps.proposal_1.slot.ToEpoch(), DOMAIN_PROPOSAL)) &&
				bls_verify(proposer.pubkey, signed_root(ps.proposal_2, "signature"), ps.proposal_2.signature, get_domain(state.fork, ps.proposal_2.slot.ToEpoch(), DOMAIN_PROPOSAL))) {
				return errors.New(fmt.Sprintf("proposer slashing %d is invalid", i))
			}
			if err := slash_validator(state, ps.proposer_index); err != nil {
				return err
			}
		}
	}

	// Attester slashings
	{
		if len(block.body.attester_slashings) > MAX_ATTESTER_SLASHINGS {
			return errors.New("too many attester slashings")
		}
		for i, attester_slashing := range block.body.attester_slashings {
			sa1, sa2 := &attester_slashing.slashable_attestation_1, &attester_slashing.slashable_attestation_2
			// verify the attester_slashing
			if !(sa1.data != sa2.data && (is_double_vote(&sa1.data, &sa2.data) || is_surround_vote(&sa1.data, &sa2.data)) &&
				verify_slashable_attestation(state, sa1) && verify_slashable_attestation(state, sa2)) {
				return errors.New(fmt.Sprintf("attester slashing %d is invalid", i))
			}
			// keep track of effectiveness
			slashedAny := false
			// run slashings where applicable
		ValLoop:
			// indices are trusted, they have been verified by verify_slashable_attestation(...)
			for _, v1 := range sa1.validator_indices {
				for _, v2 := range sa2.validator_indices {
					if v1 == v2 && !state.validator_registry[v1].slashed {
						if err := slash_validator(state, v1); err != nil {
							return err
						}
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
	}

	// Attestations
	{
		if len(block.body.attestations) > MAX_ATTESTATIONS {
			return errors.New("too many attestations")
		}
		for i, attestation := range block.body.attestations {

			justified_epoch := state.previous_justified_epoch
			if (attestation.data.slot + 1).ToEpoch() >= state.Epoch() {
				justified_epoch = state.justified_epoch
			}
			blockRoot, blockRootErr := get_block_root(state, attestation.data.justified_epoch.GetStartSlot())
			if !(attestation.data.slot >= GENESIS_SLOT && attestation.data.slot+MIN_ATTESTATION_INCLUSION_DELAY <= state.slot &&
				state.slot < attestation.data.slot+SLOTS_PER_EPOCH && attestation.data.justified_epoch == justified_epoch &&
				(blockRootErr == nil && attestation.data.justified_block_root == blockRoot) &&
				(state.latest_crosslinks[attestation.data.shard] == attestation.data.latest_crosslink ||
					state.latest_crosslinks[attestation.data.shard] == Crosslink{crosslink_data_root: attestation.data.crosslink_data_root, epoch: attestation.data.slot.ToEpoch()})) {
				return errors.New(fmt.Sprintf("attestation %d is not valid", i))
			}
			// Verify bitfields and aggregate signature
			// custody bitfield is phase 0 only:
			if attestation.aggregation_bitfield.IsZero() || !attestation.custody_bitfield.IsZero() {
				return errors.New(fmt.Sprintf("attestation %d has incorrect bitfield(s)", i))
			}

			crosslink_committees, err := get_crosslink_committees_at_slot(state, attestation.data.slot, false)
			if err != nil {
				return err
			}
			crosslink_committee := CrosslinkCommittee{}
			for _, committee := range crosslink_committees {
				if committee.Shard == attestation.data.shard {
					crosslink_committee = committee
					break
				}
			}
			// TODO spec is weak here: it's not very explicit about length of bitfields.
			//  Let's just make sure they are the size of the committee
			if !attestation.aggregation_bitfield.verifySize(uint64(len(crosslink_committee.Committee))) ||
				!attestation.custody_bitfield.verifySize(uint64(len(crosslink_committee.Committee))) {
				return errors.New(fmt.Sprintf("attestation %d has bitfield(s) with incorrect size", i))
			}
			// phase 0 only
			if !attestation.aggregation_bitfield.IsZero() || !attestation.custody_bitfield.IsZero() {
				return errors.New(fmt.Sprintf("attestation %d has non-zero bitfield(s)", i))
			}

			participants, err := get_attestation_participants(state, &attestation.data, &attestation.aggregation_bitfield)
			if err != nil {
				return errors.New("participants could not be derived from aggregation_bitfield")
			}
			custody_bit_1_participants, err := get_attestation_participants(state, &attestation.data, &attestation.custody_bitfield)
			if err != nil {
				return errors.New("participants could not be derived from custody_bitfield")
			}
			custody_bit_0_participants := participants.Minus(custody_bit_1_participants)

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
			pubKeys := []BLSPubkey{bls_aggregate_pubkeys(custody_bit_0_pubkeys), bls_aggregate_pubkeys(custody_bit_1_pubkeys)}
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
			if attestation.data.crosslink_data_root != (Root{}) {
				return errors.New(fmt.Sprintf("attestation %d has invalid crosslink: root must be 0 in phase 0", i))
			}
		}
	}

	// Deposits
	{
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
			serialized_deposit_data := make([]byte, 8+8+len(dep_input_bytes), 8+8+len(dep_input_bytes))
			binary.LittleEndian.PutUint64(serialized_deposit_data[0:8], uint64(dep.deposit_data.amount))
			binary.LittleEndian.PutUint64(serialized_deposit_data[8:16], uint64(dep.deposit_data.timestamp))
			copy(serialized_deposit_data[16:], dep_input_bytes)

			// verify the deposit
			if !verify_merkle_branch(hash(serialized_deposit_data), dep.branch, DEPOSIT_CONTRACT_TREE_DEPTH,
				uint64(dep.index), state.latest_eth1_data.deposit_root) {
				return errors.New(fmt.Sprintf("deposit %d has merkle proof that failed to be verified", i))
			}
			if err := process_deposit(state, &dep); err != nil {
				return err
			}
			state.deposit_index += 1
		}
	}

	// Voluntary exits
	{
		if len(block.body.voluntary_exits) > MAX_VOLUNTARY_EXITS {
			return errors.New("too many voluntary exits")
		}
		for i, exit := range block.body.voluntary_exits {
			validator := state.validator_registry[exit.validator_index]
			if !(validator.exit_epoch > get_delayed_activation_exit_epoch(state.Epoch()) &&
				state.Epoch() > exit.epoch &&
				bls_verify(validator.pubkey, signed_root(exit, "signature"),
					exit.signature, get_domain(state.fork, exit.epoch, DOMAIN_EXIT))) {
				return errors.New(fmt.Sprintf("voluntary exit %d could not be verified", i))
			}
			initiate_validator_exit(state, exit.validator_index)
		}
	}

	// Transfers
	{
		if len(block.body.transfers) > MAX_TRANSFERS {
			return errors.New("too many transfers")
		}
		// check if all TXs are distinct
		distinctionCheckSet := make(map[BLSSignature]uint64)
		for i, v := range block.body.transfers {
			if existing, ok := distinctionCheckSet[v.signature]; ok {
				return errors.New(fmt.Sprintf("transfer %d is the same as transfer %d, aborting", i, existing))
			}
			distinctionCheckSet[v.signature] = uint64(i)
		}

		for i, transfer := range block.body.transfers {
			withdrawCred := Root{}
			withdrawCred[31] = BLS_WITHDRAWAL_PREFIX_BYTE
			copy(withdrawCred[1:], hash(transfer.pubkey[:])[1:])
			// verify transfer data + signature. No separate error messages for line limit challenge...
			if !(state.validator_balances[transfer.from] >= transfer.amount && state.validator_balances[transfer.from] >= transfer.fee &&
				((state.validator_balances[transfer.from] == transfer.amount+transfer.fee) ||
					(state.validator_balances[transfer.from] >= transfer.amount+transfer.fee+MIN_DEPOSIT_AMOUNT)) &&
				state.slot == transfer.slot &&
				(state.Epoch() >= state.validator_registry[transfer.from].withdrawable_epoch || state.validator_registry[transfer.from].activation_epoch == FAR_FUTURE_EPOCH) &&
				state.validator_registry[transfer.from].withdrawal_credentials == withdrawCred &&
				bls_verify(transfer.pubkey, signed_root(transfer, "signature"), transfer.signature, get_domain(state.fork, transfer.slot.ToEpoch(), DOMAIN_TRANSFER))) {
				return errors.New(fmt.Sprintf("transfer %d is invalid", i))
			}
			state.validator_balances[transfer.from] -= transfer.amount + transfer.fee
			state.validator_balances[transfer.to] += transfer.amount
			state.validator_balances[get_beacon_proposer_index(state, state.slot)] += transfer.fee
		}
	}

	// END ------------------------------

	return nil
}

// Let previous_block_root be the hash_tree_root of the previous beacon block processed in the chain.
func SlotTransition(state *BeaconState, previous_block_root Root) {
	state.slot += 1

	state.latest_block_roots[(state.slot-1)%LATEST_BLOCK_ROOTS_LENGTH] = previous_block_root
	if state.slot%LATEST_BLOCK_ROOTS_LENGTH == 0 {
		// yes, this is ugly, typing requires us to be explict when we want to merkleize a list of non-bytes32 items.
		merkle_input := make([]Bytes32, len(state.latest_block_roots))
		for i := 0; i < len(state.latest_block_roots); i++ {
			merkle_input[i] = Bytes32(state.latest_block_roots[i])
		}
		state.batched_block_roots = append(state.batched_block_roots, merkle_root(merkle_input))
	}
}

func EpochTransition(state *BeaconState) {
	current_epoch, previous_epoch := state.Epoch(), state.PreviousEpoch()
	next_epoch := current_epoch + 1

	// attestation-source-index for a given epoch, by validator index.
	// The earliest attestation (by inclusion_slot) is referenced in this map.
	previous_epoch_earliest_attestations := make(map[ValidatorIndex]uint64)
	for i, att := range state.latest_attestations {
		// error ignored, attestation is trusted.
		participants, _ := get_attestation_participants(state, &att.data, &att.aggregation_bitfield)
		for _, participant := range participants {
			if att.data.slot.ToEpoch() == previous_epoch {
				if existingIndex, ok := previous_epoch_earliest_attestations[participant]; !ok || state.latest_attestations[existingIndex].inclusion_slot < att.inclusion_slot {
					previous_epoch_earliest_attestations[participant] = uint64(i)
				}
			}
		}
	}

	// Eth1 Data
	{
		if next_epoch%EPOCHS_PER_ETH1_VOTING_PERIOD == 0 {
			// look for a majority vote
			for _, data_vote := range state.eth1_data_votes {
				if data_vote.vote_count*2 > uint64(EPOCHS_PER_ETH1_VOTING_PERIOD)*uint64(SLOTS_PER_EPOCH) {
					// more than half the votes in this voting period were for this data_vote value
					state.latest_eth1_data = data_vote.eth1_data
					break
				}
			}
			// reset votes
			state.eth1_data_votes = make([]Eth1DataVote, 0)
		}
	}

	// Helper data
	// Note: Rewards and penalties are for participation in the previous epoch,
	//  so the "active validator" set is drawn from get_active calls on previous_epoch
	previous_active_validator_indices := ValidatorIndexSet(get_active_validator_indices(state.validator_registry, previous_epoch))

	// Copy over the keys of our per-validator map to get a set of validator indices with previous epoch attestations.
	previous_epoch_attester_indices := make(ValidatorIndexSet, 0, len(previous_epoch_earliest_attestations))
	for vIndex := range previous_epoch_earliest_attestations {
		previous_epoch_attester_indices = append(previous_epoch_attester_indices, vIndex)
	}
	previous_epoch_boundary_attester_indices, previous_epoch_head_attester_indices, current_epoch_boundary_attester_indices := make(ValidatorIndexSet, 0), make(ValidatorIndexSet, 0), make(ValidatorIndexSet, 0)
	for _, att := range state.latest_attestations {
		if ep := att.data.slot.ToEpoch(); ep == previous_epoch {

			boundary_block_root, err := get_block_root(state, previous_epoch.GetStartSlot())
			isForBoundary := err == nil && att.data.epoch_boundary_root == boundary_block_root

			head_block_root, err := get_block_root(state, att.data.slot)
			isForHead := err == nil && att.data.beacon_block_root == head_block_root

			// error ignored, attestation is trusted.
			participants, _ := get_attestation_participants(state, &att.data, &att.aggregation_bitfield)
			for _, vIndex := range participants {

				// If the attestation is for a block boundary:
				if isForBoundary {
					previous_epoch_boundary_attester_indices = append(previous_epoch_boundary_attester_indices, vIndex)
				}

				if isForHead {
					previous_epoch_head_attester_indices = append(previous_epoch_head_attester_indices, vIndex)
				}
			}
		} else if ep == current_epoch {
			boundary_block_root, err := get_block_root(state, current_epoch.GetStartSlot())
			isForBoundary := err == nil && att.data.epoch_boundary_root == boundary_block_root
			// error ignored, attestation is trusted.
			participants, _ := get_attestation_participants(state, &att.data, &att.aggregation_bitfield)
			for _, vIndex := range participants {
				// If the attestation is for a block boundary:
				if isForBoundary {
					current_epoch_boundary_attester_indices = append(current_epoch_boundary_attester_indices, vIndex)
				}
			}
		}
	}

	// Justification and finalization
	{
		previous_epoch_boundary_attesting_balance := get_total_balance(state, previous_epoch_boundary_attester_indices)
		current_epoch_boundary_attesting_balance := get_total_balance(state, current_epoch_boundary_attester_indices)
		previous_total_balance := get_total_balance(state, get_active_validator_indices(state.validator_registry, previous_epoch))
		current_total_balance := get_total_balance(state, get_active_validator_indices(state.validator_registry, current_epoch))

		// > Justification
		new_justified_epoch := state.justified_epoch
		state.justification_bitfield = state.justification_bitfield << 1
		if 3*previous_epoch_boundary_attesting_balance >= 2*previous_total_balance {
			state.justification_bitfield |= 2
			new_justified_epoch = previous_epoch
		}
		if 3*current_epoch_boundary_attesting_balance >= 2*current_total_balance {
			state.justification_bitfield |= 1
			new_justified_epoch = current_epoch
		}
		// > Finalization
		if (state.justification_bitfield>>1)&7 == 7 && state.previous_justified_epoch == previous_epoch-2 {
			state.finalized_epoch = state.previous_justified_epoch
		}
		if (state.justification_bitfield>>1)&3 == 3 && state.previous_justified_epoch == previous_epoch-1 {
			state.finalized_epoch = state.previous_justified_epoch
		}
		if (state.justification_bitfield>>0)&7 == 7 && state.justified_epoch == previous_epoch-1 {
			state.finalized_epoch = state.justified_epoch
		}
		if (state.justification_bitfield>>0)&3 == 3 && state.justified_epoch == previous_epoch {
			state.finalized_epoch = state.justified_epoch
		}
		// > Final part
		state.previous_justified_epoch = state.justified_epoch
		state.justified_epoch = new_justified_epoch
	}

	// All recent winning crosslinks, regardless of weight.
	winning_roots := make(map[Shard]Root)
	// Remember the attesters of each winning crosslink root (1 per shard)
	// Also includes non-persisted winners (i.e. winning attesters not bigger than 2/3 of total committee weight)
	crosslink_winners := make(map[Root]ValidatorIndexSet)
	crosslink_winners_weight := make(map[Root]Gwei)

	// Crosslinks
	{

		start, end := previous_epoch.GetStartSlot(), next_epoch.GetStartSlot()
		for slot := start; slot < end; slot++ {
			// epoch is trusted, ignore error
			crosslink_committees_at_slot, _ := get_crosslink_committees_at_slot(state, slot, false)
			for _, cross_comm := range crosslink_committees_at_slot {

				// The spec is insane in making everything a helper function, ignoring scope/encapsulation, and not being to-the-point.
				// All we need is to determine a crosslink root,
				//  "winning_root" (from all attestations in previous or current epoch),
				//  and keep track of its weight.
				crosslink_data_root := state.latest_crosslinks[cross_comm.Shard].crosslink_data_root

				// First look at all attestations, and sum the weights per root.
				weightedCrosslinks := make(map[Root]Gwei)
				for _, att := range state.latest_attestations {
					if ep := att.data.slot.ToEpoch(); ep == previous_epoch || ep == current_epoch &&
						att.data.shard == cross_comm.Shard &&
						att.data.crosslink_data_root == crosslink_data_root {
						// error ignored, attestation is trusted.
						participants, _ := get_attestation_participants(state, &att.data, &att.aggregation_bitfield)
						for _, participant := range participants {
							weightedCrosslinks[att.data.crosslink_data_root] += get_effective_balance(state, participant)
						}
					}
				}
				// Now determine the best root, by weight
				var winning_root Root
				winning_weight := Gwei(0)
				for root, weight := range weightedCrosslinks {
					if weight > winning_weight {
						winning_root = root
					}
					if weight == winning_weight {
						// break tie lexicographically
						for i := 0; i < 32; i++ {
							if root[i] > winning_root[i] {
								winning_root = root
								break
							}
						}
					}
				}
				// we need to remember attesters of winning root (for later rewarding, and exclusion to slashing)
				winning_attesting_committee_members := make(ValidatorIndexSet, 0)
				for _, att := range state.latest_attestations {
					if ep := att.data.slot.ToEpoch(); ep == previous_epoch || ep == current_epoch &&
						att.data.shard == cross_comm.Shard &&
						att.data.crosslink_data_root == winning_root {
						// error ignored, attestation is trusted.
						participants, _ := get_attestation_participants(state, &att.data, &att.aggregation_bitfield)
						for _, participant := range participants {
							for _, vIndex := range cross_comm.Committee {
								if participant == vIndex {
									winning_attesting_committee_members = append(winning_attesting_committee_members, vIndex)
								}
							}
						}
					}
				}
				crosslink_winners[winning_root] = winning_attesting_committee_members
				winning_roots[cross_comm.Shard] = winning_root
				crosslink_winners_weight[winning_root] = winning_weight

				// If it has sufficient weight, the crosslink is accepted.
				if 3*winning_weight >= 2*get_total_balance(state, cross_comm.Committee) {
					state.latest_crosslinks[cross_comm.Shard] = Crosslink{
						epoch:               slot.ToEpoch(),
						crosslink_data_root: winning_root}
				}
			}
		}
	}

	// Rewards & Penalties
	{
		// Sum balances of the sets of validators from earlier
		previous_epoch_attesting_balance := get_total_balance(state, previous_epoch_attester_indices)
		previous_epoch_boundary_attesting_balance := get_total_balance(state, previous_epoch_boundary_attester_indices)
		previous_epoch_head_attesting_balance := get_total_balance(state, previous_epoch_head_attester_indices)

		// Note: previous_total_balance and previous_epoch_boundary_attesting_balance balance might be marginally
		// different than the actual balances during previous epoch transition.
		// Due to the tight bound on validator churn each epoch and small per-epoch rewards/penalties,
		// the potential balance difference is very low and only marginally affects consensus safety.
		previous_total_balance := get_total_balance(state, get_active_validator_indices(state.validator_registry, previous_epoch))

		base_reward_quotient := Gwei(integer_squareroot(uint64(previous_total_balance))) / BASE_REWARD_QUOTIENT

		base_reward := func(index ValidatorIndex) Gwei {
			// magic number 5 is from spec. (TODO add reasoning?)
			return get_effective_balance(state, index) / base_reward_quotient / 5
		}

		epochs_since_finality := next_epoch - state.finalized_epoch

		inactivity_penalty := func(index ValidatorIndex) Gwei {
			return base_reward(index) + (get_effective_balance(state, index) * Gwei(epochs_since_finality) / INACTIVITY_PENALTY_QUOTIENT / 2)
		}

		scaled_value := func(valueFn ValueFunction, scale Gwei) ValueFunction {
			return func(index ValidatorIndex) Gwei {
				return valueFn(index) * scale
			}
		}
		inclusion_distance := func(index ValidatorIndex) Slot {
			a := &state.latest_attestations[previous_epoch_earliest_attestations[index]]
			return a.inclusion_slot - a.data.slot
		}

		scale_by_inclusion := func(valueFn ValueFunction) ValueFunction {
			return func(index ValidatorIndex) Gwei {
				return valueFn(index) / Gwei(inclusion_distance(index))
			}
		}

		// rewardOrSlash: true = reward, false = slash
		applyRewardOrSlash := func(indices ValidatorIndexSet, rewardOrSlash bool, valueFn ValueFunction) {
			for _, vIndex := range indices {
				if rewardOrSlash {
					state.validator_balances[vIndex] += valueFn(vIndex)
				} else {
					state.validator_balances[vIndex] -= valueFn(vIndex)
				}
			}
		}

		// > Justification and finalization
		{
			if epochs_since_finality <= 4 {
				// >> case 1: finality was not too long ago

				// Slash validators that were supposed to be active, but did not do their work
				{
					//Justification-non-participation R-penalty
					applyRewardOrSlash(previous_active_validator_indices.Minus(previous_epoch_attester_indices), false, base_reward)

					//Boundary-attestation-non-participation R-penalty
					applyRewardOrSlash(previous_active_validator_indices.Minus(previous_epoch_boundary_attester_indices), false, base_reward)

					//Non-canonical-participation R-penalty
					applyRewardOrSlash(previous_active_validator_indices.Minus(previous_epoch_head_attester_indices), false, base_reward)
				}

				// Reward active validators that do their work
				{
					// Justification-participation reward
					applyRewardOrSlash(previous_epoch_attester_indices, true,
						scaled_value(base_reward, previous_epoch_attesting_balance/previous_total_balance))

					// Boundary-attestation reward
					applyRewardOrSlash(previous_epoch_boundary_attester_indices, true,
						scaled_value(base_reward, previous_epoch_boundary_attesting_balance/previous_total_balance))

					// Canonical-participation reward
					applyRewardOrSlash(previous_epoch_head_attester_indices, true,
						scaled_value(base_reward, previous_epoch_head_attesting_balance/previous_total_balance))

					// Attestation-Inclusion-delay reward: quicker = more reward
					applyRewardOrSlash(previous_epoch_attester_indices, true,
						scale_by_inclusion(scaled_value(base_reward, Gwei(MIN_ATTESTATION_INCLUSION_DELAY))))
				}
			} else {
				// >> case 2: more than 4 epochs since finality

				// Slash validators that were supposed to be active, but did not do their work
				{
					// Justification-inactivity penalty
					applyRewardOrSlash(previous_active_validator_indices.Minus(previous_epoch_attester_indices), false, inactivity_penalty)
					// Boundary-attestation-Inactivity penalty
					applyRewardOrSlash(previous_active_validator_indices.Minus(previous_epoch_boundary_attester_indices), false, inactivity_penalty)
					// Non-canonical-participation R-penalty
					applyRewardOrSlash(previous_active_validator_indices.Minus(previous_epoch_head_attester_indices), false, base_reward)
					// Penalization measure: double inactivity penalty + R-penalty
					applyRewardOrSlash(previous_active_validator_indices, false, func(index ValidatorIndex) Gwei {
						if state.validator_registry[index].slashed {
							return (2 * inactivity_penalty(index)) + base_reward(index)
						}
						return 0
					})
				}

				// Attestation delay measure
				{
					// Attestation-Inclusion-delay measure: less reward for long delays
					applyRewardOrSlash(previous_epoch_attester_indices, false, func(index ValidatorIndex) Gwei {
						return base_reward(index) - scale_by_inclusion(scaled_value(base_reward, Gwei(MIN_ATTESTATION_INCLUSION_DELAY)))(index)
					})
				}
			}
		}

		// > Attestation inclusion
		{
			// Attestations should be included timely.
			// TODO Difference from spec: it is easier (and faster) to iterate through the precomputed map
			for attester_index, att_index := range previous_epoch_earliest_attestations {
				proposer_index := get_beacon_proposer_index(state, state.latest_attestations[att_index].inclusion_slot)
				state.validator_balances[proposer_index] += base_reward(attester_index) / ATTESTATION_INCLUSION_REWARD_QUOTIENT
			}
		}

		// > Crosslinks
		{
			// Crosslinks should be created by the committees
			start, end := previous_epoch.GetStartSlot(), next_epoch.GetStartSlot()
			for slot := start; slot < end; slot++ {
				// epoch is trusted, ignore error
				crosslink_committees_at_slot, _ := get_crosslink_committees_at_slot(state, slot, false)
				for _, cross_comm := range crosslink_committees_at_slot {

					// We remembered the winning root
					// (i.e. the most attested crosslink root, doesn't have to be 2/3 majority)
					winning_root := winning_roots[cross_comm.Shard]

					// We remembered the attesters of the crosslink
					crosslink_attesters := crosslink_winners[winning_root]

					// Note: non-committee validators still count as attesters for a crosslink,
					//  hence the extra work to filter for just the validators in the committee
					committee_non_participants := ValidatorIndexSet(cross_comm.Committee).Minus(crosslink_attesters)

					committee_attesters_weight := crosslink_winners_weight[winning_root]
					total_committee_weight := get_total_balance(state, cross_comm.Committee)

					// Reward those that contributed to finding a winning root.
					applyRewardOrSlash(ValidatorIndexSet(cross_comm.Committee).Minus(committee_non_participants),
						true, func(index ValidatorIndex) Gwei {
							return base_reward(index) * committee_attesters_weight / total_committee_weight
						})
					// Slash those that opted for a different crosslink
					applyRewardOrSlash(committee_non_participants, false, base_reward)
				}
			}
		}

		// > Ejections
		{
			// After we are done slashing, eject the validators that don't have enough balance left.
			for _, vIndex := range get_active_validator_indices(state.validator_registry, current_epoch) {
				if state.validator_balances[vIndex] < EJECTION_BALANCE {
					exit_validator(state, vIndex)
				}
			}
		}
	}
	// Validator registry and shuffling data
	{
		// > update registry
		{
			state.previous_shuffling_epoch = state.current_shuffling_epoch
			state.previous_shuffling_start_shard = state.current_shuffling_start_shard
			state.previous_shuffling_seed = state.current_shuffling_seed

			if state.finalized_epoch > state.validator_registry_update_epoch {
				needsUpdate := true
				{
					committee_count := get_epoch_committee_count(get_active_validator_count(state.validator_registry, current_epoch))
					for i := uint64(0); i < committee_count; i++ {
						if shard := (state.current_shuffling_start_shard + Shard(i)) % SHARD_COUNT; state.latest_crosslinks[shard].epoch <= state.validator_registry_update_epoch {
							needsUpdate = false
						}
					}
				}
				if needsUpdate {
					update_validator_registry(state)
					state.current_shuffling_epoch = next_epoch
					// recompute committee count, some validators may not be active anymore due to the above update.
					committee_count := get_epoch_committee_count(get_active_validator_count(state.validator_registry, current_epoch))
					state.current_shuffling_start_shard = (state.current_shuffling_start_shard + Shard(committee_count)) % SHARD_COUNT
					// ignore error, current_shuffling_epoch is a trusted input
					state.current_shuffling_seed = generate_seed(state, state.current_shuffling_epoch)
				} else {
					// If a validator registry update does not happen:
					epochs_since_last_registry_update := current_epoch - state.validator_registry_update_epoch
					if epochs_since_last_registry_update > 1 && is_power_of_two(uint64(epochs_since_last_registry_update)) {
						state.current_shuffling_epoch = next_epoch
						// Note that state.current_shuffling_start_shard is left unchanged
						state.current_shuffling_seed = generate_seed(state, state.current_shuffling_epoch)
					}
				}
			}
		}

		// > process slashings
		{
			active_validator_indices := get_active_validator_indices(state.validator_registry, current_epoch)
			total_balance := get_total_balance(state, active_validator_indices)

			for index, validator := range state.validator_registry {
				if validator.slashed &&
					current_epoch == validator.withdrawable_epoch-(LATEST_SLASHED_EXIT_LENGTH/2) {
					epoch_index := current_epoch % LATEST_SLASHED_EXIT_LENGTH
					total_at_start := state.latest_slashed_balances[(epoch_index+1)%LATEST_SLASHED_EXIT_LENGTH]
					total_at_end := state.latest_slashed_balances[epoch_index]
					balance := get_effective_balance(state, ValidatorIndex(index))
					state.validator_balances[index] -= Max(balance*Min((total_at_end-total_at_start)*3, total_balance)/total_balance, balance/MIN_PENALTY_QUOTIENT)
				}
			}
		}

		// > process exit queue
		{
			eligible_indices := make(ValidatorIndexSet, 0)
			for index, validator := range state.validator_registry {
				if validator.withdrawable_epoch != FAR_FUTURE_EPOCH && current_epoch > validator.exit_epoch+MIN_VALIDATOR_WITHDRAWABILITY_DELAY {
					eligible_indices = append(eligible_indices, ValidatorIndex(index))
				}
			}
			// Sort in order of exit epoch, and validators that exit within the same epoch exit in order of validator index
			sort.Slice(eligible_indices, func(i int, j int) bool {
				return state.validator_registry[eligible_indices[i]].exit_epoch < state.validator_registry[eligible_indices[j]].exit_epoch
			})
			// eligible_indices is sorted here (in-place sorting)
			for i, end := uint64(0), uint64(len(eligible_indices)); i < MAX_EXIT_DEQUEUES_PER_EPOCH && i < end; i++ {
				prepare_validator_for_withdrawal(state, eligible_indices[i])
			}
		}

		// > final updates
		{
			state.latest_active_index_roots[(next_epoch+ACTIVATION_EXIT_DELAY)%LATEST_ACTIVE_INDEX_ROOTS_LENGTH] = hash_tree_root(get_active_validator_indices(state.validator_registry, next_epoch+ACTIVATION_EXIT_DELAY))
			state.latest_slashed_balances[next_epoch%LATEST_SLASHED_EXIT_LENGTH] = state.latest_slashed_balances[current_epoch%LATEST_SLASHED_EXIT_LENGTH]
			state.latest_randao_mixes[next_epoch%LATEST_RANDAO_MIXES_LENGTH] = get_randao_mix(state, current_epoch)
			// Remove any attestation in state.latest_attestations such that slot_to_epoch(attestation.data.slot) < current_epoch
			attests := make([]PendingAttestation, 0)
			for _, a := range state.latest_attestations {
				// only keep recent attestations. (for next epoch to process)
				if a.data.slot.ToEpoch() >= current_epoch {
					attests = append(attests, a)
				}
			}
			state.latest_attestations = attests
		}
	}
}

// Set the validator with the given index as withdrawable
// MIN_VALIDATOR_WITHDRAWABILITY_DELAY after the current epoch.
func prepare_validator_for_withdrawal(state *BeaconState, index ValidatorIndex) {
	state.validator_registry[index].withdrawable_epoch = state.Epoch() + MIN_VALIDATOR_WITHDRAWABILITY_DELAY
}

// Return the epoch at which an activation or exit triggered in epoch takes effect.
func get_delayed_activation_exit_epoch(epoch Epoch) Epoch {
	return epoch + 1 + ACTIVATION_EXIT_DELAY
}

// Exit the validator of the given index
func exit_validator(state *BeaconState, index ValidatorIndex) {
	validator := &state.validator_registry[index]
	delayed_activation_exit_epoch := get_delayed_activation_exit_epoch(state.Epoch())
	// The following updates only occur if not previous exited
	if validator.exit_epoch > delayed_activation_exit_epoch {
		return
	}
	validator.exit_epoch = delayed_activation_exit_epoch
}

// Initiate the validator of the given index
func initiate_validator_exit(state *BeaconState, index ValidatorIndex) {
	state.validator_registry[index].initiated_exit = true
}

func get_active_validator_count(validator_registry []Validator, epoch Epoch) (count uint64) {
	for _, v := range validator_registry {
		if v.IsActive(epoch) {
			count++
		}
	}
	return count
}

func get_active_validator_indices(validator_registry []Validator, epoch Epoch) []ValidatorIndex {
	res := make([]ValidatorIndex, 0, len(validator_registry))
	for i, v := range validator_registry {
		if v.IsActive(epoch) {
			res = append(res, ValidatorIndex(i))
		}
	}
	return res
}

// Return the effective balance (also known as "balance at stake") for a validator with the given index.
func get_effective_balance(state *BeaconState, index ValidatorIndex) Gwei {
	return Max(state.validator_balances[index], MAX_DEPOSIT_AMOUNT)
}

// Return the combined effective balance of an array of validators.
func get_total_balance(state *BeaconState, indices []ValidatorIndex) (sum Gwei) {
	for _, vIndex := range indices {
		sum += get_effective_balance(state, vIndex)
	}
	return sum
}

// Process a deposit from Ethereum 1.0.
func process_deposit(state *BeaconState, dep *Deposit) error {
	deposit_input := &dep.deposit_data.deposit_input

	if !bls_verify(deposit_input.pubkey, signed_root(deposit_input, "proof_of_possession"), deposit_input.proof_of_possession, get_domain(state.fork, state.Epoch(), DOMAIN_DEPOSIT)) {
		// simply don't handle the deposit. (TODO: should this be an error (making block invalid)?)
		return nil
	}

	val_index := ValidatorIndexMarker
	for i, v := range state.validator_registry {
		if v.pubkey == deposit_input.pubkey {
			val_index = ValidatorIndex(i)
			break
		}
	}

	// Check if it is a known validator that is depositing ("if pubkey not in validator_pubkeys")
	if val_index == ValidatorIndexMarker {
		// Not a known pubkey, add new validator
		validator := Validator{
			pubkey: state.validator_registry[val_index].pubkey, withdrawal_credentials: deposit_input.withdrawal_credentials,
			activation_epoch: FAR_FUTURE_EPOCH, exit_epoch: FAR_FUTURE_EPOCH, withdrawable_epoch: FAR_FUTURE_EPOCH,
			initiated_exit: false, slashed: false,
		}
		// Note: In phase 2 registry indices that have been withdrawn for a long time will be recycled.
		state.validator_registry, state.validator_balances = append(state.validator_registry, validator), append(state.validator_balances, dep.deposit_data.amount)
	} else {
		// known pubkey, check withdrawal credentials first, then increase balance.
		if state.validator_registry[val_index].withdrawal_credentials != deposit_input.withdrawal_credentials {
			return errors.New("deposit has wrong withdrawal credentials")
		}
		// Increase balance by deposit amount
		state.validator_balances[val_index] += dep.deposit_data.amount
	}
	return nil
}

// Update validator registry.
func update_validator_registry(state *BeaconState) {
	// The total effective balance of active validators
	total_balance := get_total_balance(state, get_active_validator_indices(state.validator_registry, state.Epoch()))

	// The maximum balance churn in Gwei (for deposits and exits separately)
	max_balance_churn := Max(MAX_DEPOSIT_AMOUNT, total_balance/(2*MAX_BALANCE_CHURN_QUOTIENT))

	// Activate validators within the allowable balance churn
	{
		balance_churn := Gwei(0)
		for index, validator := range state.validator_registry {
			if validator.activation_epoch == FAR_FUTURE_EPOCH && state.validator_balances[index] >= MAX_DEPOSIT_AMOUNT {
				// Check the balance churn would be within the allowance
				balance_churn += get_effective_balance(state, ValidatorIndex(index))
				if balance_churn > max_balance_churn {
					break
				}
				//  Activate validator
				validator.activation_epoch = get_delayed_activation_exit_epoch(state.Epoch())
			}
		}
	}

	// Exit validators within the allowable balance churn
	{
		balance_churn := Gwei(0)
		for index, validator := range state.validator_registry {
			if validator.exit_epoch == FAR_FUTURE_EPOCH && validator.initiated_exit {
				// Check the balance churn would be within the allowance
				balance_churn += get_effective_balance(state, ValidatorIndex(index))
				if balance_churn > max_balance_churn {
					break
				}
				// Exit validator
				exit_validator(state, ValidatorIndex(index))
			}
		}
	}
}

// Return the participant indices at for the attestation_data and bitfield
func get_attestation_participants(state *BeaconState, attestation_data *AttestationData, bitfield *Bitfield) (ValidatorIndexSet, error) {
	// Find the committee in the list with the desired shard
	crosslink_committees, err := get_crosslink_committees_at_slot(state, attestation_data.slot, false)
	if err != nil {
		return nil, err
	}

	var crosslink_committee []ValidatorIndex
	for _, cross_comm := range crosslink_committees {
		if cross_comm.Shard == attestation_data.shard {
			crosslink_committee = cross_comm.Committee
			break
		}
	}
	if crosslink_committee == nil {
		return nil, errors.New(fmt.Sprintf("cannot find crosslink committee at slot %d for shard %d", attestation_data.slot, attestation_data.shard))
	}
	if !bitfield.verifySize(uint64(len(crosslink_committee))) {
		return nil, errors.New("bitfield has wrong size for corresponding crosslink committee")
	}

	// Find the participating attesters in the committee
	participants := make(ValidatorIndexSet, 0)
	for i, vIndex := range crosslink_committee {
		if bitfield.GetBit(uint64(i)) == 1 {
			participants = append(participants, vIndex)
		}
	}
	return participants, nil
}

// Generate a seed for the given epoch
func generate_seed(state *BeaconState, epoch Epoch) Bytes32 {
	buf := make([]byte, 32*3)
	copy(buf[0:32], get_randao_mix(state, epoch-MIN_SEED_LOOKAHEAD)[:])
	// get_active_index_root in spec, but only used once, and the assertion is unnecessary, since epoch input is always trusted
	copy(buf[32:32*2], state.latest_active_index_roots[epoch%LATEST_ACTIVE_INDEX_ROOTS_LENGTH][:])
	binary.LittleEndian.PutUint64(buf[32*3-8:], uint64(epoch))
	return hash(buf)
}

// Return the number of committees in one epoch.
func get_epoch_committee_count(active_validator_count uint64) uint64 {
	return MaxU64(1, MinU64(uint64(SHARD_COUNT)/uint64(SLOTS_PER_EPOCH), active_validator_count/uint64(SLOTS_PER_EPOCH)/TARGET_COMMITTEE_SIZE)) * uint64(SLOTS_PER_EPOCH)
}

type CrosslinkCommittee struct {
	Committee []ValidatorIndex
	Shard     Shard
}

// Return the list of (committee, shard) tuples for the slot.
//
// Note: There are two possible shufflings for crosslink committees for a
//  slot in the next epoch -- with and without a registryChange
func get_crosslink_committees_at_slot(state *BeaconState, slot Slot, registryChange bool) ([]CrosslinkCommittee, error) {
	epoch, current_epoch, previous_epoch := slot.ToEpoch(), state.Epoch(), state.PreviousEpoch()
	next_epoch := current_epoch + 1

	if !(previous_epoch <= epoch && epoch <= next_epoch) {
		return nil, errors.New("could not retrieve crosslink committee for out of range slot")
	}

	var committees_per_epoch uint64
	var seed Bytes32
	var shuffling_epoch Epoch
	var shuffling_start_shard Shard
	if epoch == current_epoch {
		committees_per_epoch = get_epoch_committee_count(get_active_validator_count(state.validator_registry, current_epoch))
		seed = state.current_shuffling_seed
		shuffling_epoch = state.current_shuffling_epoch
		shuffling_start_shard = state.current_shuffling_start_shard
	} else if epoch == previous_epoch {
		committees_per_epoch = get_epoch_committee_count(get_active_validator_count(state.validator_registry, previous_epoch))
		seed = state.previous_shuffling_seed
		shuffling_epoch = state.previous_shuffling_epoch
		shuffling_start_shard = state.previous_shuffling_start_shard
	} else if epoch == next_epoch {
		current_committees_per_epoch := get_epoch_committee_count(get_active_validator_count(state.validator_registry, current_epoch))
		committees_per_epoch = get_epoch_committee_count(get_active_validator_count(state.validator_registry, next_epoch))
		shuffling_epoch = next_epoch

		epochs_since_last_registry_update := current_epoch - state.validator_registry_update_epoch
		if registryChange {
			seed = generate_seed(state, next_epoch)
			shuffling_start_shard = (state.current_shuffling_start_shard + Shard(current_committees_per_epoch)) % SHARD_COUNT
		} else if epochs_since_last_registry_update > 1 && is_power_of_two(uint64(epochs_since_last_registry_update)) {
			seed = generate_seed(state, next_epoch)
			shuffling_start_shard = state.current_shuffling_start_shard
		} else {
			seed = state.current_shuffling_seed
			shuffling_start_shard = state.current_shuffling_start_shard
		}
	}
	shuffling := get_shuffling(seed, state.validator_registry, shuffling_epoch)
	offset := slot % SLOTS_PER_EPOCH
	committees_per_slot := committees_per_epoch / uint64(SLOTS_PER_EPOCH)
	slot_start_shard := (shuffling_start_shard + Shard(committees_per_slot)*Shard(offset)) % SHARD_COUNT

	crosslink_committees := make([]CrosslinkCommittee, committees_per_slot)
	for i := uint64(0); i < committees_per_slot; i++ {
		crosslink_committees[i] = CrosslinkCommittee{
			Committee: shuffling[committees_per_slot*uint64(offset)+i],
			Shard:     (slot_start_shard + Shard(i)) % SHARD_COUNT}
	}
	return crosslink_committees, nil
}

// Shuffle active validators and split into crosslink committees.
// Return a list of committees (each a list of validator indices).
func get_shuffling(seed Bytes32, validators []Validator, epoch Epoch) [][]ValidatorIndex {
	active_validator_indices := get_active_validator_indices(validators, epoch)
	committee_count := get_epoch_committee_count(uint64(len(active_validator_indices)))
	commitees := make([][]ValidatorIndex, committee_count, committee_count)
	// Active validators, shuffled in-place.
	shuffleValidatorIndices(active_validator_indices, seed)
	committee_size := uint64(len(active_validator_indices)) / committee_count
	for i := uint64(0); i < committee_count; i += committee_size {
		commitees[i] = active_validator_indices[i : i+committee_size]
	}
	return commitees
}

// Return the block root at a recent slot.
func get_block_root(state *BeaconState, slot Slot) (Root, error) {
	if !(state.slot <= slot+LATEST_BLOCK_ROOTS_LENGTH && slot < state.slot) {
		return Root{}, errors.New("slot is not a recent slot, cannot find block root")
	}
	return state.latest_block_roots[slot%LATEST_BLOCK_ROOTS_LENGTH], nil
}

// Verify validity of slashable_attestation fields.
func verify_slashable_attestation(state *BeaconState, slashable_attestation *SlashableAttestation) bool {
	// TODO Moved condition to top, compared to spec. Data can be way too big, get rid of that ASAP.
	if len(slashable_attestation.validator_indices) == 0 ||
		len(slashable_attestation.validator_indices) > MAX_INDICES_PER_SLASHABLE_VOTE ||
		// [TO BE REMOVED IN PHASE 1]
		!slashable_attestation.custody_bitfield.IsZero() ||
		// verify the size of the bitfield: it must have exactly enough bits for the given amount of validators.
		!slashable_attestation.custody_bitfield.verifySize(uint64(len(slashable_attestation.validator_indices))) {
		return false
	}

	// simple check if the list is sorted.
	for i := 0; i < len(slashable_attestation.validator_indices)-1; i++ {
		if slashable_attestation.validator_indices[i] >= slashable_attestation.validator_indices[i+1] {
			return false
		}
	}

	custody_bit_0_pubkeys, custody_bit_1_pubkeys := make([]BLSPubkey, 0), make([]BLSPubkey, 0)
	for i, validator_index := range slashable_attestation.validator_indices {
		// The slashable indices is one giant sorted list of numbers,
		//   bigger than the registry, causing a out-of-bounds panic for some of the indices.
		if !is_validator_index(state, validator_index) {
			return false
		}
		// Update spec, or is this acceptable? (the bitfield verify size doesn't suffice here)
		if slashable_attestation.custody_bitfield.GetBit(uint64(i)) == 0 {
			custody_bit_0_pubkeys = append(custody_bit_0_pubkeys, state.validator_registry[validator_index].pubkey)
		} else {
			custody_bit_1_pubkeys = append(custody_bit_1_pubkeys, state.validator_registry[validator_index].pubkey)
		}
	}
	// don't trust, verify
	return bls_verify_multiple(
		[]BLSPubkey{bls_aggregate_pubkeys(custody_bit_0_pubkeys), bls_aggregate_pubkeys(custody_bit_1_pubkeys)},
		[]Root{hash_tree_root(AttestationDataAndCustodyBit{data: slashable_attestation.data, custody_bit: false}),
			hash_tree_root(AttestationDataAndCustodyBit{data: slashable_attestation.data, custody_bit: true})},
		slashable_attestation.aggregate_signature,
		get_domain(state.fork, slashable_attestation.data.slot.ToEpoch(), DOMAIN_ATTESTATION),
	)
}

// Check if a and b have the same target epoch. //TODO: spec has wrong wording here (?)
func is_double_vote(a *AttestationData, b *AttestationData) bool {
	return a.slot.ToEpoch() == b.slot.ToEpoch()
}

// Check if a surrounds b, i.e. source(a) < source(b) and target(a) > target(b)
func is_surround_vote(a *AttestationData, b *AttestationData) bool {
	return a.justified_epoch < b.justified_epoch && a.slot.ToEpoch() > b.slot.ToEpoch()
}

func is_validator_index(state *BeaconState, index ValidatorIndex) bool {
	return index < ValidatorIndex(len(state.validator_registry))
}

// Slash the validator with index index.
func slash_validator(state *BeaconState, index ValidatorIndex) error {
	validator := &state.validator_registry[index]
	// [TO BE REMOVED IN PHASE 2] // TODO: add reasoning, spec unclear
	if state.slot >= validator.withdrawable_epoch.GetStartSlot() {
		return errors.New("cannot slash validator after withdrawal epoch")
	}
	exit_validator(state, index)
	state.latest_slashed_balances[state.Epoch()%LATEST_SLASHED_EXIT_LENGTH] += get_effective_balance(state, index)

	whistleblower_reward := get_effective_balance(state, index) / WHISTLEBLOWER_REWARD_QUOTIENT
	state.validator_balances[get_beacon_proposer_index(state, state.slot)] += whistleblower_reward
	state.validator_balances[index] -= whistleblower_reward
	validator.slashed = true
	validator.withdrawable_epoch = state.Epoch() + LATEST_SLASHED_EXIT_LENGTH
	return nil
}

//  Return the randao mix at a recent epoch
func get_randao_mix(state *BeaconState, epoch Epoch) Bytes32 {
	// Every usage is a trusted input (i.e. state is already up to date to handle the requested epoch number).
	// If something is wrong due to unforeseen usage, panic to catch it during development.
	if !(state.Epoch()-LATEST_RANDAO_MIXES_LENGTH < epoch && epoch <= state.Epoch()) {
		panic("cannot get randao mix for out-of-bounds epoch")
	}
	return state.latest_randao_mixes[epoch%LATEST_RANDAO_MIXES_LENGTH]
}

// Get the domain number that represents the fork meta and signature domain.
func get_domain(fork Fork, epoch Epoch, dom BLSDomain) BLSDomain {
	// combine fork version with domain.
	// TODO: spec is unclear about input size expectations.
	// TODO And is "+" different than packing into 64 bits here? I.e. ((32 bits fork version << 32) | (dom 32 bits))
	return BLSDomain(fork.GetVersion(epoch)<<32) + dom
}

// Return the beacon proposer index for the slot.
func get_beacon_proposer_index(state *BeaconState, slot Slot) ValidatorIndex {
	// ignore error, slot input is trusted here
	first_committee_data, _ := get_crosslink_committees_at_slot(state, slot, false)
	return first_committee_data[0].Committee[slot%Slot(len(first_committee_data[0].Committee))]
}
