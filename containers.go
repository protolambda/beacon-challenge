package beacon_challenge

type BeaconBlock struct {

	// Header
	slot Slot
	parent_root Root
	state_root Root
	randao_reveal [96]byte
	eth1_data Eth1Data

	// Body
	body BeaconBlockBody
	// Signature
	signature BLSSignature

}

type BeaconBlockBody struct {
	proposer_slashings []ProposerSlashing
	attester_slashings []AttesterSlashing
	attestations []Attestation
	deposits []Deposit
	voluntary_exits []VoluntaryExit
	transfers []Transfer
}

type ProposerSlashing struct {
	// Proposer index
	proposer_index ValidatorIndex
	// First proposal
	proposal_1 Proposal
	// Second proposal
	proposal_2 Proposal
}

type Proposal struct {
	// Slot number
	slot Slot
	// Shard number (`BEACON_CHAIN_SHARD_NUMBER` for beacon chain)
	shard Shard
	// Block root
	block_root Root
	// Signature
	signature BLSSignature
}

type AttesterSlashing struct {
	// First slashable attestation
	slashable_attestation_1 SlashableAttestation
	// Second slashable attestation
	slashable_attestation_2 SlashableAttestation
}

type SlashableAttestation struct {
	// Validator indices
	validator_indices []ValidatorIndex
	// Attestation data
	data AttestationData
	// Custody bitfield
	custody_bitfield Bitfield
	// Aggregate signature
	aggregate_signature BLSSignature
}

type Attestation struct {
	// Attester aggregation bitfield
	aggregation_bitfield Bitfield
	// Attestation data
	data AttestationData
	// Custody bitfield
	custody_bitfield Bitfield
	// BLS aggregate signature
	aggregate_signature BLSSignature
}

type AttestationData struct {
	// Slot number
	slot Slot
	// Shard number
	shard Shard
	// Root of the signed beacon block
	beacon_block_root Root
	// Root of the ancestor at the epoch boundary
	epoch_boundary_root Root
	// Data from the shard since the last attestation
	crosslink_data_root Root
	// Last crosslink
	latest_crosslink Crosslink
	// Last justified epoch in the beacon state
	justified_epoch Epoch
	// Hash of the last justified beacon block
	justified_block_root Root
}

type AttestationDataAndCustodyBit struct {
	// Attestation data
	data AttestationData
	// Custody bit
	custody_bit bool
}

type Crosslink struct {
	// Epoch number
	epoch Epoch
	// Shard data since the previous crosslink
	crosslink_data_root Root
}

type Deposit struct {
	// Branch in the deposit tree
	branch []Root
	// Index in the deposit tree
	index DepositIndex
	// Data
	deposit_data DepositData
}

type DepositData struct {
	// Amount in Gwei
	amount Gwei
	// Timestamp from deposit contract
	timestamp Timestamp
	// Deposit input
	deposit_input DepositInput
}

type DepositInput struct {
	// BLS pubkey
	pubkey BLSPubkey
	// Withdrawal credentials
	withdrawal_credentials Root
	// A BLS signature of this `DepositInput`
	proof_of_possession BLSSignature
}

type VoluntaryExit struct {
	// Minimum epoch for processing exit
	epoch Epoch
	// Index of the exiting validator
	validator_index ValidatorIndex
	// Validator signature
	signature BLSSignature
}

type Transfer struct {
	// Sender index
	from ValidatorIndex
	// Recipient index
	to ValidatorIndex
	// Amount in Gwei
	amount Gwei
	// Fee in Gwei for block proposer
	fee Gwei
	// Inclusion slot
	slot Slot
	// Sender withdrawal pubkey
	pubkey BLSPubkey
	// Sender signature
	signature BLSSignature
}

type BeaconState struct {
	// Misc
	slot Slot
	genesis_time Timestamp
	fork Fork  // For versioning hard forks

	// Validator registry
	validator_registry []Validator
	validator_balances []Gwei
	validator_registry_update_epoch Epoch

	// Randomness and committees
	latest_randao_mixes []Bytes32
	previous_shuffling_start_shard Shard
	current_shuffling_start_shard Shard
	previous_shuffling_epoch Epoch
	current_shuffling_epoch Epoch
	previous_shuffling_seed Bytes32
	current_shuffling_seed Bytes32

	// Finality
	previous_justified_epoch Epoch
	justified_epoch Epoch
	justification_bitfield uint64
	finalized_epoch Epoch

	// Recent state
	latest_crosslinks []Crosslink
	latest_block_roots []Root
	latest_active_index_roots []Root
	latest_slashed_balances []uint64  // Balances slashed at every withdrawal period
	latest_attestations []PendingAttestation
	batched_block_roots []Root

	// Ethereum 1.0 chain data
	latest_eth1_data Eth1Data
	eth1_data_votes []Eth1DataVote
	deposit_index DepositIndex
}

// Make a deep copy of the state object
func (st *BeaconState) Copy() *BeaconState {
	// copy over state
	stUn := *st
	res := &stUn
	// manually copy over slices
	// validators
	copy(res.validator_registry, st.validator_registry)
	copy(res.validator_balances, st.validator_balances)
	// randao
	copy(res.latest_randao_mixes, st.latest_randao_mixes)
	// recent state
	copy(res.latest_crosslinks, st.latest_crosslinks)
	copy(res.latest_block_roots, st.latest_block_roots)
	copy(res.latest_active_index_roots, st.latest_active_index_roots)
	copy(res.latest_slashed_balances, st.latest_slashed_balances)
	copy(res.latest_attestations, st.latest_attestations)
	copy(res.batched_block_roots, st.batched_block_roots)
	// eth1
	copy(res.eth1_data_votes, st.eth1_data_votes)
	return res
}

// Get current epoch
func (st *BeaconState) Epoch() Epoch {
	return st.slot.ToEpoch()
}

// Return previous epoch. Not just current - 1: it's clipped to genesis.
func (st *BeaconState) PreviousEpoch() Epoch {
	epoch := st.Epoch()
	if epoch < GENESIS_EPOCH {
		return GENESIS_EPOCH
	} else {
		return epoch
	}
}

type Validator struct {
	// BLS public key
	pubkey BLSPubkey
	// Withdrawal credentials
	withdrawal_credentials Bytes32
	// Epoch when validator activated
	activation_epoch Epoch
	// Epoch when validator exited
	exit_epoch Epoch
	// Epoch when validator is eligible to withdraw
	withdrawable_epoch Epoch
	// Did the validator initiate an exit
	initiated_exit bool
	// Was the validator slashed
	slashed bool
}

func (v *Validator) IsActive(epoch Epoch) bool {
	return v.activation_epoch <= epoch && epoch < v.exit_epoch
}

type PendingAttestation struct {
	// Attester aggregation bitfield
	aggregation_bitfield Bitfield
	// Attestation data
	data AttestationData
	// Custody bitfield
	custody_bitfield Bitfield
	// Inclusion slot
	inclusion_slot Slot
}

type Fork struct {
	// Previous fork version
	previous_version uint64
	// Current fork version
	current_version uint64
	// Fork epoch number
	epoch Epoch
}

type Eth1Data struct {
	// Root of the deposit tree
	deposit_root Root
	// Block hash
	block_hash Root
}

type Eth1DataVote struct {
	// Data being voted for
	eth1_data Eth1Data
	// Vote count
	vote_count uint64
}

