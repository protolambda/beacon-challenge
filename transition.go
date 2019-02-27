package beacon_challenge

// interface required by Justin Drake for challenge.
func StateTransition(state *BeaconState, block *BeaconBlock) (res *BeaconState, err error) {
	// TODO: should I copy the starting state?
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
	}
	return state, nil
}

func ApplyBlock(state *BeaconState, block *BeaconBlock) error {

	return nil
}

func SlotTransition(state *BeaconState) {

}


func EpochTransition(state *BeaconState) {

}
