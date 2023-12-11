//! The super circuit for taiko

/// for test purpose
#[cfg(any(feature = "test", test))]
pub mod test;

#[cfg(feature = "for-a7")]
use crate::anchor_tx_circuit::{AnchorTxCircuit, AnchorTxCircuitConfig, AnchorTxCircuitConfigArgs};
#[cfg(feature = "for-a7")]
use crate::bytecode_circuit::circuit::{
    BytecodeCircuit, BytecodeCircuitConfig, BytecodeCircuitConfigArgs,
};
#[cfg(feature = "for-a7")]
use crate::copy_circuit::{CopyCircuit, CopyCircuitConfig, CopyCircuitConfigArgs};
#[cfg(feature = "for-a7")]
use crate::evm_circuit::{EvmCircuit, EvmCircuitConfig, EvmCircuitConfigArgs};
#[cfg(feature = "for-a7")]
use crate::exp_circuit::{ExpCircuit, ExpCircuitConfig};
#[cfg(feature = "for-a7")]
use crate::keccak_circuit::{KeccakCircuit, KeccakCircuitConfig, KeccakCircuitConfigArgs};
#[cfg(feature = "for-a7")]
use crate::state_circuit::{StateCircuit, StateCircuitConfig, StateCircuitConfigArgs};
#[cfg(feature = "for-a7")]
use crate::table::{ByteTable, BytecodeTable, CopyTable, ExpTable};
#[cfg(feature = "for-a7")]
use crate::{table::MptTable, witness::MptUpdates};

use crate::{
    table::{BlockTable, ByteTable, KeccakTable},
    taiko_pi_circuit::{PublicData, TaikoPiCircuit, TaikoPiCircuitConfig, TaikoPiConfigArgs},
    util::{log2_ceil, Challenges, SubCircuit, SubCircuitConfig},
    witness::{block_convert, Block},
};
use bus_mapping::{
    circuit_input_builder::{CircuitInputBuilder, CircuitsParams, ProtocolInstance},
    mock::BlockData,
};
use eth_types::{geth_types::GethData, Field};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error, Expression},
};

use itertools::Itertools;
use snark_verifier_sdk::CircuitExt;

/// Configuration of the Super Circuit
#[derive(Clone)]
pub struct SuperCircuitConfig<F: Field> {
    #[cfg(feature = "for-a7")]
    tx_table: TxTable,
    #[cfg(feature = "for-a7")]
    rw_table: RwTable,
    #[cfg(feature = "for-a7")]
    mpt_table: MptTable,
    #[cfg(feature = "for-a7")]
    bytecode_table: BytecodeTable,
    #[cfg(feature = "for-a7")]
    pi_table: PiTable,
    keccak_table: KeccakTable,
    block_table: BlockTable,
    byte_table: ByteTable,
    #[cfg(feature = "for-a7")]
    copy_table: CopyTable,
    #[cfg(feature = "for-a7")]
    exp_table: ExpTable,
    pi_circuit: TaikoPiCircuitConfig<F>,
    #[cfg(feature = "for-a7")]
    anchor_tx_circuit: AnchorTxCircuitConfig<F>,
    #[cfg(feature = "for-a7")]
    evm_circuit: EvmCircuitConfig<F>,
    #[cfg(feature = "for-a7")]
    keccak_circuit: KeccakCircuitConfig<F>,
    #[cfg(feature = "for-a7")]
    bytecode_circuit: BytecodeCircuitConfig<F>,
    #[cfg(feature = "for-a7")]
    state_circuit: StateCircuitConfig<F>,
    #[cfg(feature = "for-a7")]
    exp_circuit: ExpCircuitConfig<F>,
    #[cfg(feature = "for-a7")]
    copy_circuit: CopyCircuitConfig<F>,
}

/// Circuit configuration arguments
pub struct SuperCircuitConfigArgs<F: Field> {
    /// Challenges expressions
    pub challenges: Challenges<Expression<F>>,
}

impl<F: Field> SubCircuitConfig<F> for SuperCircuitConfig<F> {
    type ConfigArgs = SuperCircuitConfigArgs<F>;

    /// Configure SuperCircuitConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs { challenges }: Self::ConfigArgs,
    ) -> Self {
        #[cfg(feature = "for-a7")]
        let tx_table = TxTable::construct(meta);
        #[cfg(feature = "for-a7")]
        let rw_table = RwTable::construct(meta);
        #[cfg(feature = "for-a7")]
        let mpt_table = MptTable::construct(meta);
        #[cfg(feature = "for-a7")]
        let bytecode_table = BytecodeTable::construct(meta);
        #[cfg(feature = "for-a7")]
        let pi_table = PiTable::construct(meta);
        let block_table = BlockTable::construct(meta);
        let keccak_table = KeccakTable::construct(meta);
        let byte_table = ByteTable::construct(meta);
        #[cfg(feature = "for-a7")]
        let q_copy_table = meta.fixed_column();
        #[cfg(feature = "for-a7")]
        let copy_table = CopyTable::construct(meta, q_copy_table);
        #[cfg(feature = "for-a7")]
        let exp_table = ExpTable::construct(meta);

        let pi_circuit = TaikoPiCircuitConfig::new(
            meta,
            TaikoPiConfigArgs {
                public_data: PublicData::default(),
                block_table: block_table.clone(),
                keccak_table: keccak_table.clone(),
                byte_table: byte_table.clone(),
                challenges,
            },
        );

        #[cfg(feature = "for-a7")]
        let anchor_tx_circuit = AnchorTxCircuitConfig::new(
            meta,
            AnchorTxCircuitConfigArgs {
                tx_table: tx_table.clone(),
                pi_table: pi_table.clone(),
                byte_table: byte_table.clone(),
                challenges: challenges.clone(),
            },
        );

        #[cfg(feature = "for-a7")]
        let evm_circuit = EvmCircuitConfig::new(
            meta,
            EvmCircuitConfigArgs {
                challenges,
                tx_table: tx_table.clone(),
                rw_table,
                bytecode_table: bytecode_table.clone(),
                block_table: block_table.clone(),
                copy_table,
                keccak_table: keccak_table.clone(),
                exp_table,
                is_taiko: true,
            },
        );

        #[cfg(feature = "for-a7")]
        let (keccak_circuit, bytecode_circuit, state_circuit, exp_circuit, copy_circuit) = {
            let keccak_circuit = KeccakCircuitConfig::new(
                meta,
                KeccakCircuitConfigArgs {
                    keccak_table: keccak_table.clone(),
                    challenges: challenges.clone(),
                },
            );

            let bytecode_circuit = BytecodeCircuitConfig::new(
                meta,
                BytecodeCircuitConfigArgs {
                    bytecode_table: bytecode_table.clone(),
                    challenges: challenges.clone(),
                    keccak_table: keccak_table.clone(),
                },
            );

            let state_circuit = StateCircuitConfig::new(
                meta,
                StateCircuitConfigArgs {
                    rw_table,
                    mpt_table,
                    challenges: challenges.clone(),
                },
            );

            let exp_circuit = ExpCircuitConfig::new(meta, exp_table);

            let copy_circuit = CopyCircuitConfig::new(
                meta,
                CopyCircuitConfigArgs {
                    tx_table: tx_table.clone(),
                    rw_table,
                    bytecode_table: bytecode_table.clone(),
                    copy_table,
                    challenges,
                    q_enable: q_copy_table,
                },
            );
            (
                keccak_circuit,
                bytecode_circuit,
                state_circuit,
                exp_circuit,
                copy_circuit,
            )
        };

        Self {
            #[cfg(feature = "for-a7")]
            tx_table,
            #[cfg(feature = "for-a7")]
            rw_table,
            #[cfg(feature = "for-a7")]
            mpt_table,
            #[cfg(feature = "for-a7")]
            bytecode_table,
            #[cfg(feature = "for-a7")]
            copy_table,
            #[cfg(feature = "for-a7")]
            exp_table,
            #[cfg(feature = "for-a7")]
            pi_table,
            pi_circuit,
            block_table,
            keccak_table,
            byte_table,
            #[cfg(feature = "for-a7")]
            anchor_tx_circuit,
            #[cfg(feature = "for-a7")]
            evm_circuit,
            #[cfg(feature = "for-a7")]
            keccak_circuit,
            #[cfg(feature = "for-a7")]
            bytecode_circuit,
            #[cfg(feature = "for-a7")]
            state_circuit,
            #[cfg(feature = "for-a7")]
            exp_circuit,
            #[cfg(feature = "for-a7")]
            copy_circuit,
        }
    }
}

/// The Super Circuit contains all the zkEVM circuits
#[derive(Clone, Default, Debug)]
pub struct SuperCircuit<F: Field> {
    /// Public Input Circuit
    pub pi_circuit: TaikoPiCircuit<F>,

    /// Anchor Transaction Circuit
    #[cfg(feature = "for-a7")]
    pub anchor_tx_circuit: AnchorTxCircuit<F>,
    /// EVM Circuit
    #[cfg(feature = "for-a7")]
    pub evm_circuit: EvmCircuit<F>,
    // planed circuits for a6
    #[cfg(feature = "for-a7")]
    pub(crate) keccak_circuit: KeccakCircuit<F>,
    #[cfg(feature = "for-a7")]
    pub(crate) bytecode_circuit: BytecodeCircuit<F>,
    #[cfg(feature = "for-a7")]
    pub(crate) state_circuit: StateCircuit<F>,
    #[cfg(feature = "for-a7")]
    pub(crate) copy_circuit: CopyCircuit<F>,
    #[cfg(feature = "for-a7")]
    pub(crate) exp_circuit: ExpCircuit<F>,

    /// Block witness
    pub block: Block<F>,
}

impl<F: Field> CircuitExt<F> for SuperCircuit<F> {
    fn num_instance(&self) -> Vec<usize> {
        self.instance().iter().map(|v| v.len()).collect_vec()
    }

    fn instances(&self) -> Vec<Vec<F>> {
        self.instance()
    }
}

// Eventhough the SuperCircuit is not a subcircuit we implement the SubCircuit
// trait for it in order to get the `new_from_block` and `instance` methods that
// allow us to generalize integration tests.
impl<F: Field> SubCircuit<F> for SuperCircuit<F> {
    type Config = SuperCircuitConfig<F>;

    fn unusable_rows() -> usize {
        TaikoPiCircuit::<F>::unusable_rows()
    }

    fn new_from_block(block: &Block<F>) -> Self {
        let pi_circuit = TaikoPiCircuit::new_from_block(block);
        #[cfg(feature = "for-a7")]
        let (
            anchor_tx_circuit,
            evm_circuit,
            keccak_circuit,
            bytecode_circuit,
            state_circuit,
            copy_circuit,
            exp_circuit,
        ) = {
            let anchor_tx_circuit = AnchorTxCircuit::new_from_block(block);
            let evm_circuit = EvmCircuit::new_from_block(block);
            let keccak_circuit = KeccakCircuit::new_from_block(block);
            let bytecode_circuit = BytecodeCircuit::new_from_block(block);
            let state_circuit = StateCircuit::new_from_block(block);
            let copy_circuit = CopyCircuit::new_from_block(block);
            let exp_circuit = ExpCircuit::new_from_block(block);
            (
                keccak_circuit,
                bytecode_circuit,
                state_circuit,
                copy_circuit,
                exp_circuit,
            )
        };

        SuperCircuit::<_> {
            pi_circuit,
            #[cfg(feature = "for-a7")]
            anchor_tx_circuit,
            #[cfg(feature = "for-a7")]
            evm_circuit,
            #[cfg(feature = "for-a7")]
            keccak_circuit,
            #[cfg(feature = "for-a7")]
            bytecode_circuit,
            #[cfg(feature = "for-a7")]
            state_circuit,
            #[cfg(feature = "for-a7")]
            copy_circuit,
            #[cfg(feature = "for-a7")]
            exp_circuit,
            block: block.clone(),
        }
    }

    /// Returns suitable inputs for the SuperCircuit.
    fn instance(&self) -> Vec<Vec<F>> {
        let mut instance = Vec::new();
        instance.extend_from_slice(&self.pi_circuit.instance());
        instance
    }

    /// Return the minimum number of rows required to prove the block
    fn min_num_rows_block(block: &Block<F>) -> (usize, usize) {
        [
            TaikoPiCircuit::min_num_rows_block(block),
            #[cfg(feature = "for-a7")]
            AnchorTxCircuit::min_num_rows_block(block),
            #[cfg(feature = "for-a7")]
            EvmCircuit::min_num_rows_block(block),
            #[cfg(feature = "for-a7")]
            KeccakCircuit::min_num_rows_block(block),
            #[cfg(feature = "for-a7")]
            BytecodeCircuit::min_num_rows_block(block),
            #[cfg(feature = "for-a7")]
            StateCircuit::min_num_rows_block(block),
            #[cfg(feature = "for-a7")]
            CopyCircuit::min_num_rows_block(block),
            #[cfg(feature = "for-a7")]
            ExpCircuit::min_num_rows_block(block),
        ]
        .iter()
        .fold((0, 0), |(x1, y1), (x2, y2)| {
            (std::cmp::max(x1, *x2), std::cmp::max(y1, *y2))
        })
    }

    /// Make the assignments to the SuperCircuit
    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        self.pi_circuit
            .synthesize_sub(&config.pi_circuit, challenges, layouter)?;
        #[cfg(feature = "for-a7")]
        {
            self.anchor_tx_circuit.synthesize_sub(
                &config.anchor_tx_circuit,
                challenges,
                layouter,
            )?;
            self.evm_circuit
                .synthesize_sub(&config.evm_circuit, challenges, layouter)?;
            self.keccak_circuit
                .synthesize_sub(&config.keccak_circuit, challenges, layouter)?;
            self.bytecode_circuit
                .synthesize_sub(&config.bytecode_circuit, challenges, layouter)?;
            self.state_circuit
                .synthesize_sub(&config.state_circuit, challenges, layouter)?;
            self.copy_circuit
                .synthesize_sub(&config.copy_circuit, challenges, layouter)?;
            self.exp_circuit
                .synthesize_sub(&config.exp_circuit, challenges, layouter)?;
        }

        Ok(())
    }
}

impl<F: Field> Circuit<F> for SuperCircuit<F> {
    type Config = (SuperCircuitConfig<F>, Challenges);
    type FloorPlanner = SimpleFloorPlanner;
    type Params = ();

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure_with_params(
        meta: &mut ConstraintSystem<F>,
        _params: Self::Params,
    ) -> Self::Config {
        Self::configure(meta)
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let challenges = Challenges::construct(meta);
        let challenge_exprs = challenges.exprs(meta);
        (
            SuperCircuitConfig::new(
                meta,
                SuperCircuitConfigArgs {
                    challenges: challenge_exprs,
                },
            ),
            challenges,
        )
    }

    fn synthesize(
        &self,
        (config, challenges): Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let challenges = challenges.values(&mut layouter);
        let randomness = challenges.evm_word();
        config
            .block_table
            .load(&mut layouter, &self.block.context, randomness)?;
        config.keccak_table.dev_load(
            &mut layouter,
            self.block
                .sha3_inputs
                .iter()
                .chain(std::iter::once(
                    &self.pi_circuit.public_data.protocol_instance.abi_encode(),
                ))
                .chain(
                    &self
                        .block
                        .bytecodes
                        .clone()
                        .into_iter()
                        .map(|b| b.1.bytes)
                        .collect_vec(),
                ),
            &challenges,
        )?;
        config.byte_table.load(&mut layouter)?;
        #[cfg(feature = "for-a7")]
        {
            config.pi_table.load(
                &mut layouter,
                self.block.protocol_instance.as_ref().unwrap(),
                &challenges,
            )?;
            config.tx_table.load(
                &mut layouter,
                &self.block.txs,
                self.block.circuits_params.max_txs,
                self.block.circuits_params.max_calldata,
                &challenges,
            )?;
            self.block.rws.check_rw_counter_sanity();
            config.rw_table.load(
                &mut layouter,
                &self.block.rws.table_assignments(),
                self.block.circuits_params.max_rws,
                challenges.evm_word(),
            )?;
            config.bytecode_table.load(
                &mut layouter,
                self.block.bytecodes.values(),
                &challenges,
            )?;
            config.exp_table.load(&mut layouter, &self.block)?;
            config
                .copy_table
                .load(&mut layouter, &self.block, &challenges)?;
            config.mpt_table.load(
                &mut layouter,
                &MptUpdates::mock_from(&self.state_circuit.rows),
                randomness,
            )?;
        }

        self.synthesize_sub(&config, &challenges, &mut layouter)
    }
}

impl<F: Field> SuperCircuit<F> {
    /// From the witness data, generate a SuperCircuit instance with all of the
    /// sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the
    /// circuit and the Public Inputs needed.
    #[allow(clippy::type_complexity)]
    pub fn build(
        geth_data: GethData,
        circuits_params: CircuitsParams,
        mut protocol_instance: ProtocolInstance,
    ) -> Result<(u32, Self, Vec<Vec<F>>, CircuitInputBuilder), bus_mapping::Error> {
        let block_data =
            BlockData::new_from_geth_data_with_params(geth_data.clone(), circuits_params);
        let mut builder = block_data.new_circuit_input_builder();
        protocol_instance.transition.blockHash =
            geth_data.eth_block.hash.unwrap().as_fixed_bytes().into();
        protocol_instance.transition.parentHash =
            geth_data.eth_block.parent_hash.as_fixed_bytes().into();
        builder.block.protocol_instance = Some(protocol_instance);
        builder
            .handle_block(&geth_data.eth_block, &geth_data.geth_traces)
            .expect("could not handle block tx");

        let ret = Self::build_from_circuit_input_builder(&builder)?;
        Ok((ret.0, ret.1, ret.2, builder))
    }

    /// From CircuitInputBuilder, generate a SuperCircuit instance with all of
    /// the sub-circuits filled with their corresponding witnesses.
    ///
    /// Also, return with it the minimum required SRS degree for the circuit and
    /// the Public Inputs needed.
    pub fn build_from_circuit_input_builder(
        builder: &CircuitInputBuilder,
    ) -> Result<(u32, Self, Vec<Vec<F>>), bus_mapping::Error> {
        let block = block_convert(&builder.block, &builder.code_db).unwrap();
        let (_, rows_needed) = Self::min_num_rows_block(&block);
        let k = log2_ceil(Self::unusable_rows() + rows_needed);
        log::debug!("super circuit uses k = {}", k);

        let circuit = SuperCircuit::new_from_block(&block);

        let instance = circuit.instance();
        Ok((k, circuit, instance))
    }
}
