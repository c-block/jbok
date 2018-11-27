package jbok.core.consensus.pow.ethash

import cats.data.NonEmptyList
import cats.effect.Sync
import cats.implicits._
import jbok.codec.rlp.RlpCodec
import jbok.codec.rlp.implicits._
import jbok.core.config.Configs.{BlockChainConfig, MiningConfig, MonetaryPolicyConfig}
import jbok.core.consensus.Consensus
import jbok.core.ledger.TypedBlock.MinedBlock
import jbok.core.ledger.{History, TypedBlock}
import jbok.core.models.{Block, BlockHeader}
import jbok.core.pool.BlockPool
import jbok.crypto._
import scodec.bits.ByteVector

class EthashConsensus[F[_]](
    blockChainConfig: BlockChainConfig,
    miningConfig: MiningConfig,
    history: History[F],
    blockPool: BlockPool[F],
    miner: EthashMiner[F],
    ommersValidator: EthashOmmersValidator[F],
    headerValidator: EthashHeaderValidator[F]
)(implicit F: Sync[F])
    extends Consensus[F](history, blockPool) {

  override def prepareHeader(parentOpt: Option[Block], ommers: List[BlockHeader]): F[BlockHeader] =
    for {
      parent <- parentOpt.fold(history.getBestBlock)(F.pure)
      number = parent.header.number + 1
      timestamp  <- getTimestamp
      difficulty <- calcDifficulty(timestamp, parent.header)
    } yield
      BlockHeader(
        parentHash = parent.header.hash,
        ommersHash = RlpCodec.encode(ommers).require.bytes.kec256,
        beneficiary = miningConfig.coinbase.bytes,
        stateRoot = ByteVector.empty,
        //we are not able to calculate transactionsRoot here because we do not know if they will fail
        transactionsRoot = ByteVector.empty,
        receiptsRoot = ByteVector.empty,
        logsBloom = ByteVector.empty,
        difficulty = difficulty,
        number = number,
        gasLimit = calcGasLimit(parent.header.gasLimit),
        gasUsed = 0,
        unixTimestamp = timestamp,
        extraData = blockChainConfig.daoForkConfig
          .flatMap(daoForkConfig => daoForkConfig.getExtraData(number))
          .getOrElse(miningConfig.headerExtraData),
        mixHash = ByteVector.empty,
        nonce = ByteVector.empty
      )

  override def postProcess(executed: TypedBlock.ExecutedBlock[F]): F[TypedBlock.ExecutedBlock[F]] = ???

  override def mine(executed: TypedBlock.ExecutedBlock[F]): F[TypedBlock.MinedBlock] =
    miner.mine(executed.block).map(block => MinedBlock(block, executed.receipts))

  override def run(block: Block): F[Consensus.Result] = ???
//    history.getBestBlock.flatMap { parent =>
//      F.ifM(blockPool.isDuplicate(header.hash))(
//        ifTrue = F.pure(Consensus.Discard(new Exception("duplicate"))),
//        ifFalse = for {
//          currentTd <- history.getTotalDifficultyByHash(parent.header.hash).map(_.get)
//          isTopOfChain = header.parentHash == parent.header.hash
//          result = if (isTopOfChain) {
//            Consensus.Forward
//          } else {
//            Consensus.Stash
//          }
//        } yield result
//      )
//    }

  override def resolveBranch(headers: List[BlockHeader]): F[Consensus.BranchResult] =
    if (!checkHeaders(headers)) {
      F.pure(Consensus.InvalidBranch)
    } else {
      val parentIsKnown = history.getBlockHeaderByHash(headers.head.parentHash).map(_.isDefined)
      parentIsKnown.ifM(
        ifTrue = {
          // find blocks with same numbers in the current chain, removing any common prefix
          headers.map(_.number).traverse(history.getBlockByNumber).map {
            blocks =>
              val (oldBranch, _) = blocks.flatten
                .zip(headers)
                .dropWhile {
                  case (oldBlock, header) =>
                    oldBlock.header == header
                }
                .unzip
              val newHeaders              = headers.dropWhile(h => oldBranch.headOption.exists(_.header.number > h.number))
              val currentBranchDifficulty = oldBranch.map(_.header.difficulty).sum
              val newBranchDifficulty     = newHeaders.map(_.difficulty).sum
              if (currentBranchDifficulty < newBranchDifficulty) {
                Consensus.NewBetterBranch(oldBranch)
              } else {
                Consensus.NoChainSwitch
              }
          }
        },
        ifFalse = F.pure(Consensus.InvalidBranch)
      )
    }

  ////////////////////////////////////
  ////////////////////////////////////

  private def checkHeaders(headers: List[BlockHeader]): Boolean =
    if (headers.length > 1)
      headers.zip(headers.tail).forall {
        case (parent, child) =>
          parent.hash == child.parentHash && parent.number + 1 == child.number
      } else
      headers.nonEmpty

  private val difficultyCalculator = new EthDifficultyCalculator(blockChainConfig)
  private val rewardCalculator     = new EthRewardCalculator(MonetaryPolicyConfig())

  private def semanticValidate(parentHeader: BlockHeader, block: Block): F[Unit] =
    for {
      _ <- headerValidator.validate(parentHeader, block.header)
      _ <- ommersValidator.validate(
        block.header.parentHash,
        block.header.number,
        block.body.uncleNodesList,
        blockPool.getHeader,
        blockPool.getNBlocks
      )
    } yield ()

  private def calcDifficulty(blockTime: Long, parentHeader: BlockHeader): F[BigInt] =
    F.pure(difficultyCalculator.calculateDifficulty(blockTime, parentHeader))

  private def calcBlockMinerReward(blockNumber: BigInt, ommersCount: Int): F[BigInt] =
    F.pure(rewardCalculator.calcBlockMinerReward(blockNumber, ommersCount))

  private def calcOmmerMinerReward(blockNumber: BigInt, ommerNumber: BigInt): F[BigInt] =
    F.pure(rewardCalculator.calcOmmerMinerReward(blockNumber, ommerNumber))

  private def getTimestamp: F[Long] =
    F.pure(System.currentTimeMillis())

  private def calcGasLimit(parentGas: BigInt): BigInt = {
    val GasLimitBoundDivisor: Int = 1024
    val gasLimitDifference        = parentGas / GasLimitBoundDivisor
    parentGas + gasLimitDifference - 1
  }
}
