package jbok.core.consensus.poa.clique

import cats.data.NonEmptyList
import cats.effect.{Sync, Timer}
import cats.implicits._
import jbok.codec.rlp.RlpEncoded
import jbok.common._
import jbok.common.log.Logger
import jbok.common.math.N
import jbok.common.math.implicits._
import jbok.core.config.MiningConfig
import jbok.core.consensus.Consensus
import jbok.core.ledger.History
import jbok.core.ledger.TypedBlock._
import jbok.core.models.{Address, Block, BlockHeader, Receipt}
import jbok.core.pool.BlockPool
import jbok.core.pool.BlockPool.Leaf
import jbok.core.validators.BlockValidator
import jbok.core.validators.HeaderInvalid.HeaderParentNotFoundInvalid
import jbok.persistent.DBErr
import scodec.bits.ByteVector
import spire.syntax.all._

import scala.concurrent.duration._
import scala.util.Random
import scala.math

final class CliqueConsensus[F[_]](config: MiningConfig, history: History[F], clique: Clique[F], pool: BlockPool[F])(
    implicit F: Sync[F],
    T: Timer[F]
) extends Consensus[F] {
  private[this] val log = Logger[F]

  override def prepareHeader(parentOpt: Option[Block]): F[BlockHeader] =
    for {
      parent <- parentOpt.fold(history.getBestBlock)(_.pure[F])
      blockNumber = parent.header.number + 1
      timestamp   = parent.header.unixTimestamp + config.period.toMillis
      snap <- clique.applyHeaders(parent.header.number, parent.header.hash, Nil)
      header <- if (!snap.miners.contains(clique.minerAddress)) {
        F.raiseError[BlockHeader](new Exception(s"unauthorized miner ${clique.minerAddress}"))
      } else {
        val header = BlockHeader(
          parentHash = parent.header.hash,
          beneficiary = ByteVector.empty,
          stateRoot = ByteVector.empty,
          transactionsRoot = ByteVector.empty,
          receiptsRoot = ByteVector.empty,
          logsBloom = ByteVector.empty,
          difficulty = calcDifficulty(snap, clique.minerAddress, blockNumber),
          number = blockNumber,
          gasLimit = calcGasLimit(parent.header.gasLimit),
          gasUsed = 0,
          unixTimestamp = timestamp,
          extra = RlpEncoded.emptyList
        )

        snap.recents.find(_._2 == clique.minerAddress) match {
          case Some((seen, _)) if amongstRecent(header.number, seen, snap.miners.size) =>
            val wait: Long  = math.max(0, snap.miners.size / 2 + 1 - (header.number - seen).toInt) * config.period.toMillis
            val delay: Long = math.max(0, header.unixTimestamp - System.currentTimeMillis()) + wait

            log.i(s"mined recently, sleep (${delay}) millis") >> T.sleep(delay.millis) >> prepareHeader(parentOpt)
          case _ =>
            clique.clearProposalIfMine(parent.header) >> header.pure[F]
        }
      }
    } yield header

  override def mine(executed: ExecutedBlock[F]): F[MinedBlock] =
    for {
      snap <- clique.applyHeaders(executed.block.header.number - 1, executed.block.header.parentHash, Nil)
      wait: Long = math.max(0L, executed.block.header.unixTimestamp - System.currentTimeMillis())
      delay <- if (executed.block.header.difficulty == Clique.diffNoTurn) {
        // It's not our turn explicitly to sign, delay it a bit
        val wiggle: Long = math.abs(Random.nextLong()) % ((snap.miners.size / 2 + 1) * Clique.wiggleTime.toMillis)
        log.trace(s"${clique.minerAddress} it is not our turn, delay ${wiggle}").as(wait + wiggle)
      } else {
        log.trace(s"${clique.minerAddress} it is our turn, mine immediately").as(wait)
      }
      _      <- T.sleep(delay.millis)
      _      <- log.trace(s"${clique.minerAddress} mined block(${executed.block.header.number})")
      header <- clique.fillExtraData(executed.block.header)
    } yield MinedBlock(executed.block.copy(header = header), executed.receipts)

  override def verify(block: Block): F[Unit] =
    for {
      blockOpt <- pool.getBlockFromPoolOrHistory(block.header.hash)
      _        <- if (blockOpt.isDefined) F.raiseError[Unit](new Exception("duplicate block")) else F.unit
      _ <- history.getBlockHeaderByHash(block.header.parentHash).flatMap[Unit] {
        case Some(parent) =>
          val result = for {
            _ <- check(calcGasLimit(parent.gasLimit) == block.header.gasLimit, "wrong gasLimit")
            _ <- check(block.header.unixTimestamp == parent.unixTimestamp + config.period.toMillis, "wrong timestamp")
          } yield ()
          result match {
            case Left(e)  => F.raiseError(new Exception(s"block verified invalid because ${e}"))
            case Right(_) => F.unit
          }

        case None => F.raiseError(HeaderParentNotFoundInvalid)
      }
    } yield ()

  override def run(block: Block): F[Consensus.Result] = {
    val result: F[Consensus.Result] = for {
      best   <- history.getBestBlock
      bestTd <- history.getTotalDifficultyByHash(best.header.hash).flatMap(opt => F.fromOption(opt, DBErr.NotFound))
      result <- if (block.header.parentHash == best.header.hash && block.header.number == best.header.number + 1) {
        (for {
          _ <- verify(block)
          _ <- history.getBlockHeaderByHash(block.header.parentHash).flatMap {
            case Some(parent) =>
              BlockValidator.preExecValidate[F](parent, block) >>
                clique.applyHeaders(parent.number, parent.hash, List(block.header)).void
            case None =>
              F.raiseError[Unit](HeaderParentNotFoundInvalid)
          }
          topBlockHash <- pool.addBlock(block).map {
            case Some(leaf) => leaf.hash
            case None       => ???
          }
          topBlocks <- pool.getBranch(topBlockHash, delete = true)
        } yield Consensus.Forward(topBlocks)).widen[Consensus.Result]
      } else {
        pool.addBlock(block).flatMap[Consensus.Result] {
          case Some(Leaf(leafHash, leafTd)) if leafTd > bestTd =>
            for {
              newBranch                     <- pool.getBranch(leafHash, delete = true)
              staleBlocksWithReceiptsAndTDs <- removeBlocksUntil(newBranch.head.header.parentHash, best.header.number).map(_.reverse)
              staleBlocks = staleBlocksWithReceiptsAndTDs.map(_._1)
              _ <- staleBlocks.traverse(block => pool.addBlock(block))
            } yield Consensus.Fork(staleBlocks, newBranch)

          case _ =>
            F.pure(Consensus.Stash(block))
        }
      }
    } yield result

    result.attempt.map {
      case Left(e)  => Consensus.Discard(e)
      case Right(x) => x
    }
  }

  override def resolveBranch(headers: List[BlockHeader]): F[Consensus.BranchResult] =
    checkHeaders(headers).ifM(
      ifTrue = headers
        .map(_.number)
        .traverse(history.getBlockByNumber)
        .map { blocks =>
          val (a, newBranch) = blocks
            .zip(headers)
            .dropWhile {
              case (Some(block), header) if block.header == header => true
              case _                                               => false
            }
            .unzip

          val oldBranch = a.takeWhile(_.isDefined).collect { case Some(b) => b }

          val currentBranchDifficulty = oldBranch.map(_.header.difficulty).qsum
          val newBranchDifficulty     = newBranch.map(_.difficulty).qsum
          if (currentBranchDifficulty < newBranchDifficulty) {
            Consensus.BetterBranch(NonEmptyList.fromListUnsafe(newBranch))
          } else {
            Consensus.NoChainSwitch
          }
        },
      ifFalse = F.pure(Consensus.InvalidBranch)
    )

  ///////////////////////////////////
  ///////////////////////////////////

  private def check(b: Boolean, message: String): Either[String, Unit] =
    if (b) {
      Right(())
    } else {
      Left(message)
    }

  private def removeBlocksUntil(parent: ByteVector, fromNumber: N): F[List[(Block, List[Receipt], N)]] =
    history.getBlockByNumber(fromNumber).flatMap[List[(Block, List[Receipt], N)]] {
      case Some(block) if block.header.hash == parent =>
        F.pure(Nil)

      case Some(block) =>
        for {
          receipts <- history.getReceiptsByHash(block.header.hash).flatMap(opt => F.fromOption(opt, DBErr.NotFound))
          td       <- history.getTotalDifficultyByHash(block.header.hash).flatMap(opt => F.fromOption(opt, DBErr.NotFound))
          _        <- history.delBlock(block.header.hash)
          removed  <- removeBlocksUntil(parent, fromNumber - 1)
        } yield (block, receipts, td) :: removed

      case None =>
        log.error(s"Unexpected missing block number: $fromNumber").as(Nil)
    }

  /**
    * 1. head's parent is known
    * 2. headers form a chain
    */
  private def checkHeaders(headers: List[BlockHeader]): F[Boolean] =
    headers match {
      case head :: tail =>
        ((head.number == 0).pure[F] || history.getBlockHeaderByHash(head.parentHash).map(_.isDefined)) &&
          headers
            .zip(tail)
            .forall {
              case (parent, child) =>
                parent.hash == child.parentHash && parent.number + 1 == child.number
            }
            .pure[F]

      case Nil => F.pure(false)
    }

  private def calcDifficulty(snapshot: Snapshot, miner: Address, number: N): N =
    if (snapshot.inturn(number, miner)) Clique.diffInTurn else Clique.diffNoTurn

  private def calcGasLimit(parentGas: N): N =
    parentGas

  private def amongstRecent(currentNumber: N, seen: N, minerSize: Int): Boolean = {
    val limit = minerSize / 2 + 1
    currentNumber < limit || seen > currentNumber - limit
  }
}
