package jbok.core.consensus.pow.ethash

import cats.effect.Effect
import cats.implicits._
import jbok.core.ledger.History
import jbok.core.config.Configs.HistoryConfig
import jbok.core.consensus.pow.ethash.OmmersError._
import jbok.core.models.{Block, BlockHeader}
import jbok.core.validators.HeaderValidator
import scodec.bits.ByteVector

object OmmersError {
  case object OmmersLengthInvalid    extends Exception("ommers length invalid")
  case object OmmersNotValid         extends Exception("ommers invalid")
  case object OmmersUsedBefore       extends Exception("ommers used before")
  case object OmmersAncestorsInvalid extends Exception("ommers ancestors invalid")
  case object OmmersDuplicated       extends Exception("ommers duplicated")
}

class EthashOmmersValidator[F[_]](history: History[F], blockChainConfig: HistoryConfig)(implicit F: Effect[F]) {

  val headerValidator = new EthashHeaderValidator(blockChainConfig)

  private def validateLength(length: Int): F[Unit] =
    if (length <= 2) F.unit else F.raiseError(OmmersLengthInvalid)

  private def validateDuplicated(ommers: List[BlockHeader]): F[Unit] =
    if (ommers.distinct.length == ommers.length) F.unit else F.raiseError(OmmersDuplicated)

  private def validateOmmersAncestors(ommers: List[BlockHeader],
                                      parentHash: ByteVector,
                                      blockNumber: BigInt,
                                      getNBlocksBack: (ByteVector, Int) => F[List[Block]]): F[Unit] = {
    val numberOfBlocks = blockNumber.min(6).toInt

    def isSibling(ommerHeader: BlockHeader, parent: Block): Boolean =
      ommerHeader.parentHash == parent.header.parentHash && !ommerHeader.equals(parent.header) && !parent.body.ommerList
        .contains(ommerHeader)

    def isKen(ommer: BlockHeader) =
      for {
        ancestors <- getNBlocksBack(parentHash, numberOfBlocks)
        b = ancestors.foldRight(false)((block, z) =>
          z || (isSibling(ommer, block) && ancestors.forall(!_.body.ommerList.contains(ommer))))
      } yield b

    val r = ommers.foldLeftM(true)((z, header) => isKen(header).map(z && _))
    F.ifM(r)(ifTrue = F.unit, ifFalse = F.raiseError(OmmersAncestorsInvalid))
  }

  private def validateOmmerHeader(ommers: List[BlockHeader]): F[Unit] =
    ommers
      .traverse(ommer => HeaderValidator.preExecValidate[F](history.getBlockHeaderByHash(ommer.parentHash), ommer))
      .void

  def validate(
      parentHash: ByteVector,
      blockNumber: BigInt,
      ommers: List[BlockHeader],
      getBlockHeaderByHash: ByteVector => F[Option[BlockHeader]],
      getNBlocksBack: (ByteVector, Int) => F[List[Block]]
  ): F[Unit] =
    for {
      _ <- validateLength(ommers.length)
      _ <- validateDuplicated(ommers)
      _ <- validateOmmerHeader(ommers)
      _ <- validateOmmersAncestors(ommers, parentHash, blockNumber, getNBlocksBack)
    } yield ()

  def validate(
      parentHash: ByteVector,
      blockNumber: BigInt,
      ommers: List[BlockHeader]
  ): F[Unit] = {
    val getBlockHeaderByHash: ByteVector => F[Option[BlockHeader]] = history.getBlockHeaderByHash
    val getNBlocksBack: (ByteVector, Int) => F[List[Block]] = (_, n) =>
      ((blockNumber - n) until blockNumber).toList.map(history.getBlockByNumber).sequence.map(_.flatten)

    validate(parentHash, blockNumber, ommers, getBlockHeaderByHash, getNBlocksBack)
  }
}
