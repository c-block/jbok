package jbok.core.validators

import cats.effect.Sync
import cats.implicits._
import jbok.codec.rlp.RlpCodec
import jbok.codec.rlp.implicits._
import jbok.core.models._
import jbok.core.validators.BodyInvalid._
import jbok.crypto._

object BodyInvalid {
  case object BlockTransactionsHashInvalid extends Exception("BlockTransactionsHashInvalid")
  case object BlockOmmersHashInvalid       extends Exception("BlockOmmersHashInvalid")
}

private[validators] object BodyValidator {

  /** validate whether the transactions and ommers do match their claimed root hashes */
  def validate[F[_]: Sync](block: Block): F[Unit] =
    for {
      _ <- validateTransactionRoot(block)
      _ <- validateOmmersHash(block)
    } yield ()

  private def validateTransactionRoot[F[_]](block: Block)(implicit F: Sync[F]): F[Unit] =
    MPTValidator
      .isValid[F, SignedTransaction](block.header.transactionsRoot, block.body.transactionList)
      .ifM(ifTrue = F.unit, ifFalse = F.raiseError(BlockTransactionsHashInvalid))

  private def validateOmmersHash[F[_]](block: Block)(implicit F: Sync[F]): F[Unit] =
    if (RlpCodec.encode(block.body.ommerList).require.toByteVector.kec256 equals block.header.ommersHash) F.unit
    else F.raiseError(BlockOmmersHashInvalid)
}
