package jbok.core.consensus.poa.clique1

import cats.effect.{ConcurrentEffect, Timer}
import jbok.core.consensus.Consensus
import jbok.core.pool.BlockPool
import cats.implicits._
import jbok.core.ledger.TypedBlock
import jbok.core.models.{Block, BlockHeader}

class CliqueConsensus[F[_]](
                           clique:Clique[F],
                           blockPool: BlockPool[F]
                           )(implicit F: ConcurrentEffect[F], T: Timer[F])
  extends Consensus[F](clique.history, blockPool){
  override def prepareHeader(parentOpt: Option[Block], ommers: List[BlockHeader]): F[BlockHeader] = {

  }

  override def postProcess(executed: TypedBlock.ExecutedBlock[F]): F[TypedBlock.ExecutedBlock[F]] = ???

  override def mine(executed: TypedBlock.ExecutedBlock[F]): F[TypedBlock.MinedBlock] = ???

  override def verify(block: Block): F[Unit] = ???

  override def run(block: Block): F[Consensus.Result] = ???

  override def resolveBranch(headers: List[BlockHeader]): F[Consensus.BranchResult] = ???
}
