package jbok.evm

import cats.data.OptionT
import cats.effect.Sync
import cats.implicits._

/**
  * Entry point to executing a program.
  */
object VM {
  private[this] val log = org.log4s.getLogger("VM")

  /**
    * Executes a program
    * @param context context to be executed
    * @return result of the execution
    */
  def run[F[_]: Sync](context: ProgramContext[F]): F[ProgramResult[F]] = {
    val state = ProgramState[F](context)
    OptionT.fromOption[F](PrecompiledContracts.runOptionally(state.config.preCompiledContracts, context)).getOrElseF {
      run(state).map { finalState =>
        ProgramResult[F](
          finalState.returnData,
          finalState.gas,
          finalState.world,
          finalState.addressesToDelete,
          finalState.logs,
          finalState.internalTxs,
          finalState.gasRefund,
          finalState.error,
          finalState.reverted
        )
      }
    }
  }

  private def run[F[_]: Sync](state: ProgramState[F]): F[ProgramState[F]] = {
    val byte = state.program.getByte(state.pc)
    state.config.byteToOpCode.get(byte) match {
      case Some(opCode) =>
        for {
          newState <- opCode.execute(state)
          _ = log.trace(
            s"$opCode | pc: ${newState.pc} | depth: ${newState.env.callDepth} | gas: ${newState.gas} | stack: ${newState.stack}")
          s <- if (newState.halted || newState.reverted) newState.pure[F] else run(newState)
        } yield s

      case None =>
        state.withError(InvalidOpCode(byte)).halt.pure[F]
    }
  }
}
