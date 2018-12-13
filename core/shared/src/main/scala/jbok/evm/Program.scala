package jbok.evm

import scodec.bits.ByteVector

import scala.annotation.tailrec
import jbok.crypto._

/**
  * Holds a program's code and provides utilities for accessing it (defaulting to zeroes when out of scope)
  *
  * @param code the EVM bytecode as bytes
  */
case class Program(code: ByteVector) {

  def getByte(pc: Int): Byte =
    code.lift(pc).getOrElse(0)

  def getBytes(from: Int, size: Int): ByteVector =
    code.slice(from, from + size).padTo(size)

  val length: Int = code.size.toInt

  lazy val validJumpDestinations: Set[Int] = validJumpDestinationsAfterPosition(0)

  val frontierConfig = EvmConfig.FrontierConfigBuilder(None)

  /**
    * Returns the valid jump destinations of the program after a given position
    * See section 9.4.3 in Yellow Paper for more detail.
    *
    * @param pos from where to start searching for valid jump destinations in the code.
    * @param accum with the previously obtained valid jump destinations.
    */
  @tailrec
  private def validJumpDestinationsAfterPosition(pos: Int, accum: Set[Int] = Set.empty): Set[Int] =
    if (pos < 0 || pos >= length) accum
    else {
      val byte = code(pos)
      val opCode = frontierConfig.byteToOpCode.get(byte) // we only need to check PushOp and JUMPDEST, they are both present in Frontier
      opCode match {
        case Some(pushOp: PushOp) => validJumpDestinationsAfterPosition(pos + pushOp.i + 2, accum)
        case Some(JUMPDEST)       => validJumpDestinationsAfterPosition(pos + 1, accum + pos)
        case _                    => validJumpDestinationsAfterPosition(pos + 1, accum)
      }
    }
}
