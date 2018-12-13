package jbok.evm

import jbok.core.models.UInt256

/**
  * Marker trait for errors that may occur during program execution
  */
sealed trait ProgramError
case class InvalidOpCode(code: Int) extends ProgramError {
  override def toString: String =
    f"${getClass.getSimpleName}(0x${code & 0xff}%02x)"
}
case object OutOfGas              extends ProgramError
case object WriteProtectionError  extends ProgramError
case object ReturnDataOutOfBounds extends ProgramError
case class InvalidJump(dest: UInt256) extends ProgramError {
  override def toString: String =
    f"${getClass.getSimpleName}(${dest.toHexString})"
}

sealed trait StackError    extends ProgramError
case object StackOverflow  extends StackError
case object StackUnderflow extends StackError
