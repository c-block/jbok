package jbok.evm

import jbok.JbokSpec
import jbok.common.testkit._
import jbok.evm.testkit._
import org.scalacheck.Gen
import scodec.bits.ByteVector

class ProgramSpec extends JbokSpec {

  val CodeSize = Byte.MaxValue
  val PositionsSize = 10

  val nonPushOp: Byte = JUMP.code
  val invalidOpCode: Byte = 0xef.toByte

  def positionsSetGen: Gen[Set[Int]] =
    getListGen(minSize = 0, maxSize = PositionsSize, genT = intGen(0, CodeSize)).map(_.toSet)

  "program" should {

    "detect all jump destinations if there are no push op" in {
      forAll(positionsSetGen) { jumpDestLocations =>
        val code = ByteVector((0 to CodeSize).map { i =>
          if (jumpDestLocations.contains(i)) JUMPDEST.code
          else nonPushOp
        }.toArray)
        val program = Program(code)
        program.validJumpDestinations shouldBe jumpDestLocations
      }
    }

    "detect all jump destinations if there are push op" in {
      forAll(positionsSetGen, positionsSetGen) { (jumpDestLocations, pushOpLocations) =>
        val code = ByteVector((0 to CodeSize).map { i =>
          if (jumpDestLocations.contains(i)) JUMPDEST.code
          else if (pushOpLocations.contains(i)) PUSH1.code
          else nonPushOp
        }.toArray)
        val program = Program(code)

        //Removing the PUSH1 that would be used as a parameter of another PUSH1
        //  Example: In "PUSH1 PUSH1 JUMPDEST", the JUMPDEST is a valid jump destination
        val pushOpLocationsNotParameters = (pushOpLocations diff jumpDestLocations).toList.sorted
          .foldLeft(List.empty[Int]) {
            case (recPushOpLocations, i) =>
              if (recPushOpLocations.lastOption.contains(i - 1)) recPushOpLocations else recPushOpLocations :+ i
          }

        val jumpDestLocationsWithoutPushBefore = jumpDestLocations
          .filterNot(i => pushOpLocationsNotParameters.contains(i - 1))
          .filter(i => 0 <= i && i <= CodeSize)
        program.validJumpDestinations shouldBe jumpDestLocationsWithoutPushBefore
      }
    }

    "detect all jump destinations if there are invalid ops" in {
      forAll(positionsSetGen, positionsSetGen) { (jumpDestLocations, invalidOpLocations) =>
        val code = ByteVector((0 to CodeSize).map { i =>
          if (jumpDestLocations.contains(i)) JUMPDEST.code
          else if (invalidOpLocations.contains(i)) invalidOpCode
          else nonPushOp
        }.toArray)
        val program = Program(code)
        program.validJumpDestinations shouldBe jumpDestLocations
      }
    }

    "detect all instructions as jump destinations if they are" in {
      val code = ByteVector((0 to CodeSize).map(_ => JUMPDEST.code).toArray)
      val program = Program(code)
      program.validJumpDestinations shouldBe (0 to CodeSize).toSet
    }
  }
}
