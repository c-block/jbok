package jbok.evm

import cats.effect.IO
import jbok.core.models.{Account, Address, TxLogEntry, UInt256}
import org.scalacheck.Gen
import org.scalatest.prop.PropertyChecks
import org.scalatest.{FunSuite, Matchers}
import scodec.bits.ByteVector
import jbok.evm.testkit._
import UInt256._
import jbok.crypto._

class OpCodeFunSpec extends FunSuite with OpCodeTesting with Matchers with PropertyChecks {

  override val config = EvmConfig.ByzantiumConfigBuilder(None)

  def executeOp(op: OpCode, stateIn: ProgramState[IO]): ProgramState[IO] =
    // gas is not tested in this spec
    op.execute(stateIn).unsafeRunSync().copy(gas = stateIn.gas, gasRefund = stateIn.gasRefund)

  def withStackVerification(op: OpCode, stateIn: ProgramState[IO], stateOut: ProgramState[IO])(body: => Any): Any =
    if (stateIn.stack.size < op.delta)
      stateOut shouldBe stateIn.withError(StackUnderflow).halt
    else if (stateIn.stack.size - op.delta + op.alpha > stateIn.stack.maxSize)
      stateOut shouldBe stateIn.withError(StackOverflow).halt
    else {
      if (stateOut.error.isEmpty) {
        val expectedStackSize = stateIn.stack.size - op.delta + op.alpha
        stateOut.stack.size shouldBe expectedStackSize

        val (_, stack1) = stateIn.stack.pop(op.delta)
        val (_, stack2) = stateOut.stack.pop(op.alpha)
        stack1 shouldBe stack2
      }
      body
    }

  def stateWithCode(state: ProgramState[IO], code: ByteVector): ProgramState[IO] = {
    val newProgram = Program(code)
    state.copy(context = state.context.copy(env = state.context.env.copy(program = newProgram)))
  }

  test(STOP) { op =>
    forAll(getProgramStateGen()) { stateIn =>
      val stateOut = executeOp(op, stateIn)
      stateOut.halted shouldBe true
      stateIn shouldBe stateOut.copy(halted = stateIn.halted)
    }
  }

  test(unaryOps: _*) { op =>
    forAll(getProgramStateGen()) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (a, _)      = stateIn.stack.pop
        val (result, _) = stateOut.stack.pop
        result shouldBe op.f(a)

        val expectedState = stateIn.withStack(stateOut.stack).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(binaryOps: _*) { op =>
    forAll(getProgramStateGen()) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(a, b), _) = stateIn.stack.pop(2)
        val (result, _)    = stateOut.stack.pop
        result shouldBe op.f(a, b)

        val expectedState = stateIn.withStack(stateOut.stack).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(ternaryOps: _*) { op =>
    forAll(getProgramStateGen()) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(a, b, c), _) = stateIn.stack.pop(3)
        val (result, _)       = stateOut.stack.pop
        result shouldBe op.f(a, b, c)

        val expectedState = stateIn.withStack(stateOut.stack).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(constOps.filter(_ != MSIZE): _*) { op =>
    forAll(getProgramStateGen()) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (result, _) = stateOut.stack.pop
        result shouldBe op.f(stateIn)

        val expectedState = stateIn.withStack(stateOut.stack).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(MSIZE) { op =>
    val stateGen = getProgramStateGen(
      memGen = getMemoryGen(256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val expectedSize  = wordsForBytes(stateIn.memory.size) * 32
        val expectedState = stateIn.withStack(stateIn.stack.push(expectedSize.toUInt256)).step()

        stateOut shouldBe expectedState
      }
    }
  }

  test(SHA3) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      memGen = getMemoryGen(maxSize = 256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(offset, size), _) = stateIn.stack.pop(2)
        val (data, mem1)           = stateIn.memory.load(offset, size)
        val (result, _)            = stateOut.stack.pop
        result shouldBe UInt256(data.kec256)

        val expectedState = stateIn.withStack(stateOut.stack).withMemory(mem1).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(BALANCE) { op =>
    forAll(getProgramStateGen(), getUInt256Gen()) { (stateIn, accountBalance) =>
      val stateOut = executeOp(op, stateIn)
      withStackVerification(op, stateIn, stateOut) {
        val (_, stack1) = stateIn.stack.pop
        stateOut shouldBe stateIn.withStack(stack1.push(UInt256.Zero)).step()
      }

      val (addr, stack1) = stateIn.stack.pop

      val account = Account(balance = accountBalance)
      val world1  = stateIn.world.putAccount(Address(addr mod UInt256(BigInt(2).pow(160))), account)

      val stateInWithAccount  = stateIn.withWorld(world1)
      val stateOutWithAccount = executeOp(op, stateInWithAccount)

      withStackVerification(op, stateInWithAccount, stateOutWithAccount) {
        val stack2 = stack1.push(accountBalance)
        stateOutWithAccount shouldBe stateInWithAccount.withStack(stack2).step()
      }
    }
  }

  test(CALLDATALOAD) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      inputDataGen = getByteVectorGen(0, 256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (offset, _) = stateIn.stack.pop
        val (data, _)   = stateOut.stack.pop
        data shouldBe UInt256(OpCode.sliceBytes(stateIn.inputData, offset, 32))

        val expectedState = stateIn.withStack(stateOut.stack).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(CALLDATACOPY) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      memGen = getMemoryGen(256),
      inputDataGen = getByteVectorGen(0, 256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(memOffset, dataOffset, size), _) = stateIn.stack.pop(3)
        val data                                  = OpCode.sliceBytes(stateIn.inputData, dataOffset, size)
        val (storedInMem, _)                      = stateOut.memory.load(memOffset, size)
        data shouldBe storedInMem

        val expectedState = stateIn.withStack(stateOut.stack).withMemory(stateOut.memory).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(RETURNDATACOPY) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      memGen = getMemoryGen(256),
      returnDataGen = getByteVectorGen(256, 256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(memOffset, dataOffset, size), _) = stateIn.stack.pop(3)
        if (dataOffset + size > stateIn.returnData.size) {
          stateOut.error.contains(ReturnDataOutOfBounds) shouldBe true
        } else {
          val data             = OpCode.sliceBytes(stateIn.returnData, dataOffset, size)
          val (storedInMem, _) = stateOut.memory.load(memOffset, size)
          data shouldBe storedInMem

          val expectedState = stateIn.withStack(stateOut.stack).withMemory(stateOut.memory).step()
          stateOut shouldBe expectedState
        }
      }
    }
  }

  test(CODECOPY) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      memGen = getMemoryGen(256),
      codeGen = getByteVectorGen(0, 256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(memOffset, codeOffset, size), _) = stateIn.stack.pop(3)
        val code                                  = OpCode.sliceBytes(stateIn.program.code, codeOffset, size)
        val (storedInMem, _)                      = stateOut.memory.load(memOffset, size)
        code shouldBe storedInMem

        val expectedState = stateIn.withStack(stateOut.stack).withMemory(stateOut.memory).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(EXTCODESIZE) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256))
    )
    val codeGen = getByteVectorGen(0, 512)

    forAll(stateGen, codeGen) { (stateIn, extCode) =>
      val stateOut = executeOp(op, stateIn)
      withStackVerification(op, stateIn, stateOut) {
        val (_, stack1) = stateIn.stack.pop
        stateOut shouldBe stateIn.withStack(stack1.push(UInt256.Zero)).step()
      }

      val (addr, stack1) = stateIn.stack.pop
      val program        = Program(extCode)
      val world1         = stateIn.world.putCode(Address(addr), program.code)

      val stateInWithExtCode  = stateIn.withWorld(world1)
      val stateOutWithExtCode = executeOp(op, stateInWithExtCode)

      withStackVerification(op, stateInWithExtCode, stateOutWithExtCode) {
        val stack2 = stack1.push(UInt256(extCode.size))
        stateOutWithExtCode shouldBe stateInWithExtCode.withStack(stack2).step()
      }
    }
  }

  test(EXTCODECOPY) { op =>
    val stateGen: Gen[ProgramState[IO]] = for {
      extCode <- getByteVectorGen(0, 256)

      stateIn <- getProgramStateGen(
        stackGen = getStackGen(maxWord = UInt256(256)),
        memGen = getMemoryGen(256),
        codeGen = getByteVectorGen(0, 256)
      )

      doSave <- Gen.oneOf(false, true, true)

      addr  = Address(stateIn.stack.pop._1)
      hash  = extCode.kec256
      world = if (doSave) stateIn.world.putAccount(addr, Account.empty().copy(codeHash = hash)) else stateIn.world
    } yield stateIn.withWorld(world)

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(addr, memOffset, codeOffset, size), _) = stateIn.stack.pop(4)
        val code                                        = OpCode.sliceBytes(stateIn.world.getCode(Address(addr)).unsafeRunSync(), codeOffset, size)
        val (storedInMem, _)                            = stateOut.memory.load(memOffset, size)
        code shouldBe storedInMem

        val expectedState = stateIn.withStack(stateOut.stack).withMemory(stateOut.memory).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(BLOCKHASH) { op =>
    val stateGen: Gen[ProgramState[IO]] = for {
      stateIn <- getProgramStateGen(
        stackGen = getStackGen(maxWord = UInt256(512)),
        blockNumberGen = getUInt256Gen(0, 512)
      )
    } yield stateIn

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (blockHeaderNumber, stack1) = stateIn.stack.pop

        val withinLimits =
          stateIn.env.blockHeader.number - blockHeaderNumber.toBigInt <= 256 &&
            blockHeaderNumber.toBigInt < stateIn.env.blockHeader.number

        val hash = stateIn.world
          .getBlockHash(blockHeaderNumber)
          .unsafeRunSync()
          .filter(_ => withinLimits)
          .getOrElse(UInt256.Zero)

        val expectedState = stateIn.withStack(stack1.push(hash)).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(POP) { op =>
    forAll(getProgramStateGen()) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        stateOut shouldBe stateIn.withStack(stateOut.stack).step()
      }
    }
  }

  test(MLOAD) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      memGen = getMemoryGen(256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (offset, _) = stateIn.stack.pop
        val (result, _) = stateOut.stack.pop
        val (data, _)   = stateIn.memory.load(offset)
        result shouldBe data

        stateOut shouldBe stateIn.withStack(stateOut.stack).withMemory(stateOut.memory).step()
      }
    }
  }

  test(MSTORE) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      memGen = getMemoryGen(256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(offset, value), _) = stateIn.stack.pop(2)
        val (data, _)               = stateOut.memory.load(offset)
        value shouldBe data

        stateOut shouldBe stateIn.withStack(stateOut.stack).withMemory(stateOut.memory).step()
      }
    }
  }

  test(MSTORE8) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      memGen = getMemoryGen(256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(offset, value), _) = stateIn.stack.pop(2)
        val (data, _)               = stateOut.memory.load(offset, 1)
        ByteVector((value mod 256).toByte) shouldBe data

        stateOut shouldBe stateIn.withStack(stateOut.stack).withMemory(stateOut.memory).step()
      }
    }
  }

  test(SLOAD) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(UInt256(256)),
      storageGen = getStorageGen(256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (offset, _) = stateIn.stack.pop
        val data        = stateIn.storage.unsafeRunSync().load(offset).unsafeRunSync()
        val (result, _) = stateOut.stack.pop
        result shouldBe data

        stateOut shouldBe stateIn.withStack(stateOut.stack).step()
      }
    }
  }

  test(SSTORE) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(UInt256(256)),
      storageGen = getStorageGen(256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(offset, value), _) = stateIn.stack.pop(2)
        val data                    = stateOut.storage.unsafeRunSync().load(offset).unsafeRunSync()
        data shouldBe value

        stateOut shouldBe stateIn.withStack(stateOut.stack).withStorage(stateOut.storage.unsafeRunSync()).step()
      }
    }
  }

  test(JUMP) { op =>
    // have about 1 in 2 opcodes be a JUMPDEST
    val opcodes   = config.opCodes ++ List.fill(config.opCodes.size)(JUMPDEST)
    val opcodeGen = Gen.oneOf(opcodes).map(_.code.toByte)

    // 80% of jump destinations arguments will be within codesize bound
    def stackValueGen(codeSize: UInt256): Gen[UInt256] = Gen.frequency(
      8 -> getUInt256Gen(0, codeSize),
      1 -> getUInt256Gen(codeSize, Int.MaxValue),
      1 -> getUInt256Gen(Int.MaxValue, UInt256.MaxValue)
    )

    val stateGen = for {
      codeSize <- Gen.choose(0, 256)
      state <- getProgramStateGen(
        stackGen = getStackGen(valueGen = stackValueGen(codeSize)),
        codeGen = getByteVectorGen(codeSize, codeSize, opcodeGen)
      )
    } yield state

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (dest, _) = stateIn.stack.pop
        if (dest.toInt == dest.toInt && stateIn.program.validJumpDestinations.contains(dest.toInt))
          stateOut shouldBe stateIn.withStack(stateOut.stack).goto(dest.toInt)
        else
          stateOut shouldBe stateIn.withError(InvalidJump(dest))
      }
    }

    val code = Assembly(
      STOP,
      STOP,
      JUMPDEST,
      PUSH4,
      0xff,
      0xff,
      JUMPDEST.code,
      0xff
    ).code

    val List(validDest, insidePush) = code.toIndexedSeq.indices.toList.filter(i => code(i) == JUMPDEST.code)
    val overflownDest               = UInt256(Int.MaxValue) + 1 + validDest
    val invalidDest                 = validDest + 1
    val offLimitDest                = code.size

    assert(overflownDest.toInt == validDest)
    assert(code(invalidDest) != JUMPDEST.code)

    val table = Table[UInt256, Boolean](
      ("destination", "isValid"),
      (validDest, true),
      (invalidDest, false),
      (insidePush, false),
      (offLimitDest, false),
      (overflownDest, false)
    )

    forAll(table) { (destination, isValid) =>
      val stackIn     = Stack.empty().push(destination)
      val stateSample = getProgramStateGen().sample.get
      val stateIn     = stateWithCode(stateSample.copy(stack = stackIn), code)
      val stateOut    = executeOp(op, stateIn)

      val expectedState =
        if (isValid)
          stateIn.withStack(Stack.empty()).goto(destination.toInt)
        else
          stateIn.withError(InvalidJump(destination))

      stateOut shouldBe expectedState
    }
  }

  test(JUMPI) { op =>
    // have about 1 in 2 opcodes be a JUMPDEST
    val opcodes   = config.opCodes ++ List.fill(config.opCodes.size)(JUMPDEST)
    val opcodeGen = Gen.oneOf(opcodes).map(_.code.toByte)

    // 40% of conditionals arguments will be false (zero)
    // 80% of jump destinations arguments will be within codesize bound
    def stackValueGen(codeSize: UInt256): Gen[UInt256] = Gen.frequency(
      4 -> Gen.const(UInt256.Zero),
      4 -> getUInt256Gen(0, codeSize),
      1 -> getUInt256Gen(codeSize, Int.MaxValue),
      1 -> getUInt256Gen(Int.MaxValue, UInt256.MaxValue)
    )

    val stateGen = for {
      codeSize <- Gen.choose(0, 256)
      state <- getProgramStateGen(
        stackGen = getStackGen(valueGen = stackValueGen(codeSize)),
        codeGen = getByteVectorGen(codeSize, codeSize, opcodeGen)
      )
    } yield state

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(dest, cond), _) = stateIn.stack.pop(2)
        val expectedState =
          if (cond.isZero)
            stateIn.withStack(stateOut.stack).step()
          else if (dest.toInt == dest.toInt && stateIn.program.validJumpDestinations.contains(dest.toInt))
            stateIn.withStack(stateOut.stack).goto(dest.toInt)
          else
            stateIn.withError(InvalidJump(dest))

        stateOut shouldBe expectedState
      }
    }

    val code = Assembly(
      STOP,
      STOP,
      JUMPDEST,
      PUSH4,
      0xff,
      0xff,
      JUMPDEST.code,
      0xff
    ).code

    val List(validDest, insidePush) = code.toIndexedSeq.indices.toList.filter(i => code(i) == JUMPDEST.code)
    val overflownDest               = UInt256(Int.MaxValue) + 1 + validDest
    val invalidDest                 = validDest + 1
    val offLimitDest                = code.size

    assert(overflownDest.toInt == validDest)
    assert(code(invalidDest) != JUMPDEST.code)

    val table = Table[UInt256, UInt256, Boolean](
      ("destination", "cond", "isValid"),
      (validDest, 1, true),
      (invalidDest, 42, false),
      (insidePush, UInt256.MaxValue, false),
      (offLimitDest, Int.MaxValue, false),
      (overflownDest, 2, false),
      (validDest, 0, true),
      (invalidDest, 0, false)
    )

    forAll(table) { (destination, cond, isValid) =>
      val stackIn     = Stack.empty().push(List(cond, destination))
      val stateSample = getProgramStateGen().sample.get
      val stateIn     = stateWithCode(stateSample.copy(stack = stackIn), code)
      val stateOut    = executeOp(op, stateIn)

      val expectedState =
        if (cond.isZero)
          stateIn.withStack(Stack.empty()).step()
        else if (isValid)
          stateIn.withStack(Stack.empty()).goto(destination.toInt)
        else
          stateIn.withError(InvalidJump(destination))

      stateOut shouldBe expectedState
    }
  }

  test(JUMPDEST) { op =>
    forAll(getProgramStateGen()) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        stateOut shouldBe stateIn.step()
      }
    }
  }

  test(pushOps: _*) { op =>
    val stateGen = getProgramStateGen(codeGen = getByteVectorGen(0, 32))

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val bytes         = stateIn.program.getBytes(stateIn.pc + 1, op.i + 1)
        val expectedStack = stateIn.stack.push(UInt256(bytes))
        val expectedState = stateIn.withStack(expectedStack).step(op.i + 2)
        stateOut shouldBe expectedState
      }
    }
  }

  test(dupOps: _*) { op =>
    forAll(getProgramStateGen()) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val expectedStack = stateIn.stack.dup(op.i)
        val expectedState = stateIn.withStack(expectedStack).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(swapOps: _*) { op =>
    forAll(getProgramStateGen()) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val expectedStack = stateIn.stack.swap(op.i + 1)
        val expectedState = stateIn.withStack(expectedStack).step()
        stateOut shouldBe expectedState
      }
    }
  }

  test(logOps: _*) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      memGen = getMemoryGen(maxSize = 256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(offset, size, topics @ _*), stack1) = stateIn.stack.pop(op.delta)
        val (data, mem1)                             = stateIn.memory.load(offset, size)
        val logEntry                                 = TxLogEntry(stateIn.env.ownerAddr, topics.map(_.bytes).toList, data)
        val expectedState                            = stateIn.withStack(stack1).withMemory(mem1).withLog(logEntry).step()

        logEntry.logTopics.size shouldBe op.i
        stateOut shouldBe expectedState
      }
    }
  }

  test(RETURN) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      memGen = getMemoryGen(maxSize = 256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(offset, size), _) = stateIn.stack.pop(2)
        val (data, mem1)           = stateIn.memory.load(offset, size)

        if (size.isZero) {
          mem1.size shouldBe stateIn.memory.size
        } else {
          mem1.size should be >= (offset + size).toInt
        }

        val expectedState = stateIn.withStack(stateOut.stack).withMemory(mem1).withReturnData(data).halt
        stateOut shouldBe expectedState
      }
    }
  }

  test(REVERT) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(maxWord = UInt256(256)),
      memGen = getMemoryGen(maxSize = 256)
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      withStackVerification(op, stateIn, stateOut) {
        val (Seq(offset, size), _) = stateIn.stack.pop(2)
        val (data, mem1)           = stateIn.memory.load(offset, size)

        if (size.isZero) {
          mem1.size shouldBe stateIn.memory.size
        } else {
          mem1.size should be >= (offset + size).toInt
        }

        val expectedState =
          stateIn.withStack(stateOut.stack).withMemory(mem1).withReturnData(data).revert
        stateOut shouldBe expectedState
      }
    }
  }

  test(INVALID) { op =>
    forAll(getProgramStateGen()) { stateIn =>
      val stateOut = executeOp(op, stateIn)

      val expectedState = stateIn.withError(InvalidOpCode(op.code))
      stateOut shouldBe expectedState
    }
  }

  test(SELFDESTRUCT) { op =>
    val stateGen = getProgramStateGen(
      stackGen = getStackGen(valueGen = getUInt256Gen().filter(Address(_) != ownerAddr))
    )

    forAll(stateGen) { stateIn =>
      val stateOut = executeOp(op, stateIn)
      withStackVerification(op, stateIn, stateOut) {
        val (refundAddr, stack1) = stateIn.stack.pop
        val world1 = stateIn.world
          .transfer(stateIn.ownAddress, Address(refundAddr), stateIn.ownBalance.unsafeRunSync())
          .unsafeRunSync()

        val expectedState = stateIn
          .withWorld(world1)
          .withAddressToDelete(stateIn.context.env.ownerAddr)
          .withStack(stack1)
          .halt
        stateOut shouldBe expectedState
      }
    }

    // test Ether transfer on SELFDESTRUCT
    val table = Table[Address, UInt256, UInt256](
      ("refundAddr", "initialEther", "transferredEther"),
      (callerAddr, 1000, 1000),
      (ownerAddr, 1000, 0) // if the Ether is transferred to the about-to-be removed account, the Ether gets destroyed
    )

    forAll(table) {
      case (refundAddr, initialEther, transferredEther) =>
        val stackIn     = Stack.empty().push(refundAddr.toUInt256)
        val stateSample = getProgramStateGen().sample.get
        val initialWorld = stateSample.world
          .putAccount(refundAddr, Account.empty())
          .putAccount(ownerAddr, Account.empty().increaseBalance(initialEther))
        val stateIn = stateSample.copy(world = initialWorld, stack = stackIn)

        val stateOut = executeOp(op, stateIn)

        stateOut.addressesToDelete shouldBe Set(ownerAddr)

        val ownerBalance = stateOut.world.getBalance(ownerAddr).unsafeRunSync()
        ownerBalance shouldBe 0

        val refundBalance = stateOut.world.getBalance(refundAddr).unsafeRunSync()
        refundBalance shouldBe transferredEther
    }
  }

  verifyAllOpCodesRegistered(except = CREATE, CALL, CALLCODE, DELEGATECALL, STATICCALL)

  test("sliceBytes helper") {
    def zeroes(i: Int): ByteVector =
      ByteVector(Array.fill[Byte](i)(0))

    val table = Table[Int, UInt256, UInt256, Int, ByteVector => ByteVector](
      ("dataSize", "sliceOffset", "sliceSize", "expectedSize", "expectedContentFn"),
      // both offset and size are greater than data size
      (0, 16, 32, 32, _ => zeroes(32)),
      // offset is within bounds, offset + size is greater than data size
      (20, 16, 32, 32, bs => bs.drop(16) ++ zeroes(28)),
      // offset + size are within bounds
      (64, 16, 31, 31, bs => bs.slice(16, 47)),
      // offset is greater than Int.MaxValue
      (64, Two ** 128, 32, 32, _ => zeroes(32)),
      // offset is within bounds, size is greater than Int.MaxValue
      (64, 16, Two ** 64 + 7, 48, bs => bs.drop(16)),
      // offset is within bounds, size is greater than Int.MaxValue and size.toInt > dataSize
      // this case a bit strange because we purposefully let size overflow when converting to Int
      // but sliceBytes is supposed to copy the behaviour of geth:
      // httProgramState[IO]://github.com/ethereum/go-ethereum/blob/5f7826270c9e87509fd7731ec64953a5e4761de0/core/vm/common.go#L42
      (64, 40, Two ** 64 + 124, 124, bs => bs.drop(40) ++ zeroes(100)),
      // both offset and size are greater than Int.MaxValue
      (64, Two ** 33, Two ** 96 + 13, 13, _ => zeroes(13))
    )

    forAll(table) { (dataSize, sliceOffset, sliceSize, expectedSize, expectedContentFn) =>
      val bytes = getByteVectorGen(dataSize, dataSize).sample.get
      val slice = OpCode.sliceBytes(bytes, sliceOffset, sliceSize)

      slice.size shouldBe expectedSize
      slice shouldBe expectedContentFn(bytes)
    }
  }

}
