package jbok.benchmark

import cats.effect.IO
import jbok.crypto._
import jbok.crypto.signature.{ECDSA, Signature}
import org.openjdk.jmh.annotations.{Benchmark, OperationsPerInvocation}
import fs2._
import jbok.common.execution._

class SignatureBenchmark extends JbokBenchmark {
  val s   = "hash benchmark"
  val b   = s.utf8bytes
  val h   = b.kec256.toArray
  val k   = Signature[ECDSA].generateKeyPair().unsafeRunSync()
  val sig = Signature[ECDSA].sign(h, k).unsafeRunSync()

  @Benchmark
  @OperationsPerInvocation(100)
  def signSecp256k1() =
    (0 until 100).foreach(_ => Signature[ECDSA].sign(h, k).unsafeRunSync())

  @Benchmark
  @OperationsPerInvocation(100)
  def signSecp256k1Parallel() =
    Stream
      .range(0, 100)
      .covary[IO]
      .mapAsyncUnordered(4)(_ => Signature[ECDSA].sign(h, k))
      .compile
      .drain
      .unsafeRunSync()

  @Benchmark
  def verifySecp256k1() =
    Signature[ECDSA].verify(h, sig, k.public).unsafeRunSync()

  @Benchmark
  def recoverSecp256k1() =
    Signature[ECDSA].recoverPublic(h, sig)

}
