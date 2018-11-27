package jbok.core.consensus.poa.clique

import cats.data.OptionT
import cats.effect.ConcurrentEffect
import cats.implicits._
import jbok.codec.rlp.RlpCodec
import jbok.codec.rlp.implicits._
import jbok.core.ledger.History
import jbok.core.consensus.poa.clique.Clique._
import jbok.core.models._
import jbok.crypto._
import jbok.crypto.signature.{CryptoSignature, ECDSA, Signature}
import jbok.persistent.LruMap
import scodec.bits._

import scala.concurrent.duration._

class Clique[F[_]](
    val config: CliqueConfig,
    val history: History[F],
    val recents: LruMap[ByteVector, Snapshot],
    val proposals: Map[Address, Boolean], // Current list of proposals we are pushing
    val signer: Address,
    val sign: ByteVector => F[CryptoSignature]
)(implicit F: ConcurrentEffect[F]) {
  private[this] val log = org.log4s.getLogger("Clique")

  def readSnapshot(number: BigInt, hash: ByteVector): OptionT[F, Snapshot] = {
    // try to read snapshot from cache or db
    log.trace(s"try to read snapshot(${number}, ${hash}) from cache")
    OptionT
      .fromOption[F](recents.get(hash)) // If an in-memory snapshot was found, use that
      .orElseF(
        if (number % checkpointInterval == 0) {
          // If an on-disk checkpoint snapshot can be found, use that
          log.trace(s"not found in cache, try to read snapshot(${number}) from db")
          Snapshot.loadSnapshot[F](history.db, hash)
        } else {
          log.trace(s"snapshot(${number}) not found in cache and db")
          F.pure(None)
        }
      )
  }

  def genesisSnapshot: F[Snapshot] = {
    log.trace(s"making a genesis snapshot")
    for {
      genesis <- history.genesisHeader
      n = (genesis.extraData.length - extraVanity - extraSeal).toInt / 20
      signers: Set[Address] = (0 until n)
        .map(i => Address(genesis.extraData.slice(i * 20 + extraVanity, i * 20 + extraVanity + 20)))
        .toSet
      snap = Snapshot(config, 0, genesis.hash, signers)
      _ <- Snapshot.storeSnapshot[F](snap, history.db)
      _ = log.trace(s"stored genesis with ${signers.size} signers")
    } yield snap
  }

  private[jbok] def snapshot(number: BigInt,
                             hash: ByteVector,
                             parents: List[BlockHeader],
                             headers: List[BlockHeader] = Nil): F[Snapshot] = {
    val snap = readSnapshot(number, hash)
      .orElseF(if (number == 0) genesisSnapshot.map(_.some) else F.pure(None))

    snap.value flatMap {
      case Some(s) =>
        // Previous snapshot found, apply any pending headers on top of it
        log.trace(s"applying ${headers.length} headers")
        for {
          newSnap <- Snapshot.applyHeaders[F](s, headers)
          _ = recents.put(newSnap.hash, newSnap)
          // If we've generated a new checkpoint snapshot, save to disk
          _ <- if (newSnap.number % checkpointInterval == 0 && headers.nonEmpty) {
            Snapshot.storeSnapshot[F](newSnap, history.db).map(_ => newSnap)
          } else {
            F.pure(newSnap)
          }
        } yield newSnap
      case None => // No snapshot for this header, gather the header and move backward(recur)
        for {
          (h, p) <- if (parents.nonEmpty) {
            // If we have explicit parents, pick from there (enforced)
            F.pure((parents.last, parents.slice(0, parents.length - 1)))
          } else {
            // No explicit parents (or no more left), reach out to the database
            history.getBlockHeaderByHash(hash).map(header => header.get -> parents)
          }
          snap <- snapshot(number - 1, h.parentHash, p, h :: headers)
        } yield snap
    }
  }
}

object Clique {
  val extraVanity = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
  val extraSeal   = 65 // Fixed number of extra-data suffix bytes reserved for signer seal
  val uncleHash   = RlpCodec.encode(()).require.bytes.kec256 // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
  val diffInTurn  = BigInt(2) // Block difficulty for in-turn signatures
  val diffNoTurn  = BigInt(1) // Block difficulty for out-of-turn signatures

  val checkpointInterval = 1024 // Number of blocks after which to save the vote snapshot to the databsase
  val inMemorySnapshots  = 128  // Number of recent vote snapshots to keep in memory
  val inMemorySignatures = 1024 // Number of recent blocks to keep in memory

  val wiggleTime = 500.millis // Random delay (per signer) to allow concurrent signers

  val nonceAuthVote = hex"0xffffffffffffffff" // Magic nonce number to vote on adding a new signer
  val nonceDropVote = hex"0x0000000000000000" // Magic nonce number to vote on removing a signer.

  def apply[F[_]: ConcurrentEffect](
      config: CliqueConfig,
      history: History[F],
      signer: Address,
      sign: ByteVector => F[CryptoSignature]
  ): Clique[F] =
    new Clique[F](
      config,
      history,
      new LruMap[ByteVector, Snapshot](inMemorySnapshots),
      Map.empty,
      signer,
      sign
    )

  def fillExtraData(signers: List[Address]): ByteVector =
    ByteVector.fill(extraVanity)(0.toByte) ++ signers.foldLeft(ByteVector.empty)(_ ++ _.bytes) ++ ByteVector.fill(
      extraSeal)(0.toByte)

  def sigHash(header: BlockHeader): ByteVector = {
    val bytes = RlpCodec.encode(header.copy(extraData = header.extraData.dropRight(extraSeal))).require.bytes
    bytes.kec256
  }

  def ecrecover(header: BlockHeader): Address = {
    // Retrieve the signature from the header extra-data
    val signature = header.extraData.takeRight(extraSeal)
    val hash      = sigHash(header)
    val sig       = CryptoSignature(signature.toArray)
    val public    = Signature[ECDSA].recoverPublic(hash.toArray, sig, None).get
    Address(public.bytes.kec256)
  }
}
