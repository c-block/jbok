package jbok.core.consensus.poa.clique1
import cats.data.OptionT
import cats.effect.ConcurrentEffect
import jbok.core.ledger.History
import jbok.core.models.{Address, BlockHeader}
import jbok.crypto.signature.{CryptoSignature, ECDSA, KeyPair, Signature}
import scalacache._
import scodec.bits.ByteVector
import scodec.bits._

import scala.concurrent.duration._
import scala.collection.mutable.{Map => MMap}
import cats.implicits._
import com.sun.tools.classfile
import jbok.codec.rlp.RlpCodec
import jbok.codec.rlp.implicits._
import jbok.crypto._

case class CliqueConfig(
                      epoch_length:BigInt=BigInt(30000),
                      block_period:FiniteDuration=15.seconds,
                      extra_vanity:Int=32,
                      extra_seal:Int=65,
                      nonce_auth:ByteVector=hex"0xffffffffffffffff",
                      nonce_drop:ByteVector=hex"0x0000000000000000",
                      diff_noturn:Int=1,
                      diff_inturn:Int=2,
                      wiggle_time:FiniteDuration=500.millis,
                       //
                      checkpointInterval: Int = 1024, // Number of blocks after which to save the vote snapshot to the database
                      inMemorySnapshots: Int = 128, // Number of recent vote snapshots to keep in memory
                      inMemorySignatures: Int = 1024, //
                       )
class Clique[F[_]](
            //依赖哪些东西,首先一个整个链history，当前的提议proposals,config, 公私钥
            config:CliqueConfig,
            val history:History[F],
            proposals:MMap[Address,Boolean],
            keyPair: KeyPair
            )(implicit F:ConcurrentEffect[F],C: Cache[Snapshot]) {
  import config._
  private[this] val log= org.log4s.getLogger("Clique")

  def sign(bv:ByteVector):F[CryptoSignature]=F.liftIO(Signature[ECDSA].sign(bv.toArray,keyPair))

  //自己投票
//  def vote(to:Address,addOrDrop:Boolean,header:BlockHeader):BlockHeader ={
//
//  }

  //接受别人的投票
  def applyHeaders(
                    number:Int,
                    hash:ByteVector,
                    parents:List[BlockHeader],
                    headers:List[BlockHeader]):F[Snapshot]={

    val snapshot=OptionT(Snapshot.loadSnapshot[F](history.db,hash))
        .orElseF(if(number==0) genesisSnapshot.map(_.some) else F.pure(None))
    snapshot.value flatMap{
      case Some(snap)=>
    }

  }
  private def genesisSnapshot: F[Snapshot] =
    for{
      genesis<-history.genesisHeader
      n=(genesis.extraData.length-extra_vanity-extra_seal)/20
      signers=(0 until n).map(i=>
        Address(genesis.extraData.slice(extra_vanity+extra_seal+i*20,extra_vanity+extra_seal+(i+1)*20))
      ).toSet
      snapshot=Snapshot(config,0,genesis.hash,signers)
    } yield(snapshot)


}

case class Vote(from:Address,to:Address,authorize:Boolean,blockHeight:BigInt)
case class Tally(addOrDrop:Boolean,numbers:Int)
object Clique {
  val extraVanity = 32 // Fixed number of extra-data prefix bytes reserved for signer vanity
  val extraSeal   = 65 // Fixed number of extra-data suffix bytes reserved for signer seal
  val ommersHash = RlpCodec
    .encode(List.empty[BlockHeader])
    .require
    .bytes
    .kec256 // Always Keccak256(RLP([])) as uncles are meaningless outside of PoW.
  val diffInTurn    = BigInt(11)              // Block difficulty for in-turn signatures
  val diffNoTurn    = BigInt(10)              // Block difficulty for out-of-turn signatures
  val nonceAuthVote = hex"0xffffffffffffffff" // Magic nonce number to vote on adding a new signer
  val nonceDropVote = hex"0x0000000000000000" //

  def sigHash(header:BlockHeader):ByteVector={
    val data=RlpCodec.encode(header.copy(extraData =header.extraData.dropRight(extraSeal) )).require.bytes
    data.kec256
  }
  def ecrecover(header: BlockHeader):Option[Address]={
    val sigbytes=header.extraData.takeRight(extraSeal)
    val sig=CryptoSignature(sigbytes.toArray)
    val hash=sigHash(header)
    Signature[ECDSA].recoverPublic(hash.toArray,sig,None).map(
      pub=>Address(pub.bytes.kec256)
    )
  }
}
