package jbok.core.models

import cats.effect.Sync
import io.circe.{Decoder, Encoder}
import jbok.codec.rlp.RlpCodec
import jbok.codec.rlp.implicits._
import jbok.codec.json.implicits._
import jbok.crypto._
import jbok.crypto.signature._
import scodec.bits.ByteVector
import shapeless._
import cats.implicits._
import jbok.core.validators.TxInvalid.TxSignatureInvalid
import scala.scalajs.js.annotation.{JSExportAll, JSExportTopLevel}

@JSExportTopLevel("SignedTransaction")
@JSExportAll
case class SignedTransaction(
    nonce: BigInt,
    gasPrice: BigInt,
    gasLimit: BigInt,
    receivingAddress: Address,
    value: BigInt,
    payload: ByteVector,
    v: BigInt,
    r: BigInt,
    s: BigInt
) {
  lazy val hash: ByteVector =
    RlpCodec.encode(this).require.bytes.kec256

  lazy val chainIdOpt: Option[BigInt] = ECDSAChainIdConvert.getChainId(v)

  lazy val senderAddress: Option[Address] = chainIdOpt.flatMap(chainId => SignedTransaction.getSender(this, chainId))

  def getSenderOrThrow[F[_]: Sync]: F[Address] =
    Sync[F].fromOption(senderAddress, TxSignatureInvalid)

  def isContractInit: Boolean =
    receivingAddress == Address.empty
}

object SignedTransaction {
  implicit val txJsonEncoder: Encoder[SignedTransaction] =
    deriveEncoder[SignedTransaction]

  implicit def txJsonDecoder: Decoder[SignedTransaction] =
    deriveDecoder[SignedTransaction]

  def apply(
      tx: Transaction,
      v: BigInt,
      r: BigInt,
      s: BigInt
  ): SignedTransaction = SignedTransaction(
    tx.nonce,
    tx.gasPrice,
    tx.gasLimit,
    tx.receivingAddress.getOrElse(Address.empty),
    tx.value,
    tx.payload,
    v,
    r,
    s
  )

  def apply(
      tx: Transaction,
      v: Byte,
      r: ByteVector,
      s: ByteVector
  ): SignedTransaction = apply(tx, BigInt(1, Array(v)), BigInt(1, r.toArray), BigInt(1, s.toArray))

  def sign[F[_]: Sync](tx: Transaction, keyPair: KeyPair)(implicit chainId: BigInt): F[SignedTransaction] = {
    val stx = new SignedTransaction(
      tx.nonce,
      tx.gasPrice,
      tx.gasLimit,
      tx.receivingAddress.getOrElse(Address(ByteVector.empty)),
      tx.value,
      tx.payload,
      BigInt(0),
      BigInt(0),
      BigInt(0)
    )
    val bytes = bytesToSign(stx, chainId)
    Signature[ECDSA].sign[F](bytes.toArray, keyPair, chainId).map(sig => stx.copy(v = sig.v, r = sig.r, s = sig.s))
  }

  private def bytesToSign(stx: SignedTransaction, chainId: BigInt): ByteVector = {
    val hlist = stx.nonce :: stx.gasPrice :: stx.gasLimit :: stx.receivingAddress :: stx.value :: stx.payload :: chainId :: BigInt(
      0) :: BigInt(0) :: HNil
    RlpCodec.encode(hlist).require.bytes.kec256
  }

  private def recoverPublicKey(stx: SignedTransaction, chainId: BigInt): Option[KeyPair.Public] = {
    val bytesToSign = SignedTransaction.bytesToSign(stx, chainId)
    val txSig       = CryptoSignature(stx.r, stx.s, stx.v)

    Signature[ECDSA].recoverPublic(bytesToSign.toArray, txSig, chainId)
  }

  private def getSender(stx: SignedTransaction, chainId: BigInt): Option[Address] =
    recoverPublicKey(stx, chainId).map(pk => Address(pk.bytes.kec256))

}
