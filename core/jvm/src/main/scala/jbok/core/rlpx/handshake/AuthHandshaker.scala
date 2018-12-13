package jbok.core.rlpx.handshake

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.SecureRandom

import cats.effect.{Concurrent, Sync, Timer}
import cats.implicits._
import jbok.codec.rlp.RlpCodec
import jbok.codec.rlp.implicits._
import jbok.core.messages.{AuthPacket, Message}
import jbok.crypto.signature._
import jbok.crypto.{ECIES, _}
import jbok.network.Connection
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement
import org.bouncycastle.crypto.digests.KeccakDigest
import scodec.Codec
import scodec.bits.{BitVector, ByteVector}

import scala.util.Random

case class Secrets(
    aes: Array[Byte],
    mac: Array[Byte],
    token: Array[Byte],
    egressMac: KeccakDigest,
    ingressMac: KeccakDigest
)

case class AuthHandshakeResult(secrets: Secrets, remotePubKey: ByteVector)

case class AuthHandshaker[F[_]](
    nodeKey: KeyPair,
    nonce: ByteVector,
    ephemeralKey: KeyPair,
    secureRandom: SecureRandom,
    isInitiator: Boolean = false,
    initiatePacketOpt: Option[ByteVector] = None,
    responsePacketOpt: Option[ByteVector] = None,
    remotePubKeyOpt: Option[ByteVector] = None
)(implicit F: Concurrent[F], T: Timer[F], chainId: BigInt) {
  import AuthHandshaker._

  private[this] val log = org.log4s.getLogger(s"AuthHandshaker")

  implicit val codec: Codec[ByteVector] = pure.codec

  def initiate(remotePk: KeyPair.Public): F[(ByteVector, AuthHandshaker[F])] =
    for {
      message <- createAuthInitiateMessageV4(remotePk)
      encoded       = RlpCodec.encode(message).require.bytes.toArray
      padded        = encoded ++ randomBytes(Random.nextInt(MaxPadding - MinPadding) + MinPadding)
      encryptedSize = padded.length + ECIES.OverheadSize
      sizePrefix    = ByteBuffer.allocate(2).putShort(encryptedSize.toShort).array
      encryptedPayload <- ECIES.encrypt[F](
        ECDSAPlatform.toECPublicKeyParameters(remotePk).getQ,
        secureRandom,
        padded,
        Some(sizePrefix)
      )
    } yield {
      val packet = ByteVector(sizePrefix) ++ encryptedPayload
      (packet, copy(isInitiator = true, initiatePacketOpt = Some(packet), remotePubKeyOpt = Some(remotePk.bytes)))
    }

  def connect(
      conn: Connection[F, Message],
      remotePk: KeyPair.Public
  ): F[AuthHandshakeResult] =
    for {
      (initPacket, initHandshaker) <- initiate(remotePk)
      _                            <- conn.write(AuthPacket(initPacket))
      _                            <- F.delay(log.trace(s"write init packet ${initPacket.length}, wait for remote response"))
      data                         <- conn.read.map(_.asInstanceOf[AuthPacket].bytes)
      _                            <- F.delay(log.trace(s"got remote response"))
      result                       <- initHandshaker.handleResponseMessageAll(data)
      _                            <- F.delay(log.trace(s"handshake connect ${result}"))
    } yield result

  def accept(
      conn: Connection[F, Message]
  ): F[AuthHandshakeResult] =
    for {
      _                  <- F.delay(log.trace(s"wait for remote init packet"))
      data               <- conn.read.map(_.asInstanceOf[AuthPacket].bytes)
      _                  <- F.delay(log.trace(s"got remote init packet ${data.length}"))
      (response, result) <- handleInitialMessageAll(data)
      _                  <- F.delay(log.trace(s"handshake accept ${result}"))
      _                  <- conn.write(AuthPacket(response))
    } yield result

  private def handleResponseMessage(data: ByteVector): F[AuthHandshakeResult] =
    for {
      plaintext <- ECIES.decrypt[F](nodeKey.secret.d, data.toArray)
      message = AuthResponseMessage.decode(plaintext.toArray)
      h       = copy(responsePacketOpt = Some(data.take(ResponsePacketLength)))
      result <- h.finalizeHandshake(message.ephemeralPublicKey, message.nonce)
    } yield result

  private def handleResponseMessageV4(data: ByteVector): F[AuthHandshakeResult] = {
    val (initData, remaining) = decodeV4Packet(data)
    val sizeBytes             = initData.take(2)
    val encryptedPayload      = initData.drop(2)

    for {
      plaintext <- ECIES.decrypt[F](
        privKey = nodeKey.secret.d,
        ciphertext = encryptedPayload.toArray,
        macData = Some(sizeBytes.toArray)
      )
      message = RlpCodec.decode[AuthResponseMessageV4](BitVector(plaintext)).require.value
      result <- copy(responsePacketOpt = Some(initData)).finalizeHandshake(message.ephemeralPublicKey, message.nonce)
    } yield result
  }

  private def handleResponseMessageAll(data: ByteVector): F[AuthHandshakeResult] =
    handleResponseMessage(data).attemptT.getOrElseF(handleResponseMessageV4(data))

  private def decodeV4Packet(data: ByteVector): (ByteVector, ByteVector) = {
    val encryptedPayloadSize        = bigEndianToShort(data.take(2).toArray)
    val (packetData, remainingData) = data.splitAt(encryptedPayloadSize + 2)
    packetData -> remainingData
  }

  private def bigEndianToShort(bs: Array[Byte]): Short = {
    val n = bs(0) << 8
    (n | bs(1) & 0xFF).toShort
  }

  private def handleInitialMessageAll(data: ByteVector): F[(ByteVector, AuthHandshakeResult)] =
    handleInitialMessage(data).attemptT.getOrElseF(handleInitialMessageV4(data))

  private def handleInitialMessage(data: ByteVector): F[(ByteVector, AuthHandshakeResult)] = {
    val initData = data.take(InitiatePacketLength)
    for {
      plaintext <- ECIES.decrypt[F](nodeKey.secret.d, initData.toArray)
      message = AuthInitiateMessage.decode(plaintext.toArray)
      response = AuthResponseMessage(
        ephemeralPublicKey = ephemeralKey.public,
        nonce = nonce,
        knownPeer = false
      )

      encryptedPacket <- ECIES.encrypt[F](
        ECDSAPlatform.toECPublicKeyParameters(KeyPair.Public(message.publicKey)).getQ,
        secureRandom,
        response.encoded.toArray,
        None
      )
      remoteEphemeralKey = extractEphemeralKey(message.signature, message.nonce, message.publicKey)
      handshakeResult <- copy(
        initiatePacketOpt = Some(initData),
        responsePacketOpt = Some(encryptedPacket),
        remotePubKeyOpt = Some(message.publicKey)).finalizeHandshake(remoteEphemeralKey, message.nonce)
    } yield (encryptedPacket, handshakeResult)
  }

  private def handleInitialMessageV4(data: ByteVector): F[(ByteVector, AuthHandshakeResult)] = {
    val (initData, remaining) = decodeV4Packet(data)
    val sizeBytes             = initData.take(2)
    val encryptedPayload      = initData.drop(2)

    for {
      plaintext <- ECIES.decrypt[F](
        privKey = nodeKey.secret.d,
        ciphertext = encryptedPayload.toArray,
        macData = Some(sizeBytes.toArray)
      )
      message = RlpCodec.decode[AuthInitiateMessageV4](BitVector(plaintext)).require.value
      response = AuthResponseMessageV4(
        ephemeralPublicKey = ephemeralKey.public,
        nonce = nonce,
        version = ProtocolVersion
      )
      encodedResponse = RlpCodec.encode(response).require.toByteArray

      encryptedSize = encodedResponse.length + ECIES.OverheadSize
      sizePrefix    = ByteBuffer.allocate(2).putShort(encryptedSize.toShort).array
      encryptedResponsePayload <- ECIES.encrypt[F](
        ECDSAPlatform.toECPublicKeyParameters(KeyPair.Public(message.publicKey)).getQ,
        secureRandom,
        encodedResponse,
        Some(sizePrefix)
      )
      packet             = ByteVector(sizePrefix) ++ encryptedResponsePayload
      remoteEphemeralKey = extractEphemeralKey(message.signature, message.nonce, message.publicKey)
      responseHandshaker = copy(initiatePacketOpt = Some(initData),
                                responsePacketOpt = Some(packet),
                                remotePubKeyOpt = Some(message.publicKey))

      handshakeResult <- responseHandshaker.finalizeHandshake(remoteEphemeralKey, message.nonce)
    } yield {
      (packet, handshakeResult)
    }
  }

  private def extractEphemeralKey(signature: CryptoSignature,
                                  nonce: ByteVector,
                                  publicKey: ByteVector): KeyPair.Public = {
    val agreement = new ECDHBasicAgreement
    agreement.init(ECDSAPlatform.toECPrivateKeyParameters(nodeKey.secret))
    val sharedSecret = agreement.calculateAgreement(ECDSAPlatform.toECPublicKeyParameters(KeyPair.Public(publicKey)))

    val token  = bigIntegerToBytes(sharedSecret, NonceSize)
    val signed = xor(token, nonce.toArray)

    ECDSAPlatform.recoverPublic(signed, signature, 0).get
  }

  private def xor(a: Array[Byte], b: Array[Byte]): Array[Byte] =
    (a zip b) map { case (b1, b2) => (b1 ^ b2).toByte }

  private def createAuthInitiateMessageV4(remotePubKey: KeyPair.Public): F[AuthInitiateMessageV4] = {
    val sharedSecret = {
      val agreement = new ECDHBasicAgreement
      agreement.init(ECDSAPlatform.toECPrivateKeyParameters(nodeKey.secret))
      bigIntegerToBytes(agreement.calculateAgreement(ECDSAPlatform.toECPublicKeyParameters(remotePubKey)), NonceSize)
    }

    val messageToSign = ByteVector(sharedSecret).xor(nonce)
    ECDSAPlatform
      .sign[F](messageToSign.toArray, ephemeralKey, 0)
      .map(sig => AuthInitiateMessageV4(sig, nodeKey.public.bytes, nonce, ProtocolVersion))
  }

  private[jbok] def bigIntegerToBytes(b: BigInteger, numBytes: Int): Array[Byte] = {
    val bytes   = new Array[Byte](numBytes)
    val biBytes = b.toByteArray
    val start   = if (biBytes.length == numBytes + 1) 1 else 0
    val length  = Math.min(biBytes.length, numBytes)
    System.arraycopy(biBytes, start, bytes, numBytes - length, length)
    bytes
  }

  private def finalizeHandshake(remoteEphemeralKey: KeyPair.Public, remoteNonce: ByteVector): F[AuthHandshakeResult] = {
    val successOpt = for {
      initiatePacket <- initiatePacketOpt
      responsePacket <- responsePacketOpt
      remotePubKey   <- remotePubKeyOpt
    } yield {
      val secretScalar = {
        val agreement = new ECDHBasicAgreement
        agreement.init(ECDSAPlatform.toECPrivateKeyParameters(ephemeralKey.secret))
        agreement.calculateAgreement(ECDSAPlatform.toECPublicKeyParameters(remoteEphemeralKey))
      }

      val agreedSecret = bigIntegerToBytes(secretScalar, SecretSize)

      val sharedSecret =
        if (isInitiator) (agreedSecret ++ (remoteNonce.toArray ++ nonce.toArray).kec256).kec256
        else (agreedSecret ++ (nonce.toArray ++ remoteNonce.toArray).kec256).kec256

      val aesSecret = (agreedSecret ++ sharedSecret).kec256

      val (egressMacSecret, ingressMacSecret) =
        if (isInitiator) macSecretSetup(agreedSecret, aesSecret, initiatePacket, nonce, responsePacket, remoteNonce)
        else macSecretSetup(agreedSecret, aesSecret, initiatePacket, remoteNonce, responsePacket, nonce)

      AuthHandshakeResult(
        secrets = Secrets(aes = aesSecret,
                          mac = (agreedSecret ++ aesSecret).kec256,
                          token = sharedSecret.kec256,
                          egressMac = egressMacSecret,
                          ingressMac = ingressMacSecret),
        remotePubKey = remotePubKey
      )
    }

    successOpt match {
      case Some(x) => F.pure(x)
      case None    => F.raiseError(new Exception("handshake error"))
    }
  }

  private def macSecretSetup(
      agreedSecret: Array[Byte],
      aesSecret: Array[Byte],
      initiatePacket: ByteVector,
      initiateNonce: ByteVector,
      responsePacket: ByteVector,
      responseNonce: ByteVector
  ) = {
    val macSecret = (agreedSecret ++ aesSecret).kec256

    val mac1 = new KeccakDigest(MacSize)
    mac1.update(xor(macSecret, responseNonce.toArray), 0, macSecret.length)
    val bufSize = 32
    val buf     = new Array[Byte](bufSize)
    new KeccakDigest(mac1).doFinal(buf, 0)
    mac1.update(initiatePacket.toArray, 0, initiatePacket.toArray.length)
    new KeccakDigest(mac1).doFinal(buf, 0)

    val mac2 = new KeccakDigest(MacSize)
    mac2.update(xor(macSecret, initiateNonce.toArray), 0, macSecret.length)
    new KeccakDigest(mac2).doFinal(buf, 0)
    mac2.update(responsePacket.toArray, 0, responsePacket.toArray.length)
    new KeccakDigest(mac2).doFinal(buf, 0)

    if (isInitiator) (mac1, mac2)
    else (mac2, mac1)
  }

  private[jbok] def publicKeyFromNodeId(nodeId: String): KeyPair.Public =
    KeyPair.Public(nodeId)
}

object AuthHandshaker {
  val InitiatePacketLength = AuthInitiateMessage.EncodedLength + ECIES.OverheadSize
  val ResponsePacketLength = AuthResponseMessage.EncodedLength + ECIES.OverheadSize

  val NonceSize       = 32
  val MacSize         = 256
  val SecretSize      = 32
  val MinPadding      = 100
  val MaxPadding      = 300
  val ProtocolVersion = 4

  def randomBytes(len: Int): Array[Byte] = {
    val arr = new Array[Byte](len)
    new Random().nextBytes(arr)
    arr
  }

  val secureRandom = new SecureRandom()

  def apply[F[_]](nodeKey: KeyPair)(implicit F: Concurrent[F], T: Timer[F], chainId: BigInt): F[AuthHandshaker[F]] =
    for {
      nonce        <- Sync[F].delay(randomByteArray(secureRandom, NonceSize))
      ephemeralKey <- Signature[ECDSA].generateKeyPair[F](Some(secureRandom))
    } yield
      AuthHandshaker[F](
        nodeKey,
        ByteVector(nonce),
        ephemeralKey,
        secureRandom
      )
}
