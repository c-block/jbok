package jbok.core.keystore

import jbok.core.models.Address
import scodec.bits.ByteVector

object KeyStoreError {
  final case object KeyNotFound         extends Exception("KeyNotFound")
  final case object KeyAlreadyExist     extends Exception("KeyAlreadyExist")
  final case object DecryptionFailed    extends Exception("DecryptionFailed")
  final case object InvalidKeyFormat    extends Exception("InvalidKeyFormat")
  final case class IOError(msg: String) extends Exception(s"IO error, ${msg}")
}

trait KeyStore[F[_]] {
  def newAccount(passphrase: String): F[Address]

  def readPassphrase(prompt: String): F[String]

  def importPrivateKey(key: ByteVector, passphrase: String): F[Address]

  def listAccounts: F[List[Address]]

  def unlockAccount(address: Address, passphrase: String): F[Wallet]

  def deleteAccount(address: Address): F[Boolean]

  def changePassphrase(
      address: Address,
      oldPassphrase: String,
      newPassphrase: String
  ): F[Boolean]

  def clear: F[Unit]
}
