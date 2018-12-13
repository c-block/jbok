package jbok.core.validators

import cats.effect.Sync
import jbok.core.config.Configs.BlockChainConfig
import jbok.core.models._
import jbok.core.validators.TxInvalid._
import jbok.evm.EvmConfig
import cats.implicits._

object TxInvalid {
  case object TxSignatureInvalid             extends Exception("SignedTransactionInvalid")
  case class TxSyntaxInvalid(reason: String) extends Exception(s"TransactionSyntaxInvalid: ${reason}")
  case class TxNonceInvalid(txNonce: UInt256, senderNonce: UInt256)
      extends Exception(
        s"TxNonceInvalid(got tx nonce $txNonce but sender nonce in mpt is: $senderNonce)"
      )
  case class TxNotEnoughGasForIntrinsicInvalid(txGasLimit: BigInt, txIntrinsicGas: BigInt)
      extends Exception(
        s"TxNotEnoughGasForIntrinsicInvalid(xx gas limit ($txGasLimit) < tx intrinsic gas ($txIntrinsicGas))"
      )
  case class TxSenderCantPayUpfrontCostInvalid(upfrontCost: UInt256, senderBalance: UInt256)
      extends Exception(
        s"TxSenderCantPayUpfrontCostInvalid(upfrontcost ($upfrontCost) > sender balance ($senderBalance))"
      )
  case class TrxGasLimitTooBigInvalid(txGasLimit: BigInt, accumGasUsed: BigInt, blockGasLimit: BigInt)
      extends Exception(
        s"TxGasLimitTooBigInvalid(tx gas limit ($txGasLimit) + acc gas ($accumGasUsed) > block gas limit ($blockGasLimit))"
      )
}

class TxValidator[F[_]](blockChainConfig: BlockChainConfig)(implicit F: Sync[F]) {
  val secp256k1n: BigInt = BigInt("115792089237316195423570985008687907852837564279074904382605163141518161494337")

  def validate(
      stx: SignedTransaction,
      senderAccount: Account,
      blockHeader: BlockHeader,
      upfrontGasCost: UInt256,
      accGasUsed: BigInt
  ): F[Unit] =
    for {
      _ <- checkSyntacticValidity(stx)
      _ <- validateSignatureFormat(stx)
      _ <- validateNonce(stx.nonce, senderAccount.nonce)
      _ <- validateGasLimitEnoughForIntrinsicGas(stx, blockHeader.number)
      _ <- validateAccountHasEnoughGasToPayUpfrontCost(senderAccount.balance, upfrontGasCost)
      _ <- validateBlockHasEnoughGasLimitForTx(stx.gasLimit, accGasUsed, blockHeader.gasLimit)
    } yield ()

  def validateSimulateTx(stx: SignedTransaction): F[Unit] =
    checkSyntacticValidity(stx)

  /** Validates if the transaction is syntactically valid (lengths of the transaction fields are correct) */
  private def checkSyntacticValidity(stx: SignedTransaction): F[Unit] = {
    import stx._

    val maxNonceValue = BigInt(2).pow(8 * 32) - 1
    val maxGasValue   = BigInt(2).pow(8 * 32) - 1
    val maxValue      = BigInt(2).pow(8 * 32) - 1
    val maxR          = BigInt(2).pow(8 * 32) - 1
    val maxS          = BigInt(2).pow(8 * 32) - 1

    if (nonce > maxNonceValue)
      F.raiseError(TxSyntaxInvalid(s"Invalid nonce: $nonce > $maxNonceValue"))
    else if (gasLimit > maxGasValue)
      F.raiseError(TxSyntaxInvalid(s"Invalid gasLimit: $gasLimit > $maxGasValue"))
    else if (gasPrice > maxGasValue)
      F.raiseError(TxSyntaxInvalid(s"Invalid gasPrice: $gasPrice > $maxGasValue"))
    else if (value > maxValue)
      F.raiseError(TxSyntaxInvalid(s"Invalid value: $value > $maxValue"))
    else if (r > maxR)
      F.raiseError(TxSyntaxInvalid(s"Invalid signatureRandom: $r > $maxR"))
    else if (s > maxS)
      F.raiseError(TxSyntaxInvalid(s"Invalid signature: $s > $maxS"))
    else
      F.unit
  }

  /** Validates if the transaction signature is valid as stated in appendix F in YP */
  private def validateSignatureFormat(stx: SignedTransaction): F[Unit] = {
    import stx._

    val validR = r > 0 && r < secp256k1n
    val validS = s > 0 && s < secp256k1n / 2
    if (validR && validS) F.unit
    else F.raiseError(TxSignatureInvalid)
  }

  /**
    * Validates if the transaction nonce matches current sender account's nonce
    *
    * @param nonce       Transaction.nonce to validate
    * @param senderNonce Nonce of the sender of the transaction
    */
  private def validateNonce(nonce: BigInt, senderNonce: UInt256): F[Unit] =
    if (senderNonce == UInt256(nonce)) F.unit
    else F.raiseError(TxNonceInvalid(UInt256(nonce), senderNonce))

  /**
    * Validates the sender account balance contains at least the cost required in up-front payment.
    *
    * @param senderBalance Balance of the sender of the tx
    * @param upfrontCost Upfront cost of the transaction tx
    * @return Either the validated transaction or a TransactionSenderCantPayUpfrontCostError
    */
  private def validateAccountHasEnoughGasToPayUpfrontCost(senderBalance: UInt256, upfrontCost: UInt256): F[UInt256] =
    if (senderBalance >= upfrontCost) F.pure(senderBalance)
    else F.raiseError(TxSenderCantPayUpfrontCostInvalid(upfrontCost, senderBalance))

  /**
    * Validates the gas limit is no smaller than the intrinsic gas used by the transaction.
    *
    * @param stx Transaction to validate
    * @param blockHeaderNumber Number of the block where the stx transaction was included
    * @return Either the validated transaction or a TransactionNotEnoughGasForIntrinsicError
    */
  private def validateGasLimitEnoughForIntrinsicGas(stx: SignedTransaction,
                                                    blockHeaderNumber: BigInt): F[SignedTransaction] = {
    val config         = EvmConfig.forBlock(blockHeaderNumber, blockChainConfig)
    val txIntrinsicGas = config.calcTransactionIntrinsicGas(stx.payload, stx.isContractInit)
    if (stx.gasLimit >= txIntrinsicGas) F.pure(stx)
    else F.raiseError(TxNotEnoughGasForIntrinsicInvalid(stx.gasLimit, txIntrinsicGas))
  }

  /**
    * The sum of the transaction’s gas limit and the gas utilised in this block prior must be no greater than the
    * block’s gasLimit
    *
    * @param gasLimit      Transaction to validate
    * @param accGasUsed    Gas spent within tx container block prior executing stx
    * @param blockGasLimit Block gas limit
    */
  private def validateBlockHasEnoughGasLimitForTx(gasLimit: BigInt,
                                                  accGasUsed: BigInt,
                                                  blockGasLimit: BigInt): F[BigInt] =
    if (gasLimit + accGasUsed <= blockGasLimit) F.pure(gasLimit)
    else F.raiseError(TrxGasLimitTooBigInvalid(gasLimit, accGasUsed, blockGasLimit))
}
