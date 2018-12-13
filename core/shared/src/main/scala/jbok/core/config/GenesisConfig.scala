package jbok.core.config

import io.circe.generic.JsonCodec
import jbok.codec.json.implicits._
import jbok.core.models._
import jbok.crypto.authds.mpt.MerklePatriciaTrie
import scodec.bits._

@JsonCodec
case class GenesisConfig(
    nonce: ByteVector,
    difficulty: BigInt,
    extraData: ByteVector,
    gasLimit: BigInt,
    coinbase: ByteVector,
    alloc: Map[String, String],
    chainId: BigInt
) {
  val timestamp: Long = System.currentTimeMillis()

  lazy val header = BlockHeader(
    parentHash = ByteVector.empty,
    ommersHash = ByteVector.empty,
    beneficiary = coinbase,
    stateRoot = MerklePatriciaTrie.emptyRootHash,
    transactionsRoot = MerklePatriciaTrie.emptyRootHash,
    receiptsRoot = MerklePatriciaTrie.emptyRootHash,
    logsBloom = ByteVector.empty,
    difficulty = difficulty,
    number = 0,
    gasLimit = gasLimit,
    gasUsed = 0,
    unixTimestamp = timestamp,
    extraData = extraData,
    mixHash = ByteVector.empty,
    nonce = nonce
  )

  lazy val body = BlockBody(Nil, Nil)

  lazy val block = Block(header, body)
}
