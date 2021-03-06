package jbok.core.ledger

import jbok.common.CommonSpec
import jbok.common.math.N
import jbok.core.models.Receipt
import scodec.bits._

class BloomFilterSpec extends CommonSpec {
  "bloom filter" should {

    val receiptWithoutLogs = Receipt(
      postTransactionStateHash = hex"fa28ef92787192b577a8628e520b546ab58b72102572e08191ddecd51d0851e5",
      cumulativeGasUsed = N(50244),
      logsBloomFilter =
        hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      logs = Nil,
      txHash = ByteVector.empty,
      contractAddress = None,
      gasUsed = N(21000),
      status = true
    )

    "properly create the bloom filter for without logs" in {
      val obtained = BloomFilter.create(receiptWithoutLogs.logs)
      obtained shouldBe receiptWithoutLogs.logsBloomFilter
    }
  }
}
