package jbok.core

import cats.effect.IO
import jbok.common.execution._
import jbok.common.testkit._
import jbok.core.config.Configs._
import jbok.core.config.GenesisConfig
import jbok.core.consensus.Consensus
import jbok.core.consensus.poa.clique.{Clique, CliqueConfig, CliqueConsensus}
import jbok.core.consensus.pow.ethash._
import jbok.core.ledger.BlockExecutor
import jbok.core.messages._
import jbok.core.mining.{BlockMiner, SimAccount, TxGenerator}
import jbok.core.models._
import jbok.core.peer.{Peer, PeerManager, PeerManagerPlatform, PeerSet}
import jbok.core.pool.{BlockPool, BlockPoolConfig, OmmerPool, TxPool}
import jbok.core.sync._
import jbok.crypto.signature.ecdsa.SecP256k1
import jbok.crypto.signature.{ECDSA, Signature}
import jbok.crypto.testkit._
import jbok.persistent.KeyValueDB
import org.scalacheck._
import scodec.bits.ByteVector

import scala.concurrent.duration._

final case class Fixture(
    chainId: Int,
    port: Int,
    miner: SimAccount,
    genesisConfig: GenesisConfig,
    consensusAlgo: String
) {
  def consensus: IO[Consensus[IO]] = consensusAlgo match {
    case "clique" =>
      for {
        db        <- KeyValueDB.inmem[IO]
        history   <- History[IO](db, chainId)
        _         <- history.init(genesisConfig)
        blockPool <- BlockPool[IO](history, BlockPoolConfig())
        cliqueConfig = CliqueConfig(period = 1.seconds)
        sign         = (bv: ByteVector) => { SecP256k1.sign(bv.toArray, miner.keyPair) }
        clique       = Clique[IO](cliqueConfig, history, miner.address, sign)
      } yield new CliqueConsensus[IO](blockPool, clique)

    case "ethash" =>
      for {
        db      <- KeyValueDB.inmem[IO]
        history <- History[IO](db)
        blockChainConfig = BlockChainConfig()
        miningConfig     = MiningConfig()
        daoForkConfig    = DaoForkConfig()
        ethashMiner <- EthashMinerPlatform[IO](miningConfig)
        blockPool   <- BlockPool[IO](history)
        ov = new EthashOmmersValidator[IO](history, blockChainConfig, daoForkConfig)
        hv = new EthashHeaderValidator[IO](blockChainConfig, daoForkConfig)
      } yield new EthashConsensus[IO](blockChainConfig, miningConfig, history, blockPool, ethashMiner, ov, hv)
  }
}

object testkit {
  def defaultFixture(port: Int = 10001, algo: String = "clique"): Fixture = cliqueFixture(port)

  def cliqueFixture(port: Int): Fixture = {
    val chainId = 0
    val miner   = SimAccount(Signature[ECDSA].generateKeyPair().unsafeRunSync(), BigInt("1000000000000000000000000"), 0)
    val alloc   = Map(miner.address.toString -> miner.balance)
    val genesisConfig =
      GenesisConfig.default.copy(alloc = alloc, extraData = Clique.fillExtraData(miner.address :: Nil))

    Fixture(chainId, port, miner, genesisConfig, "clique")
  }

  def fixture(port: Int): Fixture = {
    val chainId       = 0
    val miner         = SimAccount(Signature[ECDSA].generateKeyPair().unsafeRunSync(), BigInt("100000000000000000000"), 0)
    val alloc         = Map(miner.address.toString -> miner.balance)
    val genesisConfig = GenesisConfig.default.copy(alloc = alloc)
    Fixture(chainId, port, miner, genesisConfig, "ethash")
  }

  implicit val arbUint256 = Arbitrary {
    for {
      bytes <- genBoundedByteVector(32, 32)
    } yield UInt256(bytes)
  }

  implicit val arbAccount: Arbitrary[Account] = Arbitrary {
    for {
      nonce       <- arbUint256.arbitrary
      balance     <- arbUint256.arbitrary
      storageRoot <- genBoundedByteVector(32, 32)
      codeHash    <- genBoundedByteVector(32, 32)
    } yield Account(nonce, balance, storageRoot, codeHash)
  }

  implicit val arbAddress: Arbitrary[Address] = Arbitrary {
    for {
      bytes <- genBoundedByteVector(20, 20)
    } yield Address(bytes)
  }

  def genTx: Gen[Transaction] =
    for {
      nonce            <- bigIntGen
      gasPrice         <- bigIntGen
      gasLimit         <- bigIntGen
      receivingAddress <- Gen.option(arbAddress.arbitrary)
      value            <- bigIntGen
      payload          <- arbByteVector.arbitrary
    } yield Transaction(nonce, gasPrice, gasLimit, receivingAddress, value, payload)

  implicit val arbTransaction: Arbitrary[Transaction] = Arbitrary {
    genTx
  }

  implicit val arbSignedTransaction: Arbitrary[SignedTransaction] = Arbitrary {
    for {
      tx <- arbTransaction.arbitrary
      keyPair = Signature[ECDSA].generateKeyPair().unsafeRunSync()
      stx     = SignedTransaction.sign(tx, keyPair)
    } yield stx
  }

  implicit val arbBlockHeader: Arbitrary[BlockHeader] = Arbitrary {
    for {
      parentHash       <- genBoundedByteVector(32, 32)
      ommersHash       <- genBoundedByteVector(32, 32)
      beneficiary      <- genBoundedByteVector(20, 20)
      stateRoot        <- genBoundedByteVector(32, 32)
      transactionsRoot <- genBoundedByteVector(32, 32)
      receiptsRoot     <- genBoundedByteVector(32, 32)
      logsBloom        <- genBoundedByteVector(50, 50)
      difficulty       <- bigIntGen
      number           <- bigIntGen
      gasLimit         <- bigIntGen
      gasUsed          <- bigIntGen
      unixTimestamp    <- Gen.chooseNum(0L, Long.MaxValue)
      extraData        <- arbByteVector.arbitrary
      mixHash          <- genBoundedByteVector(32, 32)
      nonce            <- genBoundedByteVector(8, 8)
    } yield
      BlockHeader(
        parentHash = parentHash,
        ommersHash = ommersHash,
        beneficiary = beneficiary,
        stateRoot = stateRoot,
        transactionsRoot = transactionsRoot,
        receiptsRoot = receiptsRoot,
        logsBloom = logsBloom,
        difficulty = difficulty,
        number = number,
        gasLimit = gasLimit,
        gasUsed = gasUsed,
        unixTimestamp = unixTimestamp,
        extraData = extraData,
        mixHash = mixHash,
        nonce = nonce
      )
  }

  implicit def arbBlockBody(implicit ev: Fixture): Arbitrary[BlockBody] = Arbitrary {
    for {
      stxs <- arbTxs.arbitrary
    } yield BlockBody(stxs, Nil)
  }

  implicit def arbSignedTransactions(implicit ev: Fixture): Arbitrary[SignedTransactions] = Arbitrary {
    for {
      txs <- arbTxs.arbitrary
    } yield SignedTransactions(txs)
  }

  implicit def arbBlock(implicit ev: Fixture): Arbitrary[Block] = Arbitrary {
    for {
      header <- arbBlockHeader.arbitrary
      body   <- arbBlockBody.arbitrary
    } yield Block(header, body)
  }

  implicit val arbReceipt: Arbitrary[Receipt] = Arbitrary {
    for {
      postTransactionStateHash <- genBoundedByteVector(32, 32)
      cumulativeGasUsed        <- bigIntGen
      logsBloomFilter          <- genBoundedByteVector(256, 256)
    } yield
      Receipt(
        postTransactionStateHash = postTransactionStateHash,
        cumulativeGasUsed = cumulativeGasUsed,
        logsBloomFilter = logsBloomFilter,
        logs = Nil
      )
  }

  def genTxPool(config: TxPoolConfig = TxPoolConfig()): Gen[TxPool[IO]] =
    Gen.delay(TxPool[IO](config).unsafeRunSync)

  implicit val arbTxPool: Arbitrary[TxPool[IO]] = Arbitrary {
    genTxPool()
  }

  def genStatus(number: BigInt = 0,
                chainId: Int = 0,
                genesisHash: ByteVector = GenesisConfig.default.header.hash): Gen[Status] =
    Gen.delay(Status(chainId, genesisHash, number))

  def genPeer: Gen[Peer[IO]] =
    for {
      keyPair <- arbKeyPair.arbitrary
      status  <- genStatus()
    } yield Peer.dummy[IO](keyPair.public, status).unsafeRunSync()

  implicit val arbPeer: Arbitrary[Peer[IO]] = Arbitrary {
    genPeer
  }

  def genPeerSet(min: Int = 0, max: Int = 100): Gen[PeerSet[IO]] =
    for {
      size  <- Gen.chooseNum(min, max)
      peers <- Gen.listOfN(size, arbPeer.arbitrary)
    } yield PeerSet(IO(peers))

  implicit val arbPeerSet: Arbitrary[PeerSet[IO]] = Arbitrary {
    genPeerSet()
  }

  def genBlockHash: Gen[BlockHash] =
    for {
      hash   <- genBoundedByteVector(32, 32)
      number <- bigIntGen
    } yield BlockHash(hash, number)

  def genNewBlockHashes: Gen[NewBlockHashes] =
    for {
      hashes <- Gen.listOf(genBlockHash)
    } yield NewBlockHashes(hashes)

  implicit val arbNewBlockHashes: Arbitrary[NewBlockHashes] = Arbitrary(genNewBlockHashes)

  def genBlockHandler(port: Int = 1000)(implicit fixture: Fixture): Gen[BlockHandler[IO]] = {
    val consensus        = fixture.consensus.unsafeRunSync()
    val blockChainConfig = BlockChainConfig()
    val history          = consensus.history
    val executor         = BlockExecutor[IO](blockChainConfig, consensus)
    val syncConfig       = SyncConfig()
    val txPool           = TxPool[IO](TxPoolConfig()).unsafeRunSync()
    val ommerPool        = OmmerPool[IO](history).unsafeRunSync()
    val blockHandler     = BlockHandler[IO](syncConfig, executor, txPool, ommerPool)
    blockHandler
  }

  implicit def arbBlockHandler(implicit fixture: Fixture): Arbitrary[BlockHandler[IO]] = Arbitrary {
    genBlockHandler()
  }

  def genTxs(min: Int = 0, max: Int = 1024)(implicit fixture: Fixture): Gen[List[SignedTransaction]] =
    for {
      size <- Gen.chooseNum(min, max)
      generator = TxGenerator(fixture.miner).unsafeRunSync()
      txs       = generator.genTxs.take(size).compile.toList.unsafeRunSync()
    } yield txs

  implicit def arbTxs(implicit ev: Fixture): Arbitrary[List[SignedTransaction]] = Arbitrary {
    genTxs()
  }

  def genBlockMiner(implicit fixture: Fixture): Gen[BlockMiner[IO]] = {
    val consensus        = fixture.consensus.unsafeRunSync()
    val blockChainConfig = BlockChainConfig()
    val history          = consensus.history
    val executor         = BlockExecutor[IO](blockChainConfig, consensus)

    val syncConfig        = SyncConfig()
    val peerManagerConfig = PeerManagerConfig(fixture.port)
    val keyPair           = Signature[ECDSA].generateKeyPair().unsafeRunSync()
    val peerManager =
      PeerManagerPlatform[IO](peerManagerConfig, Some(keyPair), history).unsafeRunSync()
    val txPool         = TxPool[IO](TxPoolConfig()).unsafeRunSync()
    val ommerPool      = OmmerPool[IO](history).unsafeRunSync()
    val blockHandler   = BlockHandler[IO](syncConfig, executor, txPool, ommerPool)
    val fastSync       = FastSync[IO](syncConfig, peerManager).unsafeRunSync()
    val fullSync       = FullSync[IO](syncConfig, peerManager, executor, txPool)
    val requestHandler = RequestHandler[IO](syncConfig, history)
    val syncManager    = SyncManager[IO](peerManager, requestHandler, blockHandler, txPool, fastSync, fullSync)
    val miner          = BlockMiner[IO](blockHandler).unsafeRunSync()
    miner
  }

  implicit def arbBlockMiner(implicit fixture: Fixture): Arbitrary[BlockMiner[IO]] = Arbitrary {
    genBlockMiner
  }

  def genBlocks(min: Int, max: Int)(implicit fixture: Fixture): Gen[List[Block]] =
    for {
      miner <- genBlockMiner
      size  <- Gen.chooseNum(min, max)
      blocks = miner.miningStream().take(size).compile.toList.unsafeRunSync()
    } yield blocks

  def genBlock(
      parentOpt: Option[Block] = None,
      stxsOpt: Option[List[SignedTransaction]] = None,
      ommersOpt: Option[List[BlockHeader]] = None
  )(implicit fixture: Fixture): Gen[Block] =
    for {
      miner <- genBlockMiner
      block = miner.mineAndSubmit(parentOpt, stxsOpt, ommersOpt).unsafeRunSync().get
    } yield block

  def genPeerManager(config: PeerManagerConfig)(implicit fixture: Fixture): Gen[PeerManager[IO]] = {
    val keyPair = Signature[ECDSA].generateKeyPair().unsafeRunSync()
    val history = fixture.consensus.unsafeRunSync().history
    PeerManagerPlatform[IO](config, Some(keyPair), history).unsafeRunSync()
  }

  implicit def arbPeerManager(implicit fixture: Fixture): Arbitrary[PeerManager[IO]] = Arbitrary {
    genPeerManager(PeerManagerConfig(10001))
  }

  def genBlockPool(config: BlockPoolConfig = BlockPoolConfig())(implicit fixture: Fixture): Gen[BlockPool[IO]] = {
    val consensus = fixture.consensus.unsafeRunSync()
    val history   = consensus.history
    BlockPool(history, config).unsafeRunSync()
  }

  implicit def arbBlockPool(implicit fixture: Fixture): Arbitrary[BlockPool[IO]] = Arbitrary {
    genBlockPool()
  }

  def genOmmerPool(poolSize: Int = 30)(implicit fixture: Fixture): Gen[OmmerPool[IO]] = {
    val consensus = fixture.consensus.unsafeRunSync()
    val history   = consensus.history
    OmmerPool(history, poolSize).unsafeRunSync()
  }

  implicit def arbOmmerPool(implicit fixture: Fixture): Arbitrary[OmmerPool[IO]] = Arbitrary {
    genOmmerPool()
  }

  def genRequestHandler(config: SyncConfig = SyncConfig())(implicit fixture: Fixture): Gen[RequestHandler[IO]] = {
    val consensus = fixture.consensus.unsafeRunSync()
    val history   = consensus.history
    RequestHandler[IO](config, history)
  }

  implicit def arbRequestHandler(implicit fixture: Fixture): Arbitrary[RequestHandler[IO]] = Arbitrary {
    genRequestHandler()
  }

  implicit def arbHistory(implicit fixture: Fixture): Arbitrary[History[IO]] = Arbitrary {
    val consensus = fixture.consensus.unsafeRunSync()
    consensus.history
  }

  implicit def arbBlockExecutor(implicit fixture: Fixture): Arbitrary[BlockExecutor[IO]] = Arbitrary {
    val consensus        = fixture.consensus.unsafeRunSync()
    val blockChainConfig = BlockChainConfig()
    BlockExecutor[IO](blockChainConfig, consensus)
  }

  def genSyncManager(config: SyncConfig = SyncConfig())(implicit fixture: Fixture): Gen[SyncManager[IO]] = {
    val consensus        = fixture.consensus.unsafeRunSync()
    val blockChainConfig = BlockChainConfig()
    val history          = consensus.history
    val executor         = BlockExecutor[IO](blockChainConfig, consensus)

    val peerManagerConfig = PeerManagerConfig(fixture.port)
    val keyPair           = Signature[ECDSA].generateKeyPair().unsafeRunSync()
    val peerManager =
      PeerManagerPlatform[IO](peerManagerConfig, Some(keyPair), history).unsafeRunSync()
    val txPool         = TxPool[IO](TxPoolConfig()).unsafeRunSync()
    val ommerPool      = OmmerPool[IO](history).unsafeRunSync()
    val blockHandler   = BlockHandler[IO](config, executor, txPool, ommerPool)
    val fastSync       = FastSync[IO](config, peerManager).unsafeRunSync()
    val fullSync       = FullSync[IO](config, peerManager, executor, txPool)
    val requestHandler = RequestHandler[IO](config, history)
    SyncManager[IO](peerManager, requestHandler, blockHandler, txPool, fastSync, fullSync)
  }

  implicit def arbSyncManager(implicit fixture: Fixture): Arbitrary[SyncManager[IO]] = Arbitrary {
    genSyncManager()
  }
}