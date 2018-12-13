package jbok.app.simulations
import java.util.concurrent.Executors

import cats.effect.concurrent.Ref
import cats.effect.{ConcurrentEffect, IO, Timer}
import cats.implicits._
import fs2.concurrent.Topic
import jbok.app.FullNode
import jbok.app.simulations.SimulationImpl.NodeId
import jbok.common.execution._
import jbok.core.config.Configs.FullNodeConfig
import jbok.core.config.GenesisConfig
import jbok.core.consensus.Consensus
import jbok.core.consensus.poa.clique.{Clique, CliqueConfig, CliqueConsensus}
import jbok.core.ledger.History
import jbok.core.messages.SignedTransactions
import jbok.core.models.{Account, Address}
import jbok.core.pool.BlockPool
import jbok.crypto.signature.{ECDSA, KeyPair, Signature}
import jbok.persistent.KeyValueDB

import scala.collection.mutable.{ListBuffer => MList}
import scala.concurrent.ExecutionContext
import scala.concurrent.duration._
import scala.util.Random

class SimulationImpl(
    val topic: Topic[IO, Option[SimulationEvent]],
    val nodes: Ref[IO, Map[NodeId, FullNode[IO]]],
    val miners: Ref[IO, Map[NodeId, FullNode[IO]]]
) extends SimulationAPI {
  private[this] val log = org.log4s.getLogger

  val cliqueConfig = CliqueConfig(period = 5.seconds)
  val txGraphGen   = new TxGraphGen(10)

  private def infoFromNode(fullNode: FullNode[IO]): NodeInfo =
    NodeInfo(fullNode.id, fullNode.config.peer.host, fullNode.config.peer.port, fullNode.config.rpc.port)

  private def newFullNode(
      config: FullNodeConfig,
      consensus: Consensus[IO]
  )(implicit F: ConcurrentEffect[IO], EC: ExecutionContext, T: Timer[IO]): IO[FullNode[IO]] =
    FullNode.forConfigAndConsensus(config, consensus)

  override def createNodesWithMiner(n: Int, m: Int): IO[List[NodeInfo]] = {
    log.info("in createNodes")
    val fullNodeConfigs = FullNodeConfig.fill(n)
    val signers = (1 to n).toList
      .traverse[IO, KeyPair](_ => Signature[ECDSA].generateKeyPair())
      .unsafeRunSync()
    val (configs, minerSingers) = selectMiner(n, m, fullNodeConfigs, signers)

    log.info(minerSingers.toString)
    val genesisConfig =
      GenesisConfig.default
        .copy(alloc = txGraphGen.alloc,
              extraData = Clique.fillExtraData(minerSingers.map(Address(_))).toHex,
              timestamp = System.currentTimeMillis())
    log.info(s"create ${n} node(s)")

    for {
      newNodes <- configs.zipWithIndex.traverse[IO, FullNode[IO]] {
        case (config, idx) =>
          implicit val ec =
            ExecutionContext.fromExecutor(Executors.newFixedThreadPool(2, mkThreadFactory(s"EC${idx}", true)))
          for {
            db        <- KeyValueDB.inmem[IO]
            history   <- History[IO](db)
            _         <- history.init(genesisConfig)
            clique    <- Clique[IO](cliqueConfig, history, signers(idx))
            blockPool <- BlockPool(history)
            consensus = new CliqueConsensus[IO](clique, blockPool)
            fullNode <- newFullNode(config, consensus)
          } yield fullNode
      }
      _ <- nodes.update(_ ++ newNodes.map(x => x.id                                       -> x).toMap)
      _ <- miners.update(_ ++ newNodes.filter(n => n.config.mining.enabled).map(x => x.id -> x).toMap)
    } yield newNodes.map(x => infoFromNode(x))
  }

  override def deleteNode(id: String): IO[Unit] =
    for {
      node <- getNode(id)
      _    <- node.stop
      _    <- nodes.update(_ - id)
      _    <- miners.update(_ - id)
    } yield ()

  override def startNetwork: IO[Unit] = {
    log.info(s"network start all nodes")
    for {
      xs <- nodes.get
      _  <- xs.values.toList.traverse[IO, Unit](x => startNode(x.id))
    } yield ()
  }

  override def stopNetwork: IO[Unit] = {
    log.info(s"network stop all nodes")
    for {
      xs <- nodes.get
      _  <- xs.values.toList.traverse[IO, Unit](x => stopNode(x.id))
    } yield ()
  }

  private def getNode(id: NodeId): IO[FullNode[IO]] = nodes.get.map(xs => xs(id))

  override def getNodes: IO[List[NodeInfo]] = nodes.get.map(_.values.toList.map(n => infoFromNode(n)))

  override def getMiners: IO[List[NodeInfo]] = miners.get.map(_.values.toList.map(n => infoFromNode(n)))

  override def stopMiners(ids: List[NodeId]): IO[Unit] =
    for {
      nodes <- miners.get.map(m => ids.map(id => m(id)))
      _     <- nodes.traverse(_.stop)
      _     <- miners.update(_ -- ids)
    } yield ()

  private def selectMiner(
      n: Int,
      m: Int,
      fullNodeConfigs: List[FullNodeConfig],
      signers: List[KeyPair]
  ): (List[FullNodeConfig], List[KeyPair]) =
    if (m == 0) (fullNodeConfigs, List.empty)
    else {
      val gap                    = (n + m - 1) / m
      val miners: MList[KeyPair] = MList.empty
      val configs = fullNodeConfigs.zip(signers).zipWithIndex.map {
        case ((config, signer), index) =>
          if (index % gap == 0) {
            miners += signer
            config.copy(mining = config.mining.copy(enabled = true), rpc = config.rpc.copy(enabled = true))
          } else config
      }
      (configs, miners.toList)
    }

  override def setMiner(ids: List[String]): IO[Unit] =
    for {
      newMiners <- nodes.get.map(m => ids.map(id => m(id)))
      _         <- newMiners.traverse(_.start)
      _         <- miners.update(_ ++ newMiners.map(x => x.id -> x).toMap)
    } yield ()

  override def getNodeInfo(id: String): IO[NodeInfo] = getNode(id).map(x => infoFromNode(x))

  override def startNode(id: String): IO[Unit] =
    for {
      node <- getNode(id)
      _    <- node.start
    } yield infoFromNode(node)

  override def stopNode(id: String): IO[Unit] =
    for {
      node <- getNode(id)
      _    <- node.stop
    } yield infoFromNode(node)

  override def connect(topology: String): IO[Unit] = topology match {
    case "ring" =>
      for {
        xs <- nodes.get.map(_.values.toList)
        _ <- (xs :+ xs.head).sliding(2).toList.traverse[IO, Unit] {
          case a :: b :: Nil =>
            a.peerManager.addPeerNode(b.peerNode)
          case _ =>
            IO.unit
        }
      } yield ()

    case "star" =>
      for {
        xs <- nodes.get.map(_.values.toList)
        _  <- xs.tail.traverse(_.peerManager.addPeerNode(xs.head.peerNode))
      } yield ()

    case _ => IO.raiseError(new RuntimeException(s"${topology} not supported"))
  }

  override def submitStxsToNetwork(nStx: Int, t: String): IO[Unit] =
    for {
      nodeIdList <- nodes.get.map(_.keys.toList)
      nodeId = Random.shuffle(nodeIdList).take(1).head
      _ <- submitStxsToNode(nStx, t, nodeId)
    } yield ()

  override def submitStxsToNode(nStx: Int, t: String, id: String): IO[Unit] =
    for {
      minerTxPool <- nodes.get.map(_.get(id).map(_.txPool))
      stxs = t match {
        case "DoubleSpend" => txGraphGen.nextDoubleSpendTxs2(nStx)
        case _             => txGraphGen.nextValidTxs(nStx)
      }
      _ <- minerTxPool.map(_.addTransactions(SignedTransactions(stxs), true)).getOrElse(IO.unit)
    } yield ()

  override def getAccounts(): IO[List[(Address, Account)]] = IO { txGraphGen.accountMap.toList }

  override def getCoin(address: Address, value: BigInt): IO[Unit] =
    for {
      nodeIdList <- miners.get.map(_.keys.toList)
      nodeId = Random.shuffle(nodeIdList).take(1).head
      ns <- nodes.get
      _  <- ns(nodeId).txPool.addTransactions(SignedTransactions(List(txGraphGen.getCoin(address, value))), true)
    } yield ()
}

object SimulationImpl {
  type NodeId = String
  def apply()(implicit ec: ExecutionContext): IO[SimulationImpl] =
    for {
      topic  <- Topic[IO, Option[SimulationEvent]](None)
      nodes  <- Ref.of[IO, Map[NodeId, FullNode[IO]]](Map.empty)
      miners <- Ref.of[IO, Map[NodeId, FullNode[IO]]](Map.empty)
    } yield new SimulationImpl(topic, nodes, miners)
}
