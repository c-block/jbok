package jbok.app.simulations
import java.net.URI

import cats.effect.concurrent.Ref
import cats.effect.{ConcurrentEffect, ContextShift, IO, Timer}
import cats.implicits._
import fs2.Stream
import fs2.concurrent.Topic
import jbok.app.FullNode
import jbok.app.api.{NodeInfo, SimulationAPI, SimulationEvent}
import jbok.app.client.JbokClient
import jbok.codec.rlp.implicits._
import jbok.core.config.Configs.FullNodeConfig
import jbok.core.config.defaults.testReference
import jbok.core.config.GenesisConfig
import jbok.core.consensus.poa.clique.Clique
import jbok.core.models.{Account, Address}
import scodec.bits.ByteVector

import scala.collection.mutable.{ListBuffer => MList}
import scala.concurrent.duration._
import scala.util.Random

case class Node(
    nodeInfo: NodeInfo,
    peerNodeUri: String,
    jbokClient: JbokClient
)

class SimulationImpl(
    topic: Topic[IO, Option[SimulationEvent]],
    id2NodeNetwork: Ref[IO, Map[String, Node]],
    id2Node: Ref[IO, Map[String, Node]]
)(implicit F: ConcurrentEffect[IO], T: Timer[IO], CS: ContextShift[IO])
    extends SimulationAPI {
  import SimulationImpl._
  private[this] val log = jbok.common.log.getLogger("SimulationImpl")

  implicit val chainId: BigInt              = 1
  val genesisConfigChainId: GenesisConfig   = GenesisConfig.generate(chainId, Map.empty)
  val txGraphGen: TxGraphGen                = new TxGraphGen(genesisConfigChainId, nAddr = 10)
  val genesisConfigWithAlloc: GenesisConfig = txGraphGen.genesisConfig
  val blockTime: Int                        = 5

  override def createNodesWithMiner(n: Int, m: Int): IO[List[NodeInfo]] = {
    val fullNodeConfigs = FullNodeConfig.fill(testReference, n)
    val miner           = fullNodeConfigs.head.withMining(_.copy(enabled = true))
    val minerKP         = miner.mining.minerAddressOrKey.right.get
    val genesisConfig   = Clique.generateGenesisConfig(genesisConfigWithAlloc, List(minerKP).map(Address(_)))
    val configs         = miner :: fullNodeConfigs.tail
    val finalConfigs    = configs.map(_.copy(genesisOrPath = Left(genesisConfig)))

    log.info(s"create $n node(s)")

    for {
      newNodes <- finalConfigs.traverse[IO, FullNode[IO]](FullNode.forConfig)
      _        <- newNodes.tail.traverse[IO, Unit](_.peerManager.addPeerNode(newNodes.head.peerManager.peerNode))
      _        <- newNodes.traverse(_.start)
      _        <- T.sleep(5.seconds)
      _ = log.info("node start, then client to connect")
      _ <- stxStream(10).compile.drain.start
      jbokClients <- newNodes.traverse[IO, JbokClient](x =>
        jbok.app.client.JbokClient(new URI(infoFromNode(x).rpcAddr)))
      _ <- id2NodeNetwork.update(
        _ ++ newNodes
          .zip(jbokClients)
          .map {
            case (fullNode, jbokClient) =>
              fullNode.peerManager.peerNode.uri.toString -> Node(infoFromNode(fullNode),
                                                                 fullNode.peerManager.peerNode.uri.toString,
                                                                 jbokClient)
          }
          .toMap)
    } yield newNodes.map(x => infoFromNode(x))
  }

  override def getNodes: IO[List[NodeInfo]] = id2NodeNetwork.get.map(_.values.toList.map(_.nodeInfo))

  override def getNodeInfo(id: String): IO[Option[NodeInfo]] =
    id2NodeNetwork.get.map(_.get(id).map(_.nodeInfo))

  override def stopNode(id: String): IO[Unit] =
    for {
      nodes <- id2NodeNetwork.get
      _     <- nodes.get(id).traverse(_.jbokClient.admin.stop)
    } yield ()

  override def getAccounts: IO[List[(Address, Account)]] = IO { txGraphGen.accountMap.toList }

  override def getCoin(address: Address, value: BigInt): IO[Unit] =
    for {
      nodeIdList <- id2NodeNetwork.get.map(_.keys.toList)
      nodeId = Random.shuffle(nodeIdList).take(1).head
      jbokClientOpt <- id2NodeNetwork.get.map(_.get(nodeId).map(_.jbokClient))
      _ <- jbokClientOpt.traverse[IO, ByteVector](jbokClient =>
        jbokClient.public.sendRawTransaction(txGraphGen.getCoin(address, value).asBytes))
    } yield ()

  override def addNode(interface: String, port: Int): IO[Option[String]] =
    for {
      jbokClient <- jbok.app.client.JbokClient(new URI(s"ws://$interface:$port"))
      peerNodeUriOpt <- jbokClient.admin.peerNodeUri.timeout(requestTimeout).attempt.map {
        case Left(_)            => None
        case Right(peerNodeUri) => peerNodeUri.some
      }
      _ <- peerNodeUriOpt.traverse[IO, Unit] { peerNodeUri =>
        id2Node.update { id2NodeMap =>
          id2NodeMap + (peerNodeUri -> Node(NodeInfo(peerNodeUri, interface, port), peerNodeUri, jbokClient))
        }
      }
    } yield peerNodeUriOpt

  override def deleteNode(peerNodeUri: String): IO[Unit] =
    for {
      _ <- id2Node.update(_ - peerNodeUri)
    } yield ()

  override def submitStxsToNetwork(nStx: Int): IO[Unit] =
    for {
      nodeIdList <- id2NodeNetwork.get.map(_.keys.toList)
      nodeId = Random.shuffle(nodeIdList).take(1).head
      _ <- submitStxsToNode(nStx, nodeId)
    } yield ()

  override def submitStxsToNode(nStx: Int, id: String): IO[Unit] =
    for {
      jbokClientOpt <- id2NodeNetwork.get.map(_.get(id).map(_.jbokClient))
      _    = log.trace(s"submit ${10} txs in network")
      stxs = txGraphGen.nextValidTxs(nStx)
      _ <- jbokClientOpt
        .map(jbokClient => stxs.traverse[IO, ByteVector](stx => jbokClient.public.sendRawTransaction(stx.asBytes)))
        .getOrElse(IO.unit)
    } yield ()

  private def stxStream(nStx: Int): Stream[IO, Unit] =
    Stream
      .awakeEvery[IO](5.seconds)
      .evalMap[IO, Unit] { _ =>
        submitStxsToNetwork(nStx)
      }
      .handleErrorWith[IO, Unit] { err =>
        Stream.eval(IO.delay(log.error(err)))
      }
      .onFinalize[IO](IO.delay(log.info("stx stream stop.")))

  private def infoFromNode(fullNode: FullNode[IO]): NodeInfo =
    NodeInfo(fullNode.peerManager.peerNode.uri.toString, fullNode.config.peer.host, fullNode.config.rpc.port)
}

object SimulationImpl {
  val requestTimeout: FiniteDuration = 5.seconds

  def apply()(implicit F: ConcurrentEffect[IO], T: Timer[IO], CS: ContextShift[IO]): IO[SimulationImpl] =
    for {
      topic          <- Topic[IO, Option[SimulationEvent]](None)
      id2NodeNetwork <- Ref.of[IO, Map[String, Node]](Map.empty)
      id2Node        <- Ref.of[IO, Map[String, Node]](Map.empty)
    } yield new SimulationImpl(topic, id2NodeNetwork, id2Node)
}
